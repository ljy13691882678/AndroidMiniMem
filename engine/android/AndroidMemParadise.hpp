#pragma once
// ============================================================================
// AndroidMemParadise.hpp — Paradise 内核通道（替代 AndroidMemKernel）
// ----------------------------------------------------------------------------
// 保持与 IMemoryOp 完全一致的外部契约，只有驱动后端从 NI 换成 Paradise：
//   · 连续前缀读：按页切片，遇首个不可读页即停，未读区清零
//   · 连续前缀写：按页切片，返回真正写入的连续字节数
//   · 进程名 / maps / SO 基址：能从驱动拿的走驱动，拿不到的走 /proc
//
// 语义差异说明：
//   · Paradise 的 read/write 是二值返回，不给短读长度，因此「短读边界」
//     只能以页为粒度判定。跨页不可读区的检测精度从字节级降到页级，
//     这是驱动 ABI 决定的，无法在用户态弥补。
//   · DetermineMemoryType 复用 ProcessMap.hpp 的公共实现，保证与 syscall 通道
//     的映射类型判定完全一致。
// ============================================================================

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>

#include "../common/IMemoryOp.hpp"
#include "../common/LinuxProc.hpp"
#include "../common/Logger.hpp"

#include "ParadiseKernelDriver.h"

class AndroidMemParadise : public IMemoryOp {
private:
    pid_t pid_ = 0;
    std::string processName_;
    ParadiseKernelDriver& driver_;
    uint64_t driverProcessHandle_ = 0;

public:
    AndroidMemParadise() : driver_(KernelDriver()) {
        type = MemType_Kernel;
    }

    ~AndroidMemParadise() override {
        driver_.CloseProcess(driverProcessHandle_);
    }

    bool connect() {
        LOGDF("Connecting via paradise anon_fd...");
        const int rc = driver_.Connect();
        if (rc < 0) {
            LOGEF("ParadiseKernelDriver connect failed rc=%d %s", rc, strerror(errno));
            return false;
        }
        LOGDF("ParadiseKernelDriver connect success");
        return driver_.IsConnected();
    }

    bool isConnected() {
        const bool ok = driver_.IsConnected();
        if (!ok) {
            LOGEF("ParadiseKernelDriver is not connected");
        }
        return ok;
    }

    bool GetCardTime(uint64_t& outCardTime) override {
        return driver_.GetExpireTime(outCardTime);
    }

    bool OpenProcess(pid_t pid) override {
        if (pid == pid_ && driverProcessHandle_ != 0) {
            return true;
        }
        pid_ = pid;
        if (pid_ <= 0) {
            return false;
        }

        if (!isConnected()) {
            if (!connect()) {
                LOGEF("connect() failed before OpenProcess, pid: %d", pid_);
                return false;
            }
        }

        driverProcessHandle_ = driver_.OpenProcess(pid_);
        if (driverProcessHandle_ == 0) {
            LOGEF("OpenProcess failed, pid: %d", pid_);
            return false;
        }

        char name[256] = {0};
        if (driver_.GetProcessComm(pid_, name, sizeof(name))) {
            processName_ = name;
        }
        return true;
    }

    bool CloseHandle() override {
        pid_ = 0;
        bool ok = true;
        if (driverProcessHandle_) {
            ok = driver_.CloseProcess(driverProcessHandle_);
        }
        driverProcessHandle_ = 0;
        return ok;
    }

    size_t Read(uintptr_t address, void* buffer, size_t len) const override {
        if (address == 0 || buffer == nullptr || len == 0) {
            return 0;
        }
        if (const_cast<AndroidMemParadise*>(this)->driverProcessHandle_ == 0) {
            return 0;
        }

        static const size_t page_size = static_cast<size_t>(getpagesize());

        size_t total_bytes_read = 0;
        uintptr_t current_addr = address;
        char* current_buffer = static_cast<char*>(buffer);
        size_t remaining_len = len;

        while (remaining_len > 0) {
            const uintptr_t page_offset = current_addr & (page_size - 1);
            const size_t bytes_to_page_boundary = page_size - page_offset;
            const size_t chunk_size = (remaining_len < bytes_to_page_boundary)
                                          ? remaining_len
                                          : bytes_to_page_boundary;

            const ssize_t bytes_read = const_cast<AndroidMemParadise*>(this)->driver_.ReadMemory(
                const_cast<AndroidMemParadise*>(this)->driverProcessHandle_,
                static_cast<uint64_t>(current_addr),
                current_buffer,
                chunk_size);

            if (bytes_read <= 0) {
                break;   // 首个不可读页：停止，不跳页续读
            }

            const size_t got = static_cast<size_t>(bytes_read);
            total_bytes_read += got;
            current_addr += got;
            current_buffer += got;
            remaining_len -= got;

            if (got < chunk_size) {
                break;   // 页内短读说明到达不可读边界
            }
        }

        if (remaining_len > 0) {
            std::memset(current_buffer, 0, remaining_len);
        }
        return total_bytes_read;
    }

    int ReadProcessMemory(uint64_t hProcess,
                          uint64_t lpBaseAddress,
                          void* lpBuffer,
                          size_t nSize,
                          size_t* lpNumberOfBytesRead = nullptr) override {
        (void)hProcess;
        const ssize_t bytes_read = driver_.ReadMemory(
            const_cast<AndroidMemParadise*>(this)->driverProcessHandle_,
            lpBaseAddress, lpBuffer, nSize);
        const size_t got = bytes_read > 0 ? static_cast<size_t>(bytes_read) : 0;
        if (lpNumberOfBytesRead) {
            *lpNumberOfBytesRead = got;
        }
        return static_cast<int>(got);
    }

    size_t Write(uintptr_t address, const void* buffer, size_t len) const override {
        if (address == 0 || buffer == nullptr || len == 0) {
            return 0;
        }
        if (const_cast<AndroidMemParadise*>(this)->driverProcessHandle_ == 0) {
            return 0;
        }

        static const size_t page_size = static_cast<size_t>(getpagesize());

        size_t total_written = 0;
        uintptr_t current_addr = address;
        const char* current_buffer = static_cast<const char*>(buffer);
        size_t remaining_len = len;

        while (remaining_len > 0) {
            const uintptr_t page_offset = current_addr & (page_size - 1);
            const size_t bytes_to_page_boundary = page_size - page_offset;
            const size_t chunk_size = (remaining_len < bytes_to_page_boundary)
                                          ? remaining_len
                                          : bytes_to_page_boundary;

            const ssize_t bytes_written = const_cast<AndroidMemParadise*>(this)->driver_.WriteMemory(
                const_cast<AndroidMemParadise*>(this)->driverProcessHandle_,
                static_cast<uint64_t>(current_addr),
                current_buffer,
                chunk_size);

            if (bytes_written <= 0) {
                break;
            }

            const size_t got = static_cast<size_t>(bytes_written);
            total_written += got;
            current_addr += got;
            current_buffer += got;
            remaining_len -= got;

            if (got < chunk_size) {
                break;
            }
        }
        return total_written;
    }

    pid_t GetProcessId() const override {
        return pid_;
    }

    std::string GetProcessName() const override {
        return processName_;
    }

    std::string ReadString(uintptr_t address, size_t maxLen) override {
        if (maxLen == 0 || maxLen > 0x10000) {
            return "";
        }
        std::vector<char> buffer(maxLen + 1, '\0');
        const size_t read = Read(address, buffer.data(), maxLen);
        if (read == 0) {
            return "";
        }
        buffer[read] = '\0';
        return std::string(buffer.data());
    }

    bool WriteString(uintptr_t address, const std::string& str) override {
        return Write(address, str.c_str(), str.length() + 1) == str.length() + 1;
    }

    std::vector<std::pair<int, std::string>> GetProcessPidList() override {
        std::vector<std::pair<int, std::string>> result;

        std::vector<int> pids;
        if (!driver_.GetPidList(pids)) {
            // 驱动位图不可用时退回 /proc，保证列表功能不因驱动差异失效
            return LinuxProc::GetProcessPidList();
        }

        result.reserve(pids.size());
        char name[256];
        for (int pid : pids) {
            std::memset(name, 0, sizeof(name));
            driver_.GetProcessCmdline(pid, name, sizeof(name));
            if (std::string(name).empty()) {
                std::memset(name, 0, sizeof(name));
                driver_.GetProcessComm(pid, name, sizeof(name));
            }
            const std::string name_str = name;

            std::string link = "/proc/" + std::to_string(pid) + "/exe";
            char buf[1024] = {0};
            readlink(link.c_str(), buf, sizeof(buf) - 1);
            link = buf;

            if (link == "/system/bin/app_process64" ||
                link == "/system/bin/app_process32") {
                const std::string app = link.substr(link.find_last_of('/') + 1);
                result.emplace_back(pid, app + " " + name_str);
                continue;
            }
            if (link.starts_with("/system/bin/") || link.empty() ||
                link.starts_with("/system_ext/bin/") ||
                link.starts_with("/vendor/bin/") ||
                link.starts_with("/apex/com.")) {
                continue;
            }
            result.emplace_back(pid, "elf " + name_str);
        }
        return result;
    }

    std::vector<ProcessMap> GetProcessMaps() const override {
        std::vector<ProcessMap> maps;
        if (const_cast<AndroidMemParadise*>(this)->driverProcessHandle_ == 0) {
            return maps;
        }

        std::vector<DRIVER_REGION_INFO> regions;
        if (!const_cast<AndroidMemParadise*>(this)->driver_.QueryMaps(
                const_cast<AndroidMemParadise*>(this)->driverProcessHandle_, false, regions)) {
            return maps;
        }

        maps.reserve(regions.size());
        for (const auto& r : regions) {
            ProcessMap m;
            m.pid = pid_;
            m.startAddress = static_cast<uintptr_t>(r.baseaddress);
            m.endAddress = static_cast<uintptr_t>(r.baseaddress + r.size);
            m.offset = 0;
            m.length = r.size;
            m.inode = 0;
            m.dev = "";
            m.pathname = r.name;
            m.protection = r.protection;

            const bool canRead = (r.protection == PAGE_READONLY) ||
                                 (r.protection == PAGE_READWRITE) ||
                                 (r.protection == PAGE_EXECUTE_READ) ||
                                 (r.protection == PAGE_EXECUTE_READWRITE);
            const bool canWrite = (r.protection == PAGE_READWRITE) ||
                                  (r.protection == PAGE_EXECUTE_READWRITE);
            const bool canExec = (r.protection == PAGE_EXECUTE) ||
                                 (r.protection == PAGE_EXECUTE_READ) ||
                                 (r.protection == PAGE_EXECUTE_READWRITE);

            m.readable = canRead;
            m.writable = canWrite;
            m.executable = canExec;
            m.is_private = (r.type == MEM_PRIVATE);
            m.is_shared = (r.type == MEM_MAPPED);
            m.flag = 0;
            if (canRead) m.flag |= 1;
            if (canWrite) m.flag |= 2;
            if (canExec) m.flag |= 4;
            if (m.is_private) m.flag |= 8;
            if (m.is_shared) m.flag |= 16;

            m.perms.clear();
            m.perms.push_back(canRead ? 'r' : '-');
            m.perms.push_back(canWrite ? 'w' : '-');
            m.perms.push_back(canExec ? 'x' : '-');
            m.perms.push_back(m.is_private ? 'p' : (m.is_shared ? 's' : '-'));

            m.type = DetermineMemoryType(m.pathname, m.perms);
            maps.push_back(std::move(m));
        }
        return maps;
    }

    uint64_t GetSoBase(const std::string& name) const override {
        if (pid_ <= 0 || name.empty()) {
            return 0;
        }
        const uint64_t base = driver_.GetSoBaseAddress(pid_, name);
        if (base != 0) {
            return base;
        }
        // 驱动查询失败时退回 /proc 解析，避免模块基址功能整体失效
        return LinuxProc::GetModBase(pid_, name);
    }

    ProcessMap GetAddressMap(uintptr_t address) const override {
        const auto maps = GetProcessMaps();
        for (const auto& map : maps) {
            if (map.Contains(address)) {
                return map;
            }
        }
        return ProcessMap();
    }

    std::vector<ProcessMap> FindMapsByName(const std::string& name) const override {
        std::vector<ProcessMap> result;
        const auto maps = GetProcessMaps();
        for (const auto& map : maps) {
            if (!map.IsUnknown() && map.pathname.find(name) != std::string::npos) {
                result.push_back(map);
            }
        }
        return result;
    }
};