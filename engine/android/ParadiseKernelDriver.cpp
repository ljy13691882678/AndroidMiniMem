// ============================================================================
// ParadiseKernelDriver.cpp
// ----------------------------------------------------------------------------
// 把 SDK 的 paradise_driver 适配到 MiniMem engine 既有的 CApi 调用面。
//
// 关键语义差异与处理方式
// ───────────────────────────────────────────────────────────────────────────
// 1) 驱动连接
//    paradise_driver 构造时内部执行
//        syscall(__NR_reboot, 0x8e, 0x7a3b9c4d, 0x2f8e1d6b, &fd)
//    取得 anon_fd（反汇编 install_driver_fd @0x80 确认）。不依赖 ko 文件名，
//    也不需要 finit_module。对象无 is_valid()，用一次自读探测连通性。
//
// 2) 进程模型
//    SDK 用 initialize(pid) 把目标写进对象，读写都依赖它，没有句柄表。
//    本类沿用原 AndroidKernelDriver 的约定：handle 就是 pid。
//    但同一对象一次只绑定一个 pid，而 CE 协议允许同时打开多个进程，
//    因此每次读写/查询前都按 handle 重新 initialize（BindProcessLocked）。
//
// 3) 硬件断点
//    paradise hwbp 是「整表下发」模型：hwbp_set(points[], count) 覆盖全部点位，
//    最多 PARADISE_HWBP_MAX_POINTS(16) 个，记录按 point_index 取。
//    本类维护「逻辑 handle -> 点位下标」表，任何增删都重算整表再下发，
//    重建后同步刷新 pointIndex，避免下标错位取到别人的记录。
//
// 4) UXN -> ptebp
//    Paradise 没有「命中挂起线程再 resume」的异常断点。ptebp 是 PTE 级执行断点，
//    命中记录带完整 X0-X29/LR/SP/PC/PSTATE/Q0-Q31 快照，正好满足 UXN 的寄存器快照需求。
//    映射：
//      install -> ptebp 加一个执行断点，分配槽位 0..15
//      wait    -> 轮询 ptebp_get_records，取 hit_count > last_seq 的首条新记录，
//                 转成 ni_uxn_event（state 恒为 ARMED，因为线程不会真的暂停）
//      resume  -> 无挂起，直接成功；带 SET_REGS 时用 ptebp_set_record 回写快照
//      status  -> 由槽位表组合
//      clear   -> ptebp_remove
// ============================================================================

#include "ParadiseKernelDriver.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <limits>
#include <thread>
#include <unistd.h>

#include "Logger.hpp"
#include "paradise_api.h"

namespace {

void CopyStringToBuffer(const std::string& value, char* out, size_t outSize) {
    if (!out || outSize == 0) {
        return;
    }
    std::memset(out, 0, outSize);
    const size_t copyLen = std::min(outSize - 1, value.size());
    if (copyLen > 0) {
        std::memcpy(out, value.data(), copyLen);
    }
}

bool IsValidPidHandle(uint64_t handle) {
    return handle > 0 && handle <= static_cast<uint64_t>(std::numeric_limits<int>::max());
}

/* paradise 的 x0..x29 是连续字段，x30 独立命名 lr。
 * CE 侧的 regs[31] 期望 x0..x30 连续，因此分开填。 */
void FillCeRegs(uint64_t ceRegs[31], const uint64_t* paradiseX0, uint64_t lr) {
    for (int index = 0; index < 30; ++index) {
        ceRegs[index] = paradiseX0[index];
    }
    ceRegs[30] = lr;
}

HW_HIT_ITEM ConvertHwbpRecord(const paradise_hwbp_record& record) {
    HW_HIT_ITEM item{};
    item.hit_addr = record.pc;
    item.hit_time = record.hit_count;   // 驱动不给时间戳，用累计命中数占位
    FillCeRegs(item.regs_info.regs, &record.x0, record.lr);
    item.regs_info.sp = record.sp;
    item.regs_info.pc = record.pc;
    item.regs_info.pstate = record.pstate;
    item.regs_info.orig_x0 = record.orig_x0;
    item.regs_info.syscallno = record.syscallno;
    return item;
}

/* CE 的 bpSize 允许 3（三字节），arm64 硬件断点只接受 1/2/4/8 且必须是 2 的幂。
 * 非法的 3 向上归一到 4，避免整表下发被驱动整体拒绝。 */
uint32_t NormalizeWatchLength(uint32_t length) {
    switch (length) {
        case 1: return 1;
        case 2: return 2;
        case 4: return 4;
        case 8: return 8;
        default: return 4;
    }
}

ni_uxn_event ConvertPtebpToUxnEvent(const paradise_ptebp_record& record,
                                    uint32_t slot, uint32_t pid) {
    ni_uxn_event event{};
    event.slot = slot;
    event.pid = pid;
    event.tid = pid;                  // PTE 记录不含 tid
    // Paradise 不挂起线程，但 CE 协议与 MCP 层都把「有未处理命中」当作 PAUSED 状态，
    // 才能走 wait -> resume 的既有流程。这里如实报告 PAUSED，resume 则是空操作。
    event.state = NI_UXN_STATE_PAUSED;
    event.seq = record.hit_count;
    event.addr = record.pc;
    event.page = record.pc & ~static_cast<uint64_t>(0xfff);
    event.fault_address = record.pc;
    event.esr = 0;
    event.hits = record.hit_count;
    event.false_hits = 0;

    FillCeRegs(event.regs.regs, &record.x0, record.lr);
    event.regs.sp = record.sp;
    event.regs.pc = record.pc;
    event.regs.pstate = record.pstate;

    event.fpsimd.fpsr = record.fpsr;
    event.fpsimd.fpcr = record.fpcr;
    event.fpsimd.flags = NI_UXN_REGS_F_FPSIMD_VALID;
    std::memcpy(event.fpsimd.fp_regs, &record.q0, sizeof(event.fpsimd.fp_regs));
    return event;
}

}  // namespace

/* ============================================================================
 * 全局单例
 * ========================================================================== */

ParadiseKernelDriver& KernelDriver() {
    static auto* driver = new ParadiseKernelDriver();
    return *driver;
}

ParadiseKernelDriver::ParadiseKernelDriver() = default;

ParadiseKernelDriver::~ParadiseKernelDriver() {
    Disconnect();
}

/* ============================================================================
 * 连接
 * ========================================================================== */

int ParadiseKernelDriver::Connect() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (driver_) {
        return 0;
    }

    auto next = std::make_unique<paradise_driver>();

    // SDK 无 is_valid()：绑定自身 pid 后读一个栈变量探测通道。
    // 若驱动禁止自读，再用 is_process_alive 兜底，避免把「可用」误判成「不可用」。
    uint64_t probeValue = 0x4d696e694d656dULL;
    next->initialize(static_cast<pid_t>(getpid()));

    bool alive = false;
    int32_t aliveFlag = 0;
    if (next->read(reinterpret_cast<uintptr_t>(&probeValue), &probeValue,
                   sizeof(probeValue))) {
        alive = true;
    } else {
        const int savedErrno = errno != 0 ? errno : ENODEV;
        alive = next->is_process_alive(static_cast<pid_t>(getpid()), &aliveFlag) &&
                aliveFlag != 0;
        if (!alive) {
            LOGEF("paradise driver connect failed: %s", std::strerror(savedErrno));
            return -savedErrno;
        }
    }

    LOGDF("paradise driver connected (anon_fd)");
    driver_ = std::move(next);
    boundPid_ = static_cast<int32_t>(getpid());
    return 0;
}

bool ParadiseKernelDriver::Disconnect() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!driver_) {
        return false;
    }
    driver_.reset();
    boundPid_ = 0;
    {
        std::lock_guard<std::mutex> hlock(hwbpMutex_);
        hwbpEntries_.clear();
        hwbpInstalled_ = false;
    }
    {
        std::lock_guard<std::mutex> ulock(uxnMutex_);
        for (auto& slot : uxnSlots_) {
            slot = UxnSlot{};
        }
        ptebpInstalled_ = false;
    }
    return true;
}

bool ParadiseKernelDriver::IsConnected() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return driver_ != nullptr;
}

bool ParadiseKernelDriver::GetExpireTime(uint64_t& outExpireTime) {
    // Paradise 无卡密/到期概念，返回 0 表示永久。
    outExpireTime = 0;
    std::lock_guard<std::mutex> lock(mutex_);
    return driver_ != nullptr;
}

/* ============================================================================
 * 进程
 * ========================================================================== */

uint64_t ParadiseKernelDriver::OpenProcess(int pid) {
    if (pid <= 0) {
        return 0;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    paradise_driver* d = driverLocked();
    if (!d) {
        return 0;
    }

    d->initialize(static_cast<pid_t>(pid));
    boundPid_ = pid;

    int32_t alive = 0;
    if (!d->is_process_alive(static_cast<pid_t>(pid), &alive) || alive == 0) {
        LOGEF("paradise OpenProcess: pid %d not alive", pid);
        return 0;
    }
    return static_cast<uint64_t>(pid);
}

bool ParadiseKernelDriver::CloseProcess(uint64_t processHandle) {
    if (!IsValidPidHandle(processHandle)) {
        return false;
    }
    const int32_t pid = static_cast<int32_t>(processHandle);

    // 锁顺序统一为 mutex_ -> hwbpMutex_ -> uxnMutex_，与 Add/Remove 保持一致，
    // 否则 CloseProcess 与 AddHardwareBreakpoint 并发时会互相等待形成死锁。
    std::lock_guard<std::mutex> lock(mutex_);
    {
        std::lock_guard<std::mutex> hlock(hwbpMutex_);
        ClearHwbpEntriesForProcessLocked(pid);
    }
    {
        std::lock_guard<std::mutex> ulock(uxnMutex_);
        ClearUxnSlotsForProcessLocked(pid);
    }

    if (boundPid_ == pid) {
        boundPid_ = 0;
    }
    return true;
}

ssize_t ParadiseKernelDriver::ReadMemory(uint64_t processHandle,
                                        uint64_t address,
                                        void* buffer,
                                        size_t size) {
    if (!IsValidPidHandle(processHandle) || address == 0 || buffer == nullptr || size == 0) {
        return -EINVAL;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    paradise_driver* d = driverLocked();
    if (!d) {
        return -ENODEV;
    }

    const int32_t pid = static_cast<int32_t>(processHandle);
    if (boundPid_ != pid) {
        d->initialize(static_cast<pid_t>(pid));
        boundPid_ = pid;
    }

    // SDK 的 read 是二值返回，不给短读长度。上层 AndroidMemParadise 按页切片调用，
    // 因此这里单次调用对应一页：成功返回 size，失败返回 -1。
    return d->read(address, buffer, size) ? static_cast<ssize_t>(size) : -1;
}

ssize_t ParadiseKernelDriver::WriteMemory(uint64_t processHandle,
                                         uint64_t address,
                                         const void* buffer,
                                         size_t size) {
    if (!IsValidPidHandle(processHandle) || address == 0 || buffer == nullptr || size == 0) {
        return -EINVAL;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    paradise_driver* d = driverLocked();
    if (!d) {
        return -ENODEV;
    }

    const int32_t pid = static_cast<int32_t>(processHandle);
    if (boundPid_ != pid) {
        d->initialize(static_cast<pid_t>(pid));
        boundPid_ = pid;
    }

    return d->write(address, const_cast<void*>(buffer), size)
        ? static_cast<ssize_t>(size) : -1;
}

bool ParadiseKernelDriver::QueryMaps(uint64_t processHandle,
                                     bool showPhysical,
                                     std::vector<DRIVER_REGION_INFO>& out) {
    out.clear();
    if (!IsValidPidHandle(processHandle)) {
        return false;
    }
    (void)showPhysical;   // Paradise 无物理页校验接口，保留参数兼容

    // SDK 未导出 maps 查询，仅此处回退到 /proc（纯枚举，不参与读写）。
    const int32_t pid = static_cast<int32_t>(processHandle);
    const std::string path = "/proc/" + std::to_string(pid) + "/maps";
    FILE* fp = fopen(path.c_str(), "r");
    if (!fp) {
        return false;
    }

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        unsigned long long start = 0;
        unsigned long long end = 0;
        char perms[8] = {0};
        char rest[512] = {0};
        if (sscanf(line, "%llx-%llx %7s %*s %*s %*s %511[^\n]",
                   &start, &end, perms, rest) < 3) {
            continue;
        }

        DRIVER_REGION_INFO region{};
        region.baseaddress = start;
        region.size = end > start ? end - start : 0;

        const bool readable = perms[0] == 'r';
        const bool writable = perms[1] == 'w';
        const bool executable = perms[2] == 'x';
        if (executable) {
            region.protection = writable ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        } else if (writable) {
            region.protection = PAGE_READWRITE;
        } else if (readable) {
            region.protection = PAGE_READONLY;
        } else {
            region.protection = PAGE_NOACCESS;
        }
        region.type = (perms[3] == 's') ? MEM_MAPPED : MEM_PRIVATE;

        const char* name = rest;
        while (*name == ' ') {
            ++name;
        }
        std::strncpy(region.name, name, sizeof(region.name) - 1);
        out.push_back(region);
    }

    fclose(fp);
    return !out.empty();
}

bool ParadiseKernelDriver::IsAddressValid(uint64_t processHandle, uint64_t address) {
    if (!IsValidPidHandle(processHandle) || address == 0) {
        return false;
    }
    uint8_t probe = 0;
    return ReadMemory(processHandle, address, &probe, 1) == 1;
}

bool ParadiseKernelDriver::GetPidList(std::vector<int>& out) {
    out.clear();
    std::lock_guard<std::mutex> lock(mutex_);
    paradise_driver* d = driverLocked();
    if (!d) {
        return false;
    }

    // list_processes 返回位图：bit(pid)=1 表示存活。
    // 位图 64 KiB -> 524288 个 pid 位，覆盖 Linux pid_max 上限。
    constexpr size_t kBitmapBytes = 1u << 16;
    std::vector<uint8_t> bitmap(kBitmapBytes, 0);
    size_t count = 0;
    if (!d->list_processes(bitmap.data(), bitmap.size(), &count)) {
        return false;
    }

    out.reserve(std::min<size_t>(count, kBitmapBytes * 8));
    for (size_t byteIndex = 0; byteIndex < bitmap.size(); ++byteIndex) {
        const uint8_t value = bitmap[byteIndex];
        if (value == 0) {
            continue;
        }
        for (int bit = 0; bit < 8; ++bit) {
            if (value & (1u << bit)) {
                out.push_back(static_cast<int>(byteIndex * 8 + bit));
            }
        }
    }
    return true;
}

bool ParadiseKernelDriver::GetProcessCmdline(int pid, char* out, size_t outSize) {
    if (pid <= 0 || !out || outSize == 0) {
        return false;
    }
    const std::string path = "/proc/" + std::to_string(pid) + "/cmdline";
    FILE* fp = fopen(path.c_str(), "r");
    if (!fp) {
        return false;
    }
    std::memset(out, 0, outSize);
    const size_t read = fread(out, 1, outSize - 1, fp);
    fclose(fp);
    // cmdline 用 \0 分隔，转空格便于展示
    for (size_t index = 0; index + 1 < read; ++index) {
        if (out[index] == '\0') {
            out[index] = ' ';
        }
    }
    return read > 0;
}

bool ParadiseKernelDriver::GetProcessComm(int pid, char* out, size_t outSize) {
    if (pid <= 0 || !out || outSize == 0) {
        return false;
    }
    const std::string path = "/proc/" + std::to_string(pid) + "/comm";
    FILE* fp = fopen(path.c_str(), "r");
    if (!fp) {
        return false;
    }
    std::memset(out, 0, outSize);
    size_t read = fread(out, 1, outSize - 1, fp);
    fclose(fp);
    while (read > 0 && (out[read - 1] == '\n' || out[read - 1] == '\r')) {
        out[--read] = '\0';
    }
    return read > 0;
}

uint64_t ParadiseKernelDriver::GetSoBaseAddress(int pid, const std::string& soName) {
    if (pid <= 0 || soName.empty()) {
        return 0;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    paradise_driver* d = driverLocked();
    if (!d) {
        return 0;
    }
    if (boundPid_ != pid) {
        d->initialize(static_cast<pid_t>(pid));
        boundPid_ = pid;
    }
    return d->get_module_base(soName.c_str());
}

/* ============================================================================
 * 硬件断点
 * ========================================================================== */

int ParadiseKernelDriver::AllocHwbpPointLocked() {
    for (uint32_t index = 0; index < PARADISE_HWBP_MAX_POINTS; ++index) {
        bool used = false;
        for (const auto& kv : hwbpEntries_) {
            if (kv.second.pointIndex == index) {
                used = true;
                break;
            }
        }
        if (!used) {
            return static_cast<int>(index);
        }
    }
    return -1;
}

void ParadiseKernelDriver::RebuildHwbpConfigLocked() {
    // 调用方必须已持有 hwbpMutex_。
    paradise_driver* d = driverLocked();
    if (!d) {
        return;
    }
    if (hwbpEntries_.empty()) {
        d->hwbp_remove();
        hwbpInstalled_ = false;
        return;
    }

    paradise_hwbp_point_config points[PARADISE_HWBP_MAX_POINTS]{};
    uint32_t count = 0;
    for (auto& kv : hwbpEntries_) {
        HwbpEntry& entry = kv.second;
        if (!entry.enabled) {
            continue;
        }
        paradise_hwbp_point_config& point = points[count];
        point.address = entry.address;
        point.type = entry.type;
        point.length = (entry.type == PARADISE_HWBP_EXECUTE)
                           ? 4u
                           : NormalizeWatchLength(entry.length);
        point.scope = PARADISE_HWBP_ALL_THREADS;
        point.reserved = 0;
        entry.pointIndex = count;
        ++count;
    }

    if (count == 0) {
        d->hwbp_remove();
        hwbpInstalled_ = false;
        return;
    }

    // paradise 的 hwbp_set 用对象内 pid 作为 tgid，跨进程断点由上层按进程分组。
    hwbpInstalled_ = d->hwbp_set(points, count);
}

void ParadiseKernelDriver::ClearHwbpEntriesForProcessLocked(int32_t pid) {
    bool changed = false;
    for (auto it = hwbpEntries_.begin(); it != hwbpEntries_.end();) {
        if (it->second.pid == pid) {
            it = hwbpEntries_.erase(it);
            changed = true;
        } else {
            ++it;
        }
    }
    if (changed) {
        RebuildHwbpConfigLocked();
    }
}

HardwareBreakpointInstallResult ParadiseKernelDriver::AddHardwareBreakpoint(
    int pid, uint64_t address, unsigned int len, unsigned int type,
    bool forceReclaim) {
    HardwareBreakpointInstallResult result;
    if (pid <= 0 || address == 0) {
        result.errorCode = EINVAL;
        return result;
    }
    (void)forceReclaim;   // Paradise 无槽位抢占概念

    std::lock_guard<std::mutex> lock(mutex_);
    paradise_driver* d = driverLocked();
    if (!d) {
        result.errorCode = ENODEV;
        return result;
    }
    // paradise 的 hwbp 按 tgid 生效，这里必须绑定进程 pid（不是 tid）
    if (boundPid_ != pid) {
        d->initialize(static_cast<pid_t>(pid));
        boundPid_ = pid;
    }

    std::lock_guard<std::mutex> hlock(hwbpMutex_);

    // 同进程同地址已存在则覆盖（对齐 CE 语义）
    for (auto& kv : hwbpEntries_) {
        if (kv.second.pid == pid && kv.second.address == address) {
            kv.second.type = type;
            kv.second.length = len;
            kv.second.enabled = true;
            RebuildHwbpConfigLocked();
            result.handle = kv.first;
            result.interfaceResult = hwbpInstalled_ ? 0 : -1;
            result.errorCode = hwbpInstalled_ ? 0 : EIO;
            return result;
        }
    }

    if (AllocHwbpPointLocked() < 0) {
        result.errorCode = ENOSPC;
        return result;
    }

    HwbpEntry entry;
    entry.pid = pid;
    entry.address = address;
    entry.type = type;
    entry.length = (type == PARADISE_HWBP_EXECUTE) ? 4u : NormalizeWatchLength(len);

    const uint64_t handle = ++hwbpSeq_;
    hwbpEntries_[handle] = entry;
    RebuildHwbpConfigLocked();

    if (!hwbpInstalled_) {
        hwbpEntries_.erase(handle);
        RebuildHwbpConfigLocked();
        result.errorCode = EIO;
        return result;
    }

    result.handle = handle;
    result.interfaceResult = 0;
    return result;
}

bool ParadiseKernelDriver::RemoveHardwareBreakpoint(uint64_t handle) {
    if (handle == 0) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (!driverLocked()) {
        return false;
    }

    std::lock_guard<std::mutex> hlock(hwbpMutex_);
    auto it = hwbpEntries_.find(handle);
    if (it == hwbpEntries_.end()) {
        return false;
    }
    hwbpEntries_.erase(it);
    RebuildHwbpConfigLocked();
    return true;
}

bool ParadiseKernelDriver::DisableHardwareBreakpoint(uint64_t handle) {
    if (handle == 0) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (!driverLocked()) {
        return false;
    }

    std::lock_guard<std::mutex> hlock(hwbpMutex_);
    auto it = hwbpEntries_.find(handle);
    if (it == hwbpEntries_.end()) {
        return false;
    }
    it->second.enabled = false;
    RebuildHwbpConfigLocked();
    return true;
}

bool ParadiseKernelDriver::EnableHardwareBreakpoint(uint64_t handle) {
    if (handle == 0) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (!driverLocked()) {
        return false;
    }

    std::lock_guard<std::mutex> hlock(hwbpMutex_);
    auto it = hwbpEntries_.find(handle);
    if (it == hwbpEntries_.end()) {
        return false;
    }
    it->second.enabled = true;
    RebuildHwbpConfigLocked();
    return true;
}

bool ParadiseKernelDriver::ReadHardwareBreakpointInfo(uint64_t handle,
                                                     uint64_t& totalHitCount,
                                                     std::vector<HW_HIT_ITEM>& out) {
    totalHitCount = 0;
    out.clear();
    if (handle == 0) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    paradise_driver* d = driverLocked();
    if (!d) {
        return false;
    }

    std::lock_guard<std::mutex> hlock(hwbpMutex_);
    auto it = hwbpEntries_.find(handle);
    if (it == hwbpEntries_.end()) {
        return false;
    }
    HwbpEntry& entry = it->second;

    std::vector<paradise_hwbp_record> records(PARADISE_HWBP_MAX_RECORDS);
    uint32_t fetched = 0;
    if (!d->hwbp_get_records(entry.pointIndex, 0, records.data(),
                             static_cast<uint32_t>(records.size()), &fetched)) {
        return false;
    }
    records.resize(std::min<size_t>(fetched, records.size()));

    // 记录按触发 PC 聚合，hit_count 是累计值。这里把每条有效记录都上报，
    // 上层再按 PC/命中数做聚合（与 NI 的「拉取即清空」差异由 MCP 层消化）。
    for (const auto& record : records) {
        if (record.hit_count == 0) {
            continue;
        }
        out.push_back(ConvertHwbpRecord(record));
    }

    entry.reportedHits = out.size();
    totalHitCount = entry.reportedHits;
    return true;
}

bool ParadiseKernelDriver::QueryHardwareBreakpointTask(
    int tid, uint32_t capacity, HardwareBreakpointTaskQueryResult& out) {
    out = HardwareBreakpointTaskQueryResult{};
    out.tid = tid;
    out.summary.tid = tid;
    if (tid <= 0 || capacity == 0 || capacity > NI_HWBP_MAX_QUERY_ENTRIES) {
        out.errorCode = EINVAL;
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    paradise_driver* d = driverLocked();
    if (!d) {
        out.errorCode = ENODEV;
        return false;
    }

    std::lock_guard<std::mutex> hlock(hwbpMutex_);

    // Paradise 断点是进程级（scope=ALL_THREADS），所有线程共享一份配置，
    // 因此按 tid 返回同一份结果。上层按线程维度展示时不会出现分歧。
    paradise_hwbp_config config{};
    if (!d->hwbp_get_config(&config)) {
        out.errorCode = EIO;
        return false;
    }

    out.success = true;
    out.summary.capacity = capacity;
    out.summary.total_count = config.point_count;
    out.summary.brp_count = static_cast<uint32_t>(config.num_brps);
    out.summary.wrp_count = static_cast<uint32_t>(config.num_wrps);
    out.summary.enabled_count = config.point_count;
    out.summary.active_count = config.point_count;
    out.summary.perf_count = 0;
    out.summary.ptrace_count = 0;
    out.summary.module_count = config.point_count;

    const uint32_t limit = std::min<uint32_t>(config.point_count, capacity);
    out.entries.reserve(limit);
    for (uint32_t index = 0; index < limit; ++index) {
        const paradise_hwbp_point_config& point = config.points[index];
        ni_hwbp_task_entry entry{};
        entry.event_id = index;
        entry.module_handle = 0;
        entry.addr = point.address;
        entry.tid = tid;
        entry.oncpu = 0;
        entry.type = point.type;
        entry.len = point.length;
        entry.state = (point.address != 0) ? 6 : 0;   // 6 = active
        entry.source = 2;                            // 2 = module（内核下发）
        entry.flags = 1;                             // 1 = enabled
        out.entries.push_back(entry);
    }
    out.summary.count = static_cast<uint32_t>(out.entries.size());
    out.summary.entries = 0;
    return true;
}

/* ============================================================================
 * UXN（ptebp 承载）
 * ========================================================================== */

int ParadiseKernelDriver::AllocPtebpPointLocked() {
    for (uint32_t index = 0; index < PARADISE_PTEBP_MAX_POINTS; ++index) {
        bool used = false;
        for (const auto& slot : uxnSlots_) {
            if (slot.used && slot.pointIndex == index) {
                used = true;
                break;
            }
        }
        if (!used) {
            return static_cast<int>(index);
        }
    }
    return -1;
}

void ParadiseKernelDriver::RebuildPtebpConfigLocked() {
    // 调用方必须已持有 uxnMutex_。
    paradise_driver* d = driverLocked();
    if (!d) {
        return;
    }

    paradise_ptebp_point_config points[PARADISE_PTEBP_MAX_POINTS]{};
    uint32_t count = 0;
    for (auto& slot : uxnSlots_) {
        if (!slot.used) {
            continue;
        }
        paradise_ptebp_point_config& point = points[count];
        point.address = slot.address;
        point.type = PARADISE_HWBP_EXECUTE;
        point.length = 4;
        point.scope = PARADISE_HWBP_ALL_THREADS;
        point.reserved = 0;
        slot.pointIndex = count;
        ++count;
    }

    if (count == 0) {
        d->ptebp_remove();
        ptebpInstalled_ = false;
        return;
    }
    ptebpInstalled_ = d->ptebp_set(points, count);
}

void ParadiseKernelDriver::ClearUxnSlotsForProcessLocked(int32_t pid) {
    bool changed = false;
    for (auto& slot : uxnSlots_) {
        if (slot.used && slot.pid == pid) {
            slot = UxnSlot{};
            changed = true;
        }
    }
    if (changed) {
        RebuildPtebpConfigLocked();
    }
}

UxnOperationResult ParadiseKernelDriver::InstallUxnBreakpoint(ni_uxn_install& request) {
    if (request.pid == 0 || request.addr == 0 || (request.addr & 0x3) != 0 ||
        request.flags != 0) {
        return {false, EINVAL};
    }

    std::lock_guard<std::mutex> lock(mutex_);
    paradise_driver* d = driverLocked();
    if (!d) {
        return {false, ENODEV};
    }
    if (boundPid_ != static_cast<int32_t>(request.pid)) {
        d->initialize(static_cast<pid_t>(request.pid));
        boundPid_ = static_cast<int32_t>(request.pid);
    }

    std::lock_guard<std::mutex> ulock(uxnMutex_);

    for (uint32_t index = 0; index < NI_UXN_MAX_SLOTS; ++index) {
        UxnSlot& slot = uxnSlots_[index];
        if (slot.used && slot.pid == static_cast<int32_t>(request.pid) &&
            slot.address == request.addr) {
            request.slot = index;
            return {true, 0};
        }
    }

    if (AllocPtebpPointLocked() < 0) {
        return {false, ENOSPC};
    }

    for (uint32_t index = 0; index < NI_UXN_MAX_SLOTS; ++index) {
        UxnSlot& slot = uxnSlots_[index];
        if (slot.used) {
            continue;
        }

        slot.used = true;
        slot.pid = static_cast<int32_t>(request.pid);
        slot.address = request.addr;
        slot.lastSeq = 0;
        slot.deliveredHits = 0;

        RebuildPtebpConfigLocked();
        if (!ptebpInstalled_) {
            slot = UxnSlot{};
            RebuildPtebpConfigLocked();
            return {false, EIO};
        }
        request.slot = index;
        return {true, 0};
    }
    return {false, ENOSPC};
}

UxnOperationResult ParadiseKernelDriver::RemoveUxnBreakpoint(
    uint32_t pid, uint64_t address) {
    if (pid == 0 || address == 0 || (address & 0x3) != 0) {
        return {false, EINVAL};
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (!driverLocked()) {
        return {false, ENODEV};
    }

    std::lock_guard<std::mutex> ulock(uxnMutex_);
    bool found = false;
    for (auto& slot : uxnSlots_) {
        if (slot.used && slot.pid == static_cast<int32_t>(pid) &&
            slot.address == address) {
            slot = UxnSlot{};
            found = true;
            break;
        }
    }
    if (!found) {
        return {false, ENOENT};
    }
    RebuildPtebpConfigLocked();
    return {true, 0};
}

UxnOperationResult ParadiseKernelDriver::WaitUxnBreakpoint(ni_uxn_wait& request) {
    if (request.slot != NI_UXN_WAIT_ANY_SLOT &&
        request.slot >= NI_UXN_MAX_SLOTS) {
        return {false, EINVAL};
    }

    // 整个等待期间持有主锁，避免 driver_ 在轮询过程中被 Disconnect 释放。
    // CE 命令本身串行处理，等待阻塞不会与其他命令交叉。
    std::lock_guard<std::mutex> lock(mutex_);
    paradise_driver* d = driverLocked();
    if (!d) {
        return {false, ENODEV};
    }

    const uint32_t timeoutMs = std::min<uint32_t>(
        std::max<uint32_t>(request.timeout_ms, 1), 60000);
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeoutMs);

    while (true) {
        {
            std::lock_guard<std::mutex> ulock(uxnMutex_);

            std::vector<uint32_t> candidates;
            if (request.slot == NI_UXN_WAIT_ANY_SLOT) {
                for (uint32_t index = 0; index < NI_UXN_MAX_SLOTS; ++index) {
                    if (uxnSlots_[index].used) {
                        candidates.push_back(index);
                    }
                }
            } else {
                candidates.push_back(request.slot);
            }

            for (uint32_t slotIndex : candidates) {
                UxnSlot& slot = uxnSlots_[slotIndex];
                if (!slot.used) {
                    continue;
                }

                std::vector<paradise_ptebp_record> records(PARADISE_PTEBP_MAX_RECORDS);
                uint32_t fetched = 0;
                if (!d->ptebp_get_records(slot.pointIndex, 0, records.data(),
                                          static_cast<uint32_t>(records.size()),
                                          &fetched)) {
                    slot.lastError = EIO;
                    continue;
                }
                records.resize(std::min<size_t>(fetched, records.size()));

                for (const auto& record : records) {
                    if (record.hit_count <= request.last_seq) {
                        continue;
                    }
                    request.event = ConvertPtebpToUxnEvent(
                        record, slotIndex, static_cast<uint32_t>(slot.pid));
                    slot.lastSeq = record.hit_count;
                    slot.deliveredHits += 1;
                    return {true, 0};
                }
            }
        }

        if (std::chrono::steady_clock::now() >= deadline) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    // 超时返回失败而不是空事件：CE 层把 state=EMPTY 视为协议错误（EPROTO），
    // 用 ETIMEDOUT 才能让调用方正确区分「没命中」和「协议异常」。
    request.event = {};
    return {false, ETIMEDOUT};
}

UxnOperationResult ParadiseKernelDriver::ResumeUxnBreakpoint(
    const ni_uxn_resume& request) {
    if (request.slot >= NI_UXN_MAX_SLOTS ||
        (request.flags & ~NI_UXN_RESUME_F_SET_REGS) != 0) {
        return {false, EINVAL};
    }

    std::lock_guard<std::mutex> lock(mutex_);
    paradise_driver* d = driverLocked();
    if (!d) {
        return {false, ENODEV};
    }

    std::lock_guard<std::mutex> ulock(uxnMutex_);
    UxnSlot& slot = uxnSlots_[request.slot];
    if (!slot.used) {
        return {false, ENOENT};
    }

    // Paradise 不暂停线程，无需恢复动作。
    if ((request.flags & NI_UXN_RESUME_F_SET_REGS) == 0) {
        return {true, 0};
    }

    // 写回寄存器：修改该点位最新一条记录的寄存器快照。
    std::vector<paradise_ptebp_record> records(PARADISE_PTEBP_MAX_RECORDS);
    uint32_t fetched = 0;
    if (!d->ptebp_get_records(slot.pointIndex, 0, records.data(),
                              static_cast<uint32_t>(records.size()), &fetched) ||
        fetched == 0) {
        return {false, ENOENT};
    }
    records.resize(std::min<size_t>(fetched, records.size()));

    paradise_ptebp_record& target = records.back();
    for (int index = 0; index < 30; ++index) {
        (&target.x0)[index] = request.regs.regs[index];
    }
    target.lr = request.regs.regs[30];
    target.sp = request.regs.sp;
    target.pc = request.regs.pc;
    target.pstate = request.regs.pstate;

    if (!d->ptebp_set_record(slot.pointIndex,
                             static_cast<uint32_t>(records.size() - 1),
                             &target)) {
        return {false, EIO};
    }
    return {true, 0};
}

UxnOperationResult ParadiseKernelDriver::GetUxnBreakpointStatus(
    uint32_t slotIndex, ni_uxn_status& status) {
    status = {};
    status.slot = slotIndex;
    if (slotIndex >= NI_UXN_MAX_SLOTS) {
        return {false, EINVAL};
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (!driverLocked()) {
        return {false, ENODEV};
    }

    std::lock_guard<std::mutex> ulock(uxnMutex_);
    const UxnSlot& slot = uxnSlots_[slotIndex];
    if (!slot.used) {
        return {true, 0};
    }

    status.used = 1;
    status.pid = static_cast<uint32_t>(slot.pid);
    status.tid = static_cast<uint32_t>(slot.pid);
    status.state = NI_UXN_STATE_PAUSED;   // 与 wait 事件保持一致，见 ConvertPtebpToUxnEvent
    status.last_error = slot.lastError;
    status.addr = slot.address;
    status.page = slot.address & ~static_cast<uint64_t>(0xfff);
    status.hits = slot.deliveredHits;
    status.false_hits = 0;
    status.step_hits = 0;
    status.resumes = 0;
    status.seq = slot.lastSeq;
    return {true, 0};
}

UxnOperationResult ParadiseKernelDriver::ClearUxnBreakpoints() {
    std::lock_guard<std::mutex> lock(mutex_);
    paradise_driver* d = driverLocked();
    if (!d) {
        return {false, ENODEV};
    }

    std::lock_guard<std::mutex> ulock(uxnMutex_);
    for (auto& slot : uxnSlots_) {
        slot = UxnSlot{};
    }
    d->ptebp_remove();
    ptebpInstalled_ = false;
    return {true, 0};
}

/* ============================================================================
 * 内部
 * ========================================================================== */

paradise_driver* ParadiseKernelDriver::driverLocked() {
    return driver_.get();
}

const paradise_driver* ParadiseKernelDriver::driverLocked() const {
    return driver_.get();
}
