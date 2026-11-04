#pragma once
// ============================================================================
// ParadiseHwBreakpoint.hpp — 进程级硬件断点封装（替代 KernelHwBreakpoint）
// ----------------------------------------------------------------------------
// 旧实现之所以要为每个 tid 单独下断并起后台线程 rescan /proc/<pid>/task，
// 是因为 NI 的硬件断点是 per-tid 的。Paradise 的 hwbp_set 带 scope 参数，
// 一次可以覆盖 MAIN_THREAD / OTHER_THREADS / ALL_THREADS，驱动侧自己跟随线程，
// 因此这里退化成「一个逻辑 handle == 驱动里一个点位」的薄封装：
//
//   逻辑 handle  ──►  driver point index
//   一次下发整表 ──►  AddHardwareBreakpoint 内部重算并 hwbp_set
//
// 对外接口与 KernelHwBreakpoint 保持一致，CApi 不需要感知后端差异。
// 命中沿用「被动累积 + 主动拉取」模型，与 NI 相同。
// ============================================================================

#include <atomic>
#include <cstdint>
#include <map>
#include <mutex>
#include <vector>

#include "ParadiseKernelDriver.h"
#include "Logger.hpp"

// 逻辑断点 handle 的高位标记（bit61）。归属判别以 Owns() 为权威，tag 仅作可读性标识。
static constexpr uint64_t PARADISE_BP_HANDLE_TAG = 0x2000000000000000ULL;

class ParadiseHwBreakpoint {
public:
    static ParadiseHwBreakpoint& Get() {
        static ParadiseHwBreakpoint inst;
        return inst;
    }

    // 进程级下断：pid 是目标进程，不是线程。Paradise 由驱动按 scope 覆盖全部线程。
    uint64_t AddProcessHwBp(int pid, uint64_t addr, unsigned int len,
                            unsigned int type, bool forceReclaim) {
        if (pid <= 0 || addr == 0) {
            return 0;
        }

        const HardwareBreakpointInstallResult install =
            KernelDriver().AddHardwareBreakpoint(pid, addr, len, type,
                                                 forceReclaim);
        if (install.handle == 0) {
            LOGEF("[pbp] 下断失败 pid=%d addr=0x%llx type=%u len=%u "
                  "interface_result=%d error=%d(%s)",
                  pid, (unsigned long long)addr, type, len,
                  install.interfaceResult, install.errorCode,
                  strerror(install.errorCode));
            return 0;
        }

        std::lock_guard<std::mutex> lk(mMutex);
        Entry entry;
        entry.pid = pid;
        entry.bp_addr = addr;
        entry.bp_len = len;
        entry.bp_type = type;
        entry.enabled = true;
        entry.driverHandle = install.handle;

        const uint64_t handle = PARADISE_BP_HANDLE_TAG | (uint64_t)(++mSeq);
        mEntries[handle] = entry;

        LOGDF("[pbp] 下断成功 pid=%d addr=0x%llx type=%u len=%u "
              "driver_handle=0x%llx logical_handle=0x%llx",
              pid, (unsigned long long)addr, type, len,
              (unsigned long long)install.handle,
              (unsigned long long)handle);
        return handle;
    }

    bool DelProcessHwBp(uint64_t h) {
        std::lock_guard<std::mutex> lk(mMutex);
        auto it = mEntries.find(h);
        if (it == mEntries.end()) {
            return false;
        }
        KernelDriver().RemoveHardwareBreakpoint(it->second.driverHandle);
        mEntries.erase(it);
        LOGDF("[pbp] 删除断点 handle=0x%llx", (unsigned long long)h);
        return true;
    }

    bool SuspendProcessHwBp(uint64_t h) {
        std::lock_guard<std::mutex> lk(mMutex);
        auto it = mEntries.find(h);
        if (it == mEntries.end()) {
            return false;
        }
        if (!KernelDriver().DisableHardwareBreakpoint(it->second.driverHandle)) {
            return false;
        }
        it->second.enabled = false;
        return true;
    }

    bool ResumeProcessHwBp(uint64_t h) {
        std::lock_guard<std::mutex> lk(mMutex);
        auto it = mEntries.find(h);
        if (it == mEntries.end()) {
            return false;
        }
        if (!KernelDriver().EnableHardwareBreakpoint(it->second.driverHandle)) {
            return false;
        }
        it->second.enabled = true;
        return true;
    }

    bool ReadHwBpInfo(uint64_t h, uint64_t& nHitTotalCount,
                      std::vector<HW_HIT_ITEM>& vOutput) {
        std::lock_guard<std::mutex> lk(mMutex);
        auto it = mEntries.find(h);
        if (it == mEntries.end()) {
            return false;
        }
        uint64_t count = 0;
        if (!KernelDriver().ReadHardwareBreakpointInfo(it->second.driverHandle,
                                                       count, vOutput)) {
            return false;
        }
        nHitTotalCount = count;
        return true;
    }

    // 后端归属判别（权威）。
    bool Owns(uint64_t h) {
        std::lock_guard<std::mutex> lk(mMutex);
        return mEntries.find(h) != mEntries.end();
    }

private:
    struct Entry {
        int pid = 0;
        uint64_t bp_addr = 0;
        unsigned int bp_len = 0;
        unsigned int bp_type = 0;
        bool enabled = true;
        uint64_t driverHandle = 0;
    };

    std::mutex mMutex;
    std::map<uint64_t, Entry> mEntries;
    std::atomic<uint32_t> mSeq{0};

    ParadiseHwBreakpoint() = default;
    ~ParadiseHwBreakpoint() {
        std::lock_guard<std::mutex> lk(mMutex);
        for (auto& kv : mEntries) {
            KernelDriver().RemoveHardwareBreakpoint(kv.second.driverHandle);
        }
        mEntries.clear();
    }
    ParadiseHwBreakpoint(const ParadiseHwBreakpoint&) = delete;
    ParadiseHwBreakpoint& operator=(const ParadiseHwBreakpoint&) = delete;
};