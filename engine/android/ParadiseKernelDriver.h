#pragma once
// ============================================================================
// ParadiseKernelDriver.h — Paradise 内核驱动封装（替代 AndroidKernelDriver）
// ----------------------------------------------------------------------------
// 底层直接用 SDK 的 paradise_driver（libparadise_api.a），对外保持与原
// AndroidKernelDriver 一致的职责划分：
//   · 连接 / 断开 / 授权时间
//   · 进程打开关闭、内存读写、maps 枚举
//   · 硬件断点（hwbp）与 PTE 执行断点（ptebp）
//   · UXN 语义映射（由 ptebp 承载）
//
// 与 NI 驱动的差异：
//   · Paradise 用 initialize(pid) 绑定目标，没有句柄表；本类沿用「handle == pid」。
//   · Paradise 的 hwbp 是「整表下发、最多 16 点位、按触发 PC 聚合」的批式模型，
//     不是 per-tid 句柄模型。本类维护逻辑 handle -> 点位下标的映射，
//     任何增删都重算整表再下发。
//   · Paradise 的 ptebp 只支持执行断点，正好承接原 UXN 的用途。
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include <sys/types.h>

#include "AndroidDriverTypes.h"
#include "ParadiseTypes.h"

// paradise_api.h 中的 paradise_driver，前置声明避免 SDK 头文件扩散。
class paradise_driver;

struct HardwareBreakpointInstallResult {
    uint64_t handle = 0;
    int interfaceResult = -1;
    int errorCode = 0;
    uint32_t reclaimedSlots = 0;
    uint32_t blockedSlots = 0;
};

struct HardwareBreakpointTaskQueryResult {
    int tid = 0;
    bool success = false;
    int errorCode = 0;
    ni_hwbp_task_query summary{};
    std::vector<ni_hwbp_task_entry> entries;
};

struct UxnOperationResult {
    bool success = false;
    int errorCode = 0;
};

class ParadiseKernelDriver {
public:
    ParadiseKernelDriver();
    ~ParadiseKernelDriver();

    ParadiseKernelDriver(const ParadiseKernelDriver&) = delete;
    ParadiseKernelDriver& operator=(const ParadiseKernelDriver&) = delete;

    /* ── 连接与模块信息 ─────────────────────────────────────── */

    int Connect();
    bool Disconnect();
    bool IsConnected() const;
    bool GetExpireTime(uint64_t& outExpireTime);

    /* ── 进程与内存 ─────────────────────────────────────────── */

    uint64_t OpenProcess(int pid);
    bool CloseProcess(uint64_t processHandle);

    ssize_t ReadMemory(uint64_t processHandle, uint64_t address,
                       void* buffer, size_t size);
    ssize_t WriteMemory(uint64_t processHandle, uint64_t address,
                        const void* buffer, size_t size);

    bool QueryMaps(uint64_t processHandle, bool showPhysical,
                   std::vector<DRIVER_REGION_INFO>& out);
    bool IsAddressValid(uint64_t processHandle, uint64_t address);

    bool GetPidList(std::vector<int>& out);
    bool GetProcessCmdline(int pid, char* out, size_t outSize);
    bool GetProcessComm(int pid, char* out, size_t outSize);
    uint64_t GetSoBaseAddress(int pid, const std::string& soName);

    /* ── 硬件断点（paradise hwbp） ──────────────────────────── */

    HardwareBreakpointInstallResult AddHardwareBreakpoint(
        int pid, uint64_t address, unsigned int len, unsigned int type,
        bool forceReclaim = false);
    bool QueryHardwareBreakpointTask(int tid, uint32_t capacity,
                                     HardwareBreakpointTaskQueryResult& out);
    bool RemoveHardwareBreakpoint(uint64_t handle);
    bool DisableHardwareBreakpoint(uint64_t handle);
    bool EnableHardwareBreakpoint(uint64_t handle);
    bool ReadHardwareBreakpointInfo(uint64_t handle,
                                    uint64_t& totalHitCount,
                                    std::vector<HW_HIT_ITEM>& out);

    /* ── UXN 语义（由 ptebp 承载） ──────────────────────────── */

    UxnOperationResult InstallUxnBreakpoint(ni_uxn_install& request);
    UxnOperationResult RemoveUxnBreakpoint(uint32_t pid, uint64_t address);
    UxnOperationResult WaitUxnBreakpoint(ni_uxn_wait& request);
    UxnOperationResult ResumeUxnBreakpoint(const ni_uxn_resume& request);
    UxnOperationResult GetUxnBreakpointStatus(uint32_t slot,
                                              ni_uxn_status& status);
    UxnOperationResult ClearUxnBreakpoints();

private:
    /* 逻辑断点：一个地址对应驱动配置里的一个点位下标 */
    struct HwbpEntry {
        int32_t  pid = 0;
        uint64_t address = 0;
        uint32_t type = 0;
        uint32_t length = 0;
        uint32_t pointIndex = 0;
        bool     enabled = true;
        uint64_t reportedHits = 0;
    };

    /* UXN 槽位：一个槽对应一个 ptebp 点位 */
    struct UxnSlot {
        bool     used = false;
        int32_t  pid = 0;
        uint64_t address = 0;
        uint32_t pointIndex = 0;
        uint64_t lastSeq = 0;
        uint64_t deliveredHits = 0;
        int32_t  lastError = 0;
    };

    paradise_driver* driverLocked();
    const paradise_driver* driverLocked() const;

    void RebuildHwbpConfigLocked();
    void RebuildPtebpConfigLocked();
    void ClearHwbpEntriesForProcessLocked(int32_t pid);
    void ClearUxnSlotsForProcessLocked(int32_t pid);
    int  AllocHwbpPointLocked();
    int  AllocPtebpPointLocked();

    mutable std::mutex mutex_;
    std::unique_ptr<paradise_driver> driver_;
    int32_t boundPid_ = 0;

    std::mutex hwbpMutex_;
    std::unordered_map<uint64_t, HwbpEntry> hwbpEntries_;
    uint64_t hwbpSeq_ = 0;
    bool hwbpInstalled_ = false;

    std::mutex uxnMutex_;
    UxnSlot uxnSlots_[NI_UXN_MAX_SLOTS];
    bool ptebpInstalled_ = false;
};

ParadiseKernelDriver& KernelDriver();