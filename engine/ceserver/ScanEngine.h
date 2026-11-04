#pragma once
// ============================================================================
// ScanEngine.h — 内存数值扫描会话
// ----------------------------------------------------------------------------
// 设计要点
//   1. 扫描在设备端执行（engine 内），只把地址和当前值回传，避免把进程内存搬到 PC。
//   2. 一次扫描是一个有状态的会话：首次扫描建立候选集，再次扫描按变化模式过滤。
//   3. 读取走 g_memIO（即当前内存通道），所以内核模式初始化后自动获得内核级读取能力。
//   4. 候选集按地址升序保存，再次扫描时按 4KB 页批量读，把 syscall 次数压到页数量级。
// ============================================================================

#include <cstdint>
#include <mutex>
#include <vector>

#include "../common/IMemoryOp.hpp"
#include "ceserver.h"

class ScanEngine {
public:
    static ScanEngine& Get();

    // 首次扫描。成功返回 true，totalOut 为候选数量。
    bool FirstScan(IMemoryOp* mem, pid_t pid, const CeScanFirstInput& in,
                   uint64_t& totalOut, int& errorCode);

    // 再次扫描。要求先有候选集。
    bool NextScan(IMemoryOp* mem, const CeScanNextInput& in,
                  uint64_t& totalOut, int& errorCode);

    // 分页取结果。
    uint32_t Results(const CeScanResultsInput& in,
                     std::vector<CeScanResultEntry>& out) const;

    void Clear();

    uint64_t Total() const;
    bool Active() const;
    pid_t SessionPid() const;
    uint32_t SessionValueType() const;

    // 候选地址数量上限：150 万，约 12MB 地址表 + 12MB 前值表
    static constexpr uint64_t kDefaultMaxResults = 1500000;

private:
    ScanEngine() = default;

    static uint32_t ValueWidth(uint32_t valueType);
    static bool ValueIsFloat(uint32_t valueType);
    static void ReadAt(const uint8_t* base, size_t avail, size_t off,
                       uint32_t type, uint64_t& iv, double& fv);
    static bool Match(const CeScanFirstInput& in, uint64_t iv, double fv);
    static bool MatchNext(uint32_t mode, uint64_t iv, double fv,
                          uint64_t piv, double pfv,
                          uint64_t wantIv, double wantFv);

    mutable std::mutex mutex_;
    bool active_ = false;
    pid_t pid_ = 0;
    uint32_t valueType_ = CE_SCAN_TYPE_DWORD;
    uint32_t alignment_ = 4;
    std::vector<uint64_t> addresses_;
    std::vector<uint64_t> prevInt_;
    std::vector<double> prevFloat_;
};