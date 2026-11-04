#include "ScanEngine.h"

#include <algorithm>
#include <cerrno>
#include <cstring>

#include "Logger.hpp"

namespace {

constexpr size_t kChunkSize = 256 * 1024;   // 首次扫描的块大小
constexpr size_t kPageSize = 4096;
constexpr size_t kPageBuf = kPageSize * 2;  // 留一次跨页余量

inline uint64_t AlignUp(uint64_t value, uint64_t alignment) {
    if (alignment <= 1) {
        return value;
    }
    const uint64_t mask = alignment - 1;
    return (value + mask) & ~mask;
}

}  // namespace

ScanEngine& ScanEngine::Get() {
    static ScanEngine inst;
    return inst;
}

uint32_t ScanEngine::ValueWidth(uint32_t valueType) {
    switch (valueType) {
        case CE_SCAN_TYPE_BYTE:
            return 1;
        case CE_SCAN_TYPE_WORD:
            return 2;
        case CE_SCAN_TYPE_DWORD:
            return 4;
        case CE_SCAN_TYPE_QWORD:
            return 8;
        case CE_SCAN_TYPE_FLOAT:
            return 4;
        case CE_SCAN_TYPE_DOUBLE:
            return 8;
        default:
            return 0;
    }
}

bool ScanEngine::ValueIsFloat(uint32_t valueType) {
    return valueType == CE_SCAN_TYPE_FLOAT || valueType == CE_SCAN_TYPE_DOUBLE;
}

// 从连续内存块里按类型解码一个值。调用方保证 off + width <= avail。
void ScanEngine::ReadAt(const uint8_t* base, size_t avail, size_t off,
                        uint32_t type, uint64_t& iv, double& fv) {
    iv = 0;
    fv = 0.0;
    const uint8_t* p = base + off;
    switch (type) {
        case CE_SCAN_TYPE_BYTE:
            iv = *p;
            break;
        case CE_SCAN_TYPE_WORD: {
            uint16_t v = 0;
            std::memcpy(&v, p, sizeof(v));
            iv = v;
            break;
        }
        case CE_SCAN_TYPE_DWORD: {
            uint32_t v = 0;
            std::memcpy(&v, p, sizeof(v));
            iv = v;
            break;
        }
        case CE_SCAN_TYPE_QWORD: {
            uint64_t v = 0;
            std::memcpy(&v, p, sizeof(v));
            iv = v;
            break;
        }
        case CE_SCAN_TYPE_FLOAT: {
            float v = 0.0f;
            std::memcpy(&v, p, sizeof(v));
            fv = static_cast<double>(v);
            break;
        }
        case CE_SCAN_TYPE_DOUBLE: {
            double v = 0.0;
            std::memcpy(&v, p, sizeof(v));
            fv = v;
            break;
        }
        default:
            break;
    }
    (void)avail;
}

bool ScanEngine::Match(const CeScanFirstInput& in, uint64_t iv, double fv) {
    if (in.scanMode == CE_SCAN_UNKNOWN) {
        return true;    // 未知初始值：全部收录，后续用「变化」类模式收窄
    }
    if (ValueIsFloat(in.valueType)) {
        return fv == in.floatValue;
    }
    return iv == in.intValue;
}

bool ScanEngine::MatchNext(uint32_t mode, uint64_t iv, double fv,
                           uint64_t piv, double pfv,
                           uint64_t wantIv, double wantFv) {
    switch (mode) {
        case CE_SCAN_UNCHANGED:
            return iv == piv && fv == pfv;
        case CE_SCAN_CHANGED:
            return !(iv == piv && fv == pfv);
        case CE_SCAN_INCREASED:
            return fv != pfv ? fv > pfv : iv > piv;
        case CE_SCAN_DECREASED:
            return fv != pfv ? fv < pfv : iv < piv;
        case CE_SCAN_EXACT:
            return fv != 0.0 || wantFv != 0.0 ? fv == wantFv : iv == wantIv;
        case CE_SCAN_BIGGER:
            return fv != 0.0 || wantFv != 0.0 ? fv > wantFv : iv > wantIv;
        case CE_SCAN_SMALLER:
            return fv != 0.0 || wantFv != 0.0 ? fv < wantFv : iv < wantIv;
        default:
            return false;
    }
}

bool ScanEngine::FirstScan(IMemoryOp* mem, pid_t pid, const CeScanFirstInput& in,
                           uint64_t& totalOut, int& errorCode) {
    totalOut = 0;
    errorCode = 0;

    if (!mem || pid <= 0) {
        errorCode = EINVAL;
        return false;
    }
    const uint32_t width = ValueWidth(in.valueType);
    if (width == 0) {
        errorCode = EINVAL;
        return false;
    }
    if (in.scanMode != CE_SCAN_EXACT && in.scanMode != CE_SCAN_UNKNOWN) {
        errorCode = EINVAL;   // 首次扫描只支持精确值与未知值
        return false;
    }

    uint32_t alignment = in.alignment ? in.alignment : width;
    if (alignment != 1 && alignment != 2 && alignment != 4 && alignment != 8) {
        errorCode = EINVAL;
        return false;
    }
    alignment = std::max(alignment, width);
    if (alignment > 8) {
        alignment = width;
    }

    // 目标进程必须已完成 OpenProcess，读操作依赖 mem 内部状态
    if (mem->GetProcessId() != pid) {
        if (!mem->OpenProcess(pid)) {
            errorCode = ESRCH;
            return false;
        }
    }

    std::vector<ProcessMap> maps = mem->GetProcessMaps();
    if (maps.empty()) {
        errorCode = ENODATA;
        return false;
    }

    const uint64_t maxResults =
        in.maxResults ? in.maxResults : kDefaultMaxResults;

    std::vector<uint64_t> addrs;
    std::vector<uint64_t> ints;
    std::vector<double> floats;
    addrs.reserve(4096);

    std::vector<uint8_t> buf(kChunkSize);
    bool truncated = false;

    for (const auto& map : maps) {
        if (truncated) {
            break;
        }
        if (!map.IsValid()) {
            continue;
        }
        const bool readable = map.readable || (map.perms.size() > 0 && map.perms[0] == 'r');
        const bool writable = map.writable || (map.perms.size() > 1 && map.perms[1] == 'w');
        if (!readable) {
            continue;
        }
        if (in.regionFilter == CE_SCAN_REGION_WRITABLE && !writable) {
            continue;
        }
        if (map.pathname.find("[vvar]") != std::string::npos ||
            map.pathname.find("[vsyscall]") != std::string::npos) {
            continue;
        }

        for (uint64_t cursor = map.startAddress; cursor < map.endAddress;
             cursor += kChunkSize) {
            const size_t want = static_cast<size_t>(
                std::min<uint64_t>(kChunkSize, map.endAddress - cursor));
            const size_t got = mem->Read(cursor, buf.data(), want);
            if (got == 0) {
                continue;
            }

            const uint64_t first = AlignUp(cursor, alignment);
            for (uint64_t a = first; a + width <= cursor + got; a += alignment) {
                const size_t off = static_cast<size_t>(a - cursor);
                uint64_t iv = 0;
                double fv = 0.0;
                ReadAt(buf.data(), got, off, in.valueType, iv, fv);
                if (!Match(in, iv, fv)) {
                    continue;
                }
                addrs.push_back(a);
                if (in.scanMode == CE_SCAN_UNKNOWN) {
                    ints.push_back(iv);
                    floats.push_back(fv);
                }
                if (addrs.size() >= maxResults) {
                    truncated = true;
                    break;
                }
            }
            if (truncated) {
                break;
            }
        }
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        addresses_.swap(addrs);
        prevInt_.swap(ints);
        prevFloat_.swap(floats);
        active_ = true;
        pid_ = pid;
        valueType_ = in.valueType;
        alignment_ = alignment;
    }

    totalOut = addresses_.size();
    LOGDF("ScanEngine: first scan pid=%d type=%u mode=%u alignment=%u "
          "regionFilter=%u total=%llu%s",
          pid, in.valueType, in.scanMode, alignment, in.regionFilter,
          static_cast<unsigned long long>(totalOut),
          truncated ? " (truncated at maxResults)" : "");
    return true;
}

bool ScanEngine::NextScan(IMemoryOp* mem, const CeScanNextInput& in,
                          uint64_t& totalOut, int& errorCode) {
    totalOut = 0;
    errorCode = 0;

    std::lock_guard<std::mutex> lock(mutex_);
    if (!active_ || addresses_.empty()) {
        errorCode = ENOENT;
        return false;
    }
    if (!mem) {
        errorCode = EINVAL;
        return false;
    }
    const uint32_t width = ValueWidth(valueType_);
    if (width == 0) {
        errorCode = EINVAL;
        return false;
    }

    const bool hasPrev = prevInt_.size() == addresses_.size();
    const bool needPrev = (in.scanMode == CE_SCAN_UNCHANGED ||
                           in.scanMode == CE_SCAN_CHANGED ||
                           in.scanMode == CE_SCAN_INCREASED ||
                           in.scanMode == CE_SCAN_DECREASED);

    std::vector<uint64_t> keepAddrs;
    std::vector<uint64_t> keepInt;
    std::vector<double> keepFloat;
    keepAddrs.reserve(addresses_.size());
    keepInt.reserve(addresses_.size());
    keepFloat.reserve(addresses_.size());

    // 按页批量读：候选地址整体升序，同一页只读一次
    uint64_t curPage = ~0ull;
    std::vector<uint8_t> pageBuf(kPageBuf, 0);
    size_t pageValid = 0;

    for (size_t i = 0; i < addresses_.size(); ++i) {
        const uint64_t addr = addresses_[i];
        const uint64_t page = addr & ~static_cast<uint64_t>(kPageSize - 1);
        if (page != curPage) {
            curPage = page;
            pageValid = mem->Read(page, pageBuf.data(), kPageBuf);
        }

        const size_t off = static_cast<size_t>(addr - page);
        if (pageValid == 0 || off + width > pageValid) {
            continue;   // 该页不可读或跨页，直接丢弃
        }

        uint64_t iv = 0;
        double fv = 0.0;
        ReadAt(pageBuf.data(), pageValid, off, valueType_, iv, fv);

        const uint64_t piv = hasPrev ? prevInt_[i] : 0;
        const double pfv = hasPrev ? prevFloat_[i] : 0.0;

        if (needPrev && !hasPrev) {
            continue;   // 无前值可用，变化类模式无法判定
        }
        if (!MatchNext(in.scanMode, iv, fv, piv, pfv, in.intValue, in.floatValue)) {
            continue;
        }

        keepAddrs.push_back(addr);
        keepInt.push_back(iv);
        keepFloat.push_back(fv);
    }

    addresses_.swap(keepAddrs);
    prevInt_.swap(keepInt);
    prevFloat_.swap(keepFloat);
    totalOut = addresses_.size();

    LOGDF("ScanEngine: next scan mode=%u left=%llu",
          in.scanMode, static_cast<unsigned long long>(totalOut));
    return true;
}

uint32_t ScanEngine::Results(const CeScanResultsInput& in,
                             std::vector<CeScanResultEntry>& out) const {
    std::lock_guard<std::mutex> lock(mutex_);
    out.clear();
    if (addresses_.empty()) {
        return 0;
    }

    const uint64_t offset = std::min<uint64_t>(in.offset, addresses_.size());
    const uint64_t remain = addresses_.size() - offset;
    const uint64_t count = std::min<uint64_t>(in.count ? in.count : remain, remain);

    out.reserve(static_cast<size_t>(count));
    const bool hasPrev = prevInt_.size() == addresses_.size();
    for (uint64_t i = 0; i < count; ++i) {
        const size_t index = static_cast<size_t>(offset + i);
        CeScanResultEntry entry{};
        entry.address = addresses_[index];
        if (hasPrev) {
            entry.intValue = prevInt_[index];
            entry.floatValue = prevFloat_[index];
        }
        out.push_back(entry);
    }
    return static_cast<uint32_t>(out.size());
}

void ScanEngine::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    addresses_.clear();
    prevInt_.clear();
    prevFloat_.clear();
    addresses_.shrink_to_fit();
    prevInt_.shrink_to_fit();
    prevFloat_.shrink_to_fit();
    active_ = false;
    pid_ = 0;
}

uint64_t ScanEngine::Total() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return addresses_.size();
}

bool ScanEngine::Active() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return active_;
}

pid_t ScanEngine::SessionPid() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pid_;
}

uint32_t ScanEngine::SessionValueType() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return valueType_;
}