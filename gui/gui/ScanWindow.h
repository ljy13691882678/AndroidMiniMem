#pragma once

#include "Window.h"
#include "../mem/MemTypes.h"

#include <cstdint>
#include <string>
#include <vector>

namespace Mem { class IMemService; }

// 内存扫描面板：数值搜索（精确/未知/变化）+ 地址反查基址。
class ScanWindow : public Window {
public:
    explicit ScanWindow(Mem::IMemService& service);

    void onDraw() override;
    unsigned int getWindowFlags() const override;

private:
    void drawScanControls();
    void drawResultTable();
    void drawAddressAnalyzer();

    void doFirstScan();
    void doNextScan();
    void doClear();
    void refreshResults();
    void analyzeAddress(uint64_t address);

    Mem::IMemService& service_;

    // 扫描参数
    int valueTypeIdx = 2;      // 0 byte,1 word,2 dword,3 qword,4 float,5 double
    int firstModeIdx = 0;      // 0 精确, 1 大于, 2 小于, 3 未知
    int nextModeIdx = 0;       // 0 未变,1 改变,2 增加,3 减少,4 精确,5 大于,6 小于,7 未知
    int alignmentIdx = 2;      // 1,2,4,8
    int regionIdx = 0;         // 0 可写区域, 1 全部可读区域
    char valueBuf[64] = "";
    char nextValueBuf[64] = "";

    // 结果
    uint64_t total = 0;
    uint32_t pageOffset = 0;
    uint32_t pageSize = 200;
    std::vector<Mem::ScanEntry> results;
    bool scanned = false;
    std::string scanStatus;

    // 地址分析
    char addrBuf[64] = "";
    Mem::AddressInfo addrInfo;
    bool hasAddrInfo = false;
};