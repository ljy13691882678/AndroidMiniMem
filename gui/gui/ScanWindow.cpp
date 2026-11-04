#include "ScanWindow.h"
#include "AppContext.h"
#include "Gui.h"
#include "../imgui/imgui.h"
#include "../mem/IMemService.h"

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {

const char* kValueTypeNames[] = {"byte", "word", "dword", "qword", "float", "double"};
const uint32_t kValueTypes[] = {1, 2, 4, 8, 100, 101};

const char* kFirstModeNames[] = {"精确", "大于", "小于", "未知初始值"};
const uint32_t kFirstModes[] = {0, 1, 2, 3};

const char* kNextModeNames[] = {"未变动", "已变动", "增加", "减少",
                                "精确", "大于", "小于", "未知"};
const uint32_t kNextModes[] = {4, 5, 6, 7, 0, 1, 2, 3};

const uint32_t kAlignments[] = {1, 2, 4, 8};

bool isFloatType(uint32_t type) {
    return type == 100 || type == 101;
}

uint64_t parseValue(const char* text, bool asFloat, bool& ok) {
    ok = false;
    if (!text || *text == '\0') {
        return 0;
    }
    char* end = nullptr;
    if (asFloat) {
        const double v = std::strtod(text, &end);
        ok = end && end != text;
        return static_cast<uint64_t>(v);
    }
    const unsigned long long v = std::strtoull(text, &end, 0);
    ok = end && end != text;
    return static_cast<uint64_t>(v);
}

} // namespace

ScanWindow::ScanWindow(Mem::IMemService& service)
    : service_(service) {
    name = "内存扫描";
}

unsigned int ScanWindow::getWindowFlags() const {
    return ImGuiWindowFlags_None;
}

void ScanWindow::onDraw() {
    // 未附加进程时仍然把面板画出来，只是整体禁用，
    // 这样用户能先看到扫描参数与地址分析区的布局。
    const bool attached = hasProcess();
    if (!attached) {
        ImGui::TextDisabled("未附加进程，请先在「主控」页选择目标进程（以下控件已禁用）");
        ImGui::BeginDisabled();
    }

    drawScanControls();
    ImGui::Separator();
    drawResultTable();
    ImGui::Separator();
    drawAddressAnalyzer();

    if (!attached) {
        ImGui::EndDisabled();
    }
}

void ScanWindow::drawScanControls() {
    ImGui::Text("目标: %s (PID %d)", currentProcessName().c_str(), currentPid());

    ImGui::SetNextItemWidth(120);
    ImGui::Combo("数据类型", &valueTypeIdx, kValueTypeNames,
                 IM_ARRAYSIZE(kValueTypeNames));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(80);
    ImGui::Combo("对齐", &alignmentIdx, "1\0""2\0""4\0""8\0");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(140);
    ImGui::Combo("区域", &regionIdx, "可写区域\0全部可读区域\0");

    ImGui::SetNextItemWidth(120);
    ImGui::Combo("首次模式", &firstModeIdx, kFirstModeNames,
                 IM_ARRAYSIZE(kFirstModeNames));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(160);
    ImGui::InputText("数值", valueBuf, sizeof(valueBuf));
    ImGui::SameLine();
    if (ImGui::Button("首次扫描")) {
        doFirstScan();
    }

    ImGui::SetNextItemWidth(120);
    ImGui::Combo("再次模式", &nextModeIdx, kNextModeNames,
                 IM_ARRAYSIZE(kNextModeNames));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(160);
    ImGui::InputText("新值", nextValueBuf, sizeof(nextValueBuf));
    ImGui::SameLine();
    if (ImGui::Button("再次扫描")) {
        doNextScan();
    }
    ImGui::SameLine();
    if (ImGui::Button("清空")) {
        doClear();
    }

    if (!scanStatus.empty()) {
        ImGui::TextWrapped("%s", scanStatus.c_str());
    }
}

void ScanWindow::drawResultTable() {
    if (!scanned) {
        ImGui::TextDisabled("尚无扫描结果");
        return;
    }

    ImGui::Text("候选结果: %" PRIu64 " 条", total);
    ImGui::SameLine();
    ImGui::TextDisabled("（分页显示，每页 %u 条）", pageSize);

    if (total > pageSize) {
        if (ImGui::Button("上一页") && pageOffset >= pageSize) {
            pageOffset -= pageSize;
            refreshResults();
        }
        ImGui::SameLine();
        if (ImGui::Button("下一页") && pageOffset + pageSize < total) {
            pageOffset += pageSize;
            refreshResults();
        }
        ImGui::SameLine();
        ImGui::Text("第 %u / %" PRIu64 " 页",
                    pageOffset / pageSize + 1,
                    (total + pageSize - 1) / pageSize);
        ImGui::SameLine();
    }
    if (ImGui::Button("刷新")) {
        refreshResults();
    }

    const ImGuiTableFlags flags = ImGuiTableFlags_Borders |
                                  ImGuiTableFlags_RowBg |
                                  ImGuiTableFlags_ScrollY |
                                  ImGuiTableFlags_SizingFixedFit;
    if (ImGui::BeginTable("scan_results", 3, flags, ImVec2(0, 260))) {
        ImGui::TableSetupColumn("地址", ImGuiTableColumnFlags_WidthFixed, 180);
        ImGui::TableSetupColumn("当前值", ImGuiTableColumnFlags_WidthFixed, 160);
        ImGui::TableSetupColumn("操作", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        const uint32_t type = kValueTypes[valueTypeIdx];
        for (const auto& item : results) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Text("0x%016" PRIX64, item.address);

            ImGui::TableSetColumnIndex(1);
            if (isFloatType(type)) {
                ImGui::Text("%.6f", item.floatValue);
            } else {
                ImGui::Text("%" PRIu64, item.intValue);
            }

            ImGui::TableSetColumnIndex(2);
            ImGui::PushID(static_cast<int>(item.address & 0x7FFFFFFF));
            if (ImGui::SmallButton("分析基址")) {
                std::snprintf(addrBuf, sizeof(addrBuf), "0x%" PRIX64, item.address);
                analyzeAddress(item.address);
            }
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
}

void ScanWindow::drawAddressAnalyzer() {
    ImGui::Text("地址分析（找模块基址 / 偏移）");
    ImGui::SetNextItemWidth(200);
    ImGui::InputText("地址", addrBuf, sizeof(addrBuf));
    ImGui::SameLine();
    if (ImGui::Button("分析")) {
        bool ok = false;
        const uint64_t address = parseValue(addrBuf, false, ok);
        if (ok && address != 0) {
            analyzeAddress(address);
        } else {
            Gui::log("地址格式无效");
        }
    }

    if (hasAddrInfo) {
        ImGui::Text("模块: %s", addrInfo.moduleName.empty() ? "(非模块区域)"
                                                          : addrInfo.moduleName.c_str());
        ImGui::Text("模块基址: 0x%016" PRIX64 "   大小: 0x%" PRIX64,
                    addrInfo.moduleBase, addrInfo.moduleSize);
        ImGui::Text("模块内偏移: 0x%" PRIX64, addrInfo.offset);
        ImGui::Text("所属区域: 0x%016" PRIX64 "  size=0x%" PRIX64 "  perms=%s",
                    addrInfo.regionBase, addrInfo.regionSize,
                    addrInfo.perms.c_str());
    }
}

void ScanWindow::doFirstScan() {
    const uint32_t type = kValueTypes[valueTypeIdx];
    const uint32_t mode = kFirstModes[firstModeIdx];
    const bool asFloat = isFloatType(type);

    Mem::ScanFirstRequest request;
    request.valueType = type;
    request.scanMode = mode;
    request.alignment = kAlignments[alignmentIdx];
    request.regionFilter = static_cast<uint32_t>(regionIdx);
    request.maxResults = 4000000;

    if (mode != 3) {
        bool ok = false;
        const uint64_t raw = parseValue(valueBuf, asFloat, ok);
        if (!ok) {
            Gui::log("首次扫描失败: 数值无效");
            return;
        }
        request.intValue = raw;
        request.floatValue = asFloat ? std::strtod(valueBuf, nullptr)
                                     : static_cast<double>(raw);
    }

    auto result = service_.scanFirst(service_.captureContext(true), request);
    if (!result.ok()) {
        Gui::log("首次扫描失败: %s", result.error().message.c_str());
        return;
    }

    total = result.value().total;
    pageOffset = 0;
    scanned = true;
    scanStatus = "首次扫描完成，候选 " + std::to_string(total) + " 条";
    Gui::log("首次扫描完成: %llu 条", static_cast<unsigned long long>(total));
    refreshResults();
}

void ScanWindow::doNextScan() {
    if (!scanned) {
        Gui::log("再次扫描失败: 请先执行首次扫描");
        return;
    }

    const uint32_t type = kValueTypes[valueTypeIdx];
    const uint32_t mode = kNextModes[nextModeIdx];
    const bool asFloat = isFloatType(type);

    Mem::ScanNextRequest request;
    request.scanMode = mode;

    const bool needsValue = (mode == 0 || mode == 1 || mode == 2);
    if (needsValue) {
        bool ok = false;
        const uint64_t raw = parseValue(nextValueBuf, asFloat, ok);
        if (!ok) {
            Gui::log("再次扫描失败: 新值无效");
            return;
        }
        request.intValue = raw;
        request.floatValue = asFloat ? std::strtod(nextValueBuf, nullptr)
                                     : static_cast<double>(raw);
    }

    auto result = service_.scanNext(service_.captureContext(true), request);
    if (!result.ok()) {
        Gui::log("再次扫描失败: %s", result.error().message.c_str());
        return;
    }

    total = result.value().total;
    pageOffset = 0;
    scanStatus = "再次扫描完成，剩余 " + std::to_string(total) + " 条";
    Gui::log("再次扫描完成: %llu 条", static_cast<unsigned long long>(total));
    refreshResults();
}

void ScanWindow::doClear() {
    auto result = service_.scanClear(service_.captureContext(false));
    if (!result.ok()) {
        Gui::log("清空扫描失败: %s", result.error().message.c_str());
        return;
    }
    total = 0;
    pageOffset = 0;
    results.clear();
    scanned = false;
    scanStatus = "已清空扫描会话";
}

void ScanWindow::refreshResults() {
    if (!scanned || total == 0) {
        results.clear();
        return;
    }

    Mem::ScanResultsRequest request;
    request.offset = pageOffset;
    request.count = pageSize;

    auto result = service_.scanResults(service_.captureContext(true), request);
    if (!result.ok()) {
        Gui::log("取扫描结果失败: %s", result.error().message.c_str());
        results.clear();
        return;
    }
    results = result.value().items;
}

void ScanWindow::analyzeAddress(uint64_t address) {
    Mem::AddressInfoRequest request;
    request.address = address;

    auto result = service_.addressInfo(service_.captureContext(true), request);
    if (!result.ok()) {
        hasAddrInfo = false;
        Gui::log("地址分析失败: %s", result.error().message.c_str());
        return;
    }
    addrInfo = result.value();
    hasAddrInfo = true;
    Gui::log("地址 0x%llX -> 模块=%s 基址=0x%llX 偏移=0x%llX",
             static_cast<unsigned long long>(address),
             addrInfo.moduleName.empty() ? "(none)" : addrInfo.moduleName.c_str(),
             static_cast<unsigned long long>(addrInfo.moduleBase),
             static_cast<unsigned long long>(addrInfo.offset));
}