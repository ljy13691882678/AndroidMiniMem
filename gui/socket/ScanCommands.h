#pragma once

#include <cstdint>
#include <vector>

#include "SocketCommand.h"

// 内存扫描 / 地址分析的设备线协议封装。
// engine 侧对应 CMD_SCAN_FIRST / CMD_SCAN_NEXT / CMD_SCAN_RESULTS /
// CMD_SCAN_CLEAR / CMD_ADDRESS_INFO。

bool ScanFirstRaw(const CeScanFirstInput& input,
                  uint32_t handle,
                  uint64_t& totalOut,
                  int32_t& errorCode,
                  PortType port = PORT_MAIN);

bool ScanNextRaw(const CeScanNextInput& input,
                 uint64_t& totalOut,
                 int32_t& errorCode,
                 PortType port = PORT_MAIN);

bool ScanResultsRaw(uint64_t offset,
                    uint32_t count,
                    std::vector<CeScanResultEntry>& out,
                    uint64_t& totalOut,
                    uint32_t& valueTypeOut,
                    PortType port = PORT_MAIN);

bool ScanClearRaw(PortType port = PORT_MAIN);

bool AddressInfoRaw(uint64_t address,
                    uint32_t handle,
                    CeAddressInfoOutput& out,
                    PortType port = PORT_MAIN);