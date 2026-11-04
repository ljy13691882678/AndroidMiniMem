#include "ScanCommands.h"

#include <algorithm>
#include <limits>

namespace {

constexpr uint32_t kMaxScanResultPage = 4096;

bool sendScanState(WindowsSocketClient* client, uint64_t& totalOut,
                   int32_t& errorCode) {
    int result = 0;
    int32_t err = 0;
    uint64_t total = 0;
    if (!client->Receive(&result, sizeof(result)) ||
        !client->Receive(&err, sizeof(err)) ||
        !client->Receive(&total, sizeof(total))) {
        return false;
    }
    errorCode = err;
    totalOut = total;
    return result == 1;
}

}  // namespace

bool ScanFirstRaw(const CeScanFirstInput& input,
                  uint32_t handle,
                  uint64_t& totalOut,
                  int32_t& errorCode,
                  PortType port) {
    totalOut = 0;
    errorCode = 0;
    return SocketCommand::execute(port, [&](WindowsSocketClient* client, int h) -> bool {
#pragma pack(1)
        struct {
            unsigned char command;
            uint32_t handle;
            CeScanFirstInput input;
        } op;
#pragma pack()
        op.command = CMD_SCAN_FIRST;
        op.handle = static_cast<uint32_t>(handle != 0 ? handle : h);
        op.input = input;
        if (!client->Send(&op, sizeof(op))) {
            return false;
        }
        return sendScanState(client, totalOut, errorCode);
    });
}

bool ScanNextRaw(const CeScanNextInput& input,
                 uint64_t& totalOut,
                 int32_t& errorCode,
                 PortType port) {
    totalOut = 0;
    errorCode = 0;
    return SocketCommand::execute(port, [&](WindowsSocketClient* client, int) -> bool {
#pragma pack(1)
        struct {
            unsigned char command;
            CeScanNextInput input;
        } op;
#pragma pack()
        op.command = CMD_SCAN_NEXT;
        op.input = input;
        if (!client->Send(&op, sizeof(op))) {
            return false;
        }
        return sendScanState(client, totalOut, errorCode);
    });
}

bool ScanResultsRaw(uint64_t offset,
                    uint32_t count,
                    std::vector<CeScanResultEntry>& out,
                    uint64_t& totalOut,
                    uint32_t& valueTypeOut,
                    PortType port) {
    out.clear();
    totalOut = 0;
    valueTypeOut = 0;
    const uint32_t wanted = std::min(count, kMaxScanResultPage);
    if (wanted == 0) {
        return false;
    }

    return SocketCommand::execute(port, [&](WindowsSocketClient* client, int) -> bool {
#pragma pack(1)
        struct {
            unsigned char command;
            CeScanResultsInput input;
        } op;
#pragma pack()
        op.command = CMD_SCAN_RESULTS;
        op.input.offset = offset;
        op.input.count = wanted;
        op.input.reserved = 0;
        if (!client->Send(&op, sizeof(op))) {
            return false;
        }

        uint32_t returned = 0;
        if (!client->Receive(&returned, sizeof(returned))) {
            return false;
        }
        if (!client->Receive(&totalOut, sizeof(totalOut))) {
            return false;
        }
        if (!client->Receive(&valueTypeOut, sizeof(valueTypeOut))) {
            return false;
        }
        if (returned > wanted) {
            return SocketCommand::rejectMalformedResponse(client);
        }

        out.resize(returned);
        for (uint32_t i = 0; i < returned; ++i) {
            if (!client->Receive(&out[i], sizeof(CeScanResultEntry))) {
                out.clear();
                return false;
            }
        }
        return true;
    });
}

bool ScanClearRaw(PortType port) {
    return SocketCommand::execute(port, [](WindowsSocketClient* client, int) -> bool {
        unsigned char command = CMD_SCAN_CLEAR;
        if (!client->Send(&command, sizeof(command))) {
            return false;
        }
        int result = 0;
        if (!client->Receive(&result, sizeof(result))) {
            return false;
        }
        return result == 1;
    });
}

bool AddressInfoRaw(uint64_t address,
                    uint32_t handle,
                    CeAddressInfoOutput& out,
                    PortType port) {
    out = {};
    return SocketCommand::execute(port, [&](WindowsSocketClient* client, int h) -> bool {
#pragma pack(1)
        struct {
            unsigned char command;
            uint32_t handle;
            CeAddressInfoInput input;
        } op;
#pragma pack()
        op.command = CMD_ADDRESS_INFO;
        op.handle = static_cast<uint32_t>(handle != 0 ? handle : h);
        op.input.address = address;
        if (!client->Send(&op, sizeof(op))) {
            return false;
        }
        int result = 0;
        if (!client->Receive(&result, sizeof(result))) {
            return false;
        }
        if (!client->Receive(&out, sizeof(out))) {
            return false;
        }
        return result == 1;
    });
}