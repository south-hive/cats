#pragma once

/// @file command_logger.h
/// @brief Compact IF-SEND/IF-RECV command logger for TC developers.
///
/// Produces human-readable, one-line-per-command logs:
///   #001 >> SMUID.Properties              P=01 C=0C01 TSN=0 HSN=0       2ms
///   #002 << SMUID.Properties  St=0(OK)    P=01 C=0C01 TSN=0 HSN=0       5ms
///       TPerProps: MaxComPkt=65536 MaxPkt=65516
///   #003 >> SMUID.StartSession            P=01 C=0C01 TSN=0 HSN=1       1ms
///       SP=AdminSP Write=1 Auth=SID Challenge=(32B)
///
/// Key params shown on indented line below. Raw hex only on error.
///
/// Usage:
/// @code
///   auto logger = std::make_shared<debug::CommandLogger>("/tmp/logs");
///   auto transport = debug::LoggingTransport::wrap(nvmeTransport, logger);
/// @endcode

#include "../core/types.h"
#include "../core/error.h"
#include "../codec/token.h"
#include <cstdint>
#include <string>
#include <fstream>
#include <mutex>
#include <atomic>
#include <sstream>
#include <chrono>

namespace libsed {

class TokenDecoder;

namespace debug {

class CommandLogger {
public:
    explicit CommandLogger(const std::string& logDir = ".");
    CommandLogger(const std::string& filePath, bool explicit_path);
    ~CommandLogger();

    CommandLogger(const CommandLogger&) = delete;
    CommandLogger& operator=(const CommandLogger&) = delete;

    void logIfSend(uint8_t protocolId, uint16_t comId, ByteSpan payload);
    void logIfRecv(uint8_t protocolId, uint16_t comId,
                   const uint8_t* data, size_t bytesReceived);

    std::string filePath() const;
    uint32_t commandCount() const { return cmdCount_.load(); }
    bool isOpen() const;
    void close();

private:
    void logCommand(const char* direction,
                    uint8_t protocolId, uint16_t comId,
                    const uint8_t* data, size_t len);

    // ── Format helpers ──
    static std::string formatMethod(const uint8_t* data, size_t len);
    static std::string formatStatus(const uint8_t* data, size_t len);
    static std::string formatParams(const uint8_t* data, size_t len);
    static std::string formatResult(const uint8_t* data, size_t len);
    static void writeRawHex(std::ostream& os, const uint8_t* data, size_t len);

    // ── UID resolution ──
    static const char* resolveUid(uint64_t uid);
    static const char* resolveMethodUid(uint64_t uid);
    static uint64_t bytesToUid(const uint8_t* data, size_t len);
    static std::string formatAtomValue(const Token& tok);
    static const char* methodStatusName(uint64_t status);

    // ── File name ──
    static std::string getExecutableName();
    static std::string getTimestamp();

    mutable std::mutex    mutex_;
    std::ofstream         file_;
    std::string           filePath_;
    std::atomic<uint32_t> cmdCount_{0};

    // Elapsed time tracking: send timestamp saved, recv calculates delta
    std::chrono::steady_clock::time_point lastSendTime_;
};

} // namespace debug
} // namespace libsed
