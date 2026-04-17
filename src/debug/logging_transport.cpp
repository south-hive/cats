/// @file logging_transport.cpp
/// @brief LoggingTransport 구현 — ITransport 데코레이터.

#include <libsed/debug/logging_transport.h>

namespace libsed {
namespace debug {

LoggingTransport::LoggingTransport(std::shared_ptr<ITransport> inner,
                                   std::shared_ptr<CommandLogger> logger)
    : inner_(std::move(inner))
    , logger_(std::move(logger))
{
}

std::shared_ptr<ITransport> LoggingTransport::wrap(
    std::shared_ptr<ITransport> inner,
    const std::string& logDir)
{
    auto logger = std::make_shared<CommandLogger>(logDir);
    return std::make_shared<LoggingTransport>(std::move(inner), std::move(logger));
}

std::shared_ptr<ITransport> LoggingTransport::wrapToFile(
    std::shared_ptr<ITransport> inner,
    const std::string& filePath)
{
    // Second ctor arg (bool explicit_path) is unused by CommandLogger; its
    // presence selects the explicit-path overload.
    auto logger = std::make_shared<CommandLogger>(filePath, true);
    return std::make_shared<LoggingTransport>(std::move(inner), std::move(logger));
}

std::shared_ptr<ITransport> LoggingTransport::wrapDump(
    std::shared_ptr<ITransport> inner,
    std::ostream& os,
    int verbosity)
{
    auto logger = CommandLogger::createDumper(os, verbosity);
    return std::make_shared<LoggingTransport>(std::move(inner), std::move(logger));
}

Result LoggingTransport::ifSend(uint8_t protocolId, uint16_t comId,
                                ByteSpan payload)
{
    // 전송 전에 페이로드를 기록 (전송 실패해도 기록 보존)
    if (logger_) {
        logger_->logIfSend(protocolId, comId, payload);
    }
    return inner_->ifSend(protocolId, comId, payload);
}

Result LoggingTransport::ifRecv(uint8_t protocolId, uint16_t comId,
                                MutableByteSpan buffer,
                                size_t& bytesReceived)
{
    auto r = inner_->ifRecv(protocolId, comId, buffer, bytesReceived);

    // 수신 후에 실제 데이터를 기록 (빈 응답은 스킵)
    if (logger_ && bytesReceived > 0) {
        logger_->logIfRecv(protocolId, comId, buffer.data(), bytesReceived);
    }
    return r;
}

TransportType LoggingTransport::type() const {
    return inner_->type();
}

std::string LoggingTransport::devicePath() const {
    return inner_->devicePath();
}

bool LoggingTransport::isOpen() const {
    return inner_->isOpen();
}

void LoggingTransport::close() {
    inner_->close();
    if (logger_) {
        logger_->close();
    }
}

} // namespace debug
} // namespace libsed
