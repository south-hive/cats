#pragma once

/// @file logging_transport.h
/// @brief ITransport 데코레이터 — 모든 IF-SEND/IF-RECV를 CommandLogger에 기록.
///
/// 기존 ITransport 구현체를 래핑하여 모든 ifSend/ifRecv 호출을
/// CommandLogger를 통해 파일에 기록한다.
/// 전송 기능 자체는 래핑된 transport에 위임한다.
///
/// 사용 예:
/// @code
///   auto nvme = TransportFactory::createNvme("/dev/nvme0");
///   auto logged = debug::LoggingTransport::wrap(nvme, "/tmp/logs");
///   // 이후 logged를 transport로 사용하면 모든 명령이 기록됨
/// @endcode

#include "../transport/i_transport.h"
#include "command_logger.h"
#include <memory>

namespace libsed {
namespace debug {

/// @brief 모든 전송 연산을 로깅하는 ITransport 데코레이터
class LoggingTransport : public ITransport {
public:
    /// @brief 기존 transport를 래핑하는 LoggingTransport를 생성
    /// @param inner  래핑할 ITransport 구현체
    /// @param logger 공유 CommandLogger (여러 세션 간 공유 가능)
    LoggingTransport(std::shared_ptr<ITransport> inner,
                     std::shared_ptr<CommandLogger> logger);

    /// @brief 편의 팩토리: transport를 래핑하고 자동 이름 로그 파일 생성
    /// @param inner  래핑할 ITransport
    /// @param logDir 로그 디렉토리 (기본값: ".")
    /// @return LoggingTransport를 가리키는 shared_ptr<ITransport>
    static std::shared_ptr<ITransport> wrap(
        std::shared_ptr<ITransport> inner,
        const std::string& logDir = ".");

    /// @brief --dump 모드: transport를 래핑하고 decoded 출력을 stream에 출력
    /// @param inner     래핑할 ITransport
    /// @param os        출력 스트림 (기본값: stderr)
    /// @param verbosity 1=decoded only (--dump), 2=decoded+raw hex (--dump2)
    static std::shared_ptr<ITransport> wrapDump(
        std::shared_ptr<ITransport> inner,
        std::ostream& os = std::cerr,
        int verbosity = 1);

    // ── ITransport interface ────────────────────────────

    Result ifSend(uint8_t protocolId, uint16_t comId,
                  ByteSpan payload) override;

    Result ifRecv(uint8_t protocolId, uint16_t comId,
                  MutableByteSpan buffer,
                  size_t& bytesReceived) override;

    TransportType type() const override;
    std::string devicePath() const override;
    bool isOpen() const override;
    void close() override;

    /// @brief 내부 CommandLogger 접근자
    std::shared_ptr<CommandLogger> logger() const { return logger_; }

    /// @brief 내부 transport 접근자
    std::shared_ptr<ITransport> inner() const { return inner_; }

private:
    std::shared_ptr<ITransport>    inner_;
    std::shared_ptr<CommandLogger> logger_;
};

} // namespace debug
} // namespace libsed
