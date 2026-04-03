#pragma once

/// @file command_logger.h
/// @brief IF-SEND/IF-RECV 명령 이력을 파일에 기록하는 로거.
///
/// 레거시 SED 라이브러리의 명령 로그 형식을 재현한다.
/// 각 명령에 대해 Command Info, TCG Head, TCG Payload (토큰 디코딩),
/// Raw Payload (헥스 덤프)를 기록한다.
///
/// 사용 예:
/// @code
///   auto logger = std::make_shared<debug::CommandLogger>("/tmp/logs");
///   auto transport = debug::LoggingTransport::wrap(nvmeTransport, logger);
///   // 이후 모든 IF-SEND/IF-RECV가 자동으로 파일에 기록됨
/// @endcode

#include "../core/types.h"
#include "../core/error.h"
#include <cstdint>
#include <string>
#include <fstream>
#include <mutex>
#include <atomic>
#include <sstream>

namespace libsed {
namespace debug {

/// @brief IF-SEND/IF-RECV 명령을 파일에 기록하는 로거
///
/// 스레드 안전하며, 여러 세션(ComID)에서 동시 사용 가능하다.
/// 로그 파일 이름은 실행 파일명 + 타임스탬프로 자동 생성된다.
class CommandLogger {
public:
    /// @brief 자동 파일명으로 로거를 생성 (디렉토리 지정)
    /// @param logDir 로그 파일을 저장할 디렉토리 (기본값: ".")
    explicit CommandLogger(const std::string& logDir = ".");

    /// @brief 지정된 파일 경로로 로거를 생성
    /// @param filePath 로그 파일의 전체 경로
    /// @param explicit_path 오버로드 구분용 태그 (값 무시)
    CommandLogger(const std::string& filePath, bool explicit_path);

    ~CommandLogger();

    // non-copyable, non-movable
    CommandLogger(const CommandLogger&) = delete;
    CommandLogger& operator=(const CommandLogger&) = delete;

    /// @brief IF-SEND 명령을 기록
    /// @param protocolId 보안 프로토콜 번호 (SP)
    /// @param comId      ComID (SPS)
    /// @param payload    전송 데이터
    void logIfSend(uint8_t protocolId, uint16_t comId, ByteSpan payload);

    /// @brief IF-RECV 명령을 기록
    /// @param protocolId    보안 프로토콜 번호
    /// @param comId         ComID
    /// @param data          수신 데이터
    /// @param bytesReceived 실제 수신된 바이트 수
    void logIfRecv(uint8_t protocolId, uint16_t comId,
                   const uint8_t* data, size_t bytesReceived);

    /// @brief 로그 파일 경로 반환
    std::string filePath() const;

    /// @brief 기록된 명령 수 반환
    uint32_t commandCount() const { return cmdCount_.load(); }

    /// @brief 로거가 활성 상태인지 확인
    bool isOpen() const;

    /// @brief 로그 파일을 닫고 플러시
    void close();

private:
    /// @brief 하나의 명령 항목을 포맷하여 파일에 기록
    void logCommand(const char* direction,
                    uint8_t protocolId, uint16_t comId,
                    const uint8_t* data, size_t len);

    /// @brief Command Info 섹션 작성
    static void writeCommandInfo(std::ostream& os,
                                 uint8_t protocolId, uint16_t comId, size_t len);

    /// @brief TCG Head 섹션 작성 (ComPacket/Packet/SubPacket 헤더 파싱)
    static void writeTcgHead(std::ostream& os,
                             const uint8_t* data, size_t len);

    /// @brief TCG Payload 섹션 작성 (토큰 디코딩 + UID 해석)
    static void writeTcgPayload(std::ostream& os,
                                const uint8_t* data, size_t len);

    /// @brief Raw Payload 섹션 작성 (16바이트/줄 헥스 덤프)
    static void writeRawPayload(std::ostream& os,
                                const uint8_t* data, size_t len);

    /// @brief 현재 실행 파일의 basename 획득
    static std::string getExecutableName();

    /// @brief 현재 시간 타임스탬프 문자열 (YYYYMMDD_HHMMSS)
    static std::string getTimestamp();

    /// @brief UID 값을 사람이 읽을 수 있는 이름으로 변환
    /// @return 매칭되는 이름 문자열, 없으면 nullptr
    static const char* resolveUid(uint64_t uid);

    /// @brief Method UID를 사람이 읽을 수 있는 이름으로 변환
    /// @return 매칭되는 이름 문자열, 없으면 nullptr
    static const char* resolveMethodUid(uint64_t uid);

    /// @brief 8바이트 byte-sequence를 uint64_t (big-endian)로 변환
    static uint64_t bytesToUid(const uint8_t* data, size_t len);

    mutable std::mutex    mutex_;
    std::ofstream         file_;
    std::string           filePath_;
    std::atomic<uint32_t> cmdCount_{0};
};

} // namespace debug
} // namespace libsed
