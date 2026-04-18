#pragma once

#include "../core/types.h"
#include <cstdint>
#include <string>

namespace libsed {

/// @brief Level 0 Feature Descriptor 기본 클래스
class FeatureDescriptor {
public:
    virtual ~FeatureDescriptor() = default;

    /// @brief Feature Code 반환
    uint16_t featureCode() const { return featureCode_; }
    /// @brief Feature Descriptor 버전 반환
    uint8_t  version() const { return version_; }
    /// @brief Feature 데이터 길이 반환 (바이트 단위)
    uint16_t dataLength() const { return dataLength_; }

    /// @brief Feature 이름 문자열 반환 (하위 클래스에서 구현)
    virtual std::string name() const = 0;
    /// @brief 원시 바이트 데이터로부터 Feature 파싱 (하위 클래스에서 구현)
    /// @param data 원시 데이터 포인터
    /// @param len 데이터 길이
    virtual void parse(const uint8_t* data, size_t len) = 0;

protected:
    uint16_t featureCode_ = 0;
    uint8_t  version_ = 0;
    uint16_t dataLength_ = 0;

    /// @brief Feature 헤더 공통 파싱 (Feature Code, 버전, 데이터 길이)
    /// @param data 원시 데이터 포인터 (최소 4바이트)
    void parseHeader(const uint8_t* data) {
        featureCode_ = (static_cast<uint16_t>(data[0]) << 8) | data[1];
        version_ = (data[2] >> 4) & 0x0F;
        dataLength_ = static_cast<uint16_t>(data[3]);
    }
};

/// @brief TPer Feature (0x0001)
/// TPer의 기본 통신 능력을 나타냄
class TPerFeature : public FeatureDescriptor {
public:
    std::string name() const override { return "TPer"; }
    void parse(const uint8_t* data, size_t len) override;

    /// @brief 동기 프로토콜 지원 여부
    bool syncSupported = false;
    /// @brief 비동기 프로토콜 지원 여부
    bool asyncSupported = false;
    /// @brief ACK/NAK 프로토콜 지원 여부
    bool ackNakSupported = false;
    /// @brief 버퍼 관리 프로토콜 지원 여부
    bool bufferMgmtSupported = false;
    /// @brief 스트리밍 프로토콜 지원 여부
    bool streamingSupported = false;
    /// @brief ComID 관리 프로토콜 지원 여부
    bool comIdMgmtSupported = false;
};

/// @brief Locking Feature (0x0002)
/// 드라이브의 잠금 기능 상태를 나타냄
class LockingFeature : public FeatureDescriptor {
public:
    std::string name() const override { return "Locking"; }
    void parse(const uint8_t* data, size_t len) override;

    /// @brief 잠금 기능 지원 여부
    bool lockingSupported = false;
    /// @brief 잠금 기능 활성화 여부
    bool lockingEnabled = false;
    /// @brief 현재 잠금 상태 여부
    bool locked = false;
    /// @brief 미디어 암호화 지원 여부
    bool mediaEncryption = false;
    /// @brief MBR 섀도잉 지원 여부
    bool mbrSupported = false;
    /// @brief MBR 섀도잉 활성화 여부
    bool mbrEnabled = false;
    /// @brief MBR 섀도잉 완료 여부
    bool mbrDone = false;
};

/// @brief Geometry Reporting Feature (0x0003)
/// 드라이브의 물리적 배치 정보
class GeometryFeature : public FeatureDescriptor {
public:
    std::string name() const override { return "Geometry"; }
    void parse(const uint8_t* data, size_t len) override;

    /// @brief 정렬 필요 여부
    bool align = false;
    /// @brief 논리 블록 크기 (바이트)
    uint32_t logicalBlockSize = 512;
    /// @brief 정렬 단위 크기 (논리 블록 수)
    uint64_t alignmentGranularity = 0;
    /// @brief 최소 정렬 LBA
    uint64_t lowestAlignedLBA = 0;
};

/// @brief Opal SSC v1.0 Feature (0x0200)
class OpalV1Feature : public FeatureDescriptor {
public:
    std::string name() const override { return "Opal v1.0"; }
    void parse(const uint8_t* data, size_t len) override;

    /// @brief 기본 ComID
    uint16_t baseComId = 0;
    /// @brief 할당된 ComID 수
    uint16_t numComIds = 0;
    /// @brief Range Crossing 허용 여부
    bool rangeCrossing = false;
};

/// @brief Opal SSC v2.0 Feature (0x0203)
class OpalV2Feature : public FeatureDescriptor {
public:
    std::string name() const override { return "Opal v2.0"; }
    void parse(const uint8_t* data, size_t len) override;

    /// @brief 기본 ComID
    uint16_t baseComId = 0;
    /// @brief 할당된 ComID 수
    uint16_t numComIds = 0;
    /// @brief Range Crossing 허용 여부
    bool rangeCrossing = false;
    /// @brief Locking SP가 지원하는 관리자 수
    uint16_t numLockingSPAdminsSupported = 0;
    /// @brief Locking SP가 지원하는 사용자 수
    uint16_t numLockingSPUsersSupported = 0;
    /// @brief 초기 PIN 표시자 (C_PIN_MSID 행 참조 방식)
    uint8_t  initialPinIndicator = 0;
    /// @brief Revert 후 PIN 표시자
    uint8_t  revertedPinIndicator = 0;
};

/// @brief Enterprise SSC Feature (0x0100)
class EnterpriseFeature : public FeatureDescriptor {
public:
    std::string name() const override { return "Enterprise"; }
    void parse(const uint8_t* data, size_t len) override;

    /// @brief 기본 ComID
    uint16_t baseComId = 0;
    /// @brief 할당된 ComID 수
    uint16_t numComIds = 0;
    /// @brief Range Crossing 허용 여부
    bool rangeCrossing = false;
};

/// @brief Pyrite SSC v1.0 Feature (0x0302)
class PyriteV1Feature : public FeatureDescriptor {
public:
    std::string name() const override { return "Pyrite v1.0"; }
    void parse(const uint8_t* data, size_t len) override;

    /// @brief 기본 ComID
    uint16_t baseComId = 0;
    /// @brief 할당된 ComID 수
    uint16_t numComIds = 0;
    /// @brief 초기 PIN 표시자
    uint8_t  initialPinIndicator = 0;
    /// @brief Revert 후 PIN 표시자
    uint8_t  revertedPinIndicator = 0;
};

/// @brief Pyrite SSC v2.0 Feature (0x0303)
class PyriteV2Feature : public FeatureDescriptor {
public:
    std::string name() const override { return "Pyrite v2.0"; }
    void parse(const uint8_t* data, size_t len) override;

    /// @brief 기본 ComID
    uint16_t baseComId = 0;
    /// @brief 할당된 ComID 수
    uint16_t numComIds = 0;
    /// @brief 초기 PIN 표시자
    uint8_t  initialPinIndicator = 0;
    /// @brief Revert 후 PIN 표시자
    uint8_t  revertedPinIndicator = 0;
};

/// @brief 알 수 없는/범용 Feature Descriptor
class UnknownFeature : public FeatureDescriptor {
public:
    std::string name() const override { return "Unknown(0x" + std::to_string(featureCode_) + ")"; }
    void parse(const uint8_t* data, size_t len) override;

    /// @brief 파싱되지 않은 원시 데이터
    Bytes rawData;
};

/// Separate header files just re-export from here
// tper_feature.h, locking_feature.h, etc. can just #include "feature_descriptor.h"

} // namespace libsed
