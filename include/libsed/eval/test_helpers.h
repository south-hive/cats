#pragma once

/// @file test_helpers.h
/// @brief TC 작성에 공통으로 사용되는 인라인 헬퍼 함수.
///
/// 이전에 20+ 예제 파일에 복사-붙여넣기로 중복되던 step(), printHex(),
/// sscName(), printFeatureDescriptors() 등의 함수를 한 곳에 정의합니다.

#include "libsed/eval/eval_api.h"  // pulls in types.h, discovery.h, feature_descriptor.h
#include <cstdio>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <string>

namespace libsed {
namespace eval {

/// @brief 번호가 매겨진 단계 결과 출력 (appnote 스타일)
inline void step(int n, const std::string& name, Result r) {
    std::cout << "  [Step " << n << "] " << name << ": "
              << (r.ok() ? "OK" : "FAIL");
    if (r.failed()) std::cout << " (" << r.message() << ")";
    std::cout << "\n";
}

/// @brief 라벨이 붙은 단계 결과 출력 (eval 데모 스타일)
inline void step(const std::string& name, Result r) {
    std::cout << "  [" << name << "] "
              << (r.ok() ? "OK" : "FAIL");
    if (r.failed()) std::cout << " - " << r.message();
    std::cout << "\n";
}

/// @brief 라벨 + 바이트 배열 16진수 덤프 (2-space indent)
inline void printHex(const std::string& label, const Bytes& data, size_t max = 32) {
    std::cout << "    " << label << " (" << data.size() << " bytes): ";
    for (size_t i = 0; i < data.size() && i < max; i++)
        printf("%02X ", data[i]);
    if (data.size() > max) std::cout << "...";
    std::cout << "\n";
}

/// @brief 바이트 배열 16진수 덤프 (라벨 없이, 인라인)
inline void printHex(const Bytes& data, size_t max = 32) {
    for (size_t i = 0; i < data.size() && i < max; i++)
        printf("%02X", data[i]);
    if (data.size() > max) printf("..(%zu bytes)", data.size());
}

/// @brief SSC 타입을 문자열로 변환
inline const char* sscName(SscType ssc) {
    switch (ssc) {
        case SscType::Opal20:     return "Opal 2.0";
        case SscType::Opal10:     return "Opal 1.0";
        case SscType::Enterprise: return "Enterprise";
        case SscType::Pyrite10:   return "Pyrite 1.0";
        case SscType::Pyrite20:   return "Pyrite 2.0";
        default:                  return "Unknown";
    }
}

/// @brief Feature Descriptor 상세 출력 (sedutil --query 스타일)
inline void printFeatureDescriptors(const Discovery& disc) {
    for (const auto& feat : disc.features()) {
        uint16_t code = feat->featureCode();
        printf("    Feature: %s (0x%04X)\n", feat->name().c_str(), code);

        if (auto* f = dynamic_cast<const TPerFeature*>(feat.get())) {
            printf("      Sync=%s Async=%s AckNak=%s BufferMgmt=%s Streaming=%s ComIDMgmt=%s\n",
                   f->syncSupported ? "Y" : "N",
                   f->asyncSupported ? "Y" : "N",
                   f->ackNakSupported ? "Y" : "N",
                   f->bufferMgmtSupported ? "Y" : "N",
                   f->streamingSupported ? "Y" : "N",
                   f->comIdMgmtSupported ? "Y" : "N");
        }
        else if (auto* f = dynamic_cast<const LockingFeature*>(feat.get())) {
            printf("      LockingSupported=%s LockingEnabled=%s Locked=%s MediaEncrypt=%s MBREnabled=%s MBRDone=%s\n",
                   f->lockingSupported ? "Y" : "N",
                   f->lockingEnabled ? "Y" : "N",
                   f->locked ? "Y" : "N",
                   f->mediaEncryption ? "Y" : "N",
                   f->mbrEnabled ? "Y" : "N",
                   f->mbrDone ? "Y" : "N");
        }
        else if (auto* f = dynamic_cast<const GeometryFeature*>(feat.get())) {
            printf("      Align=%s LogicalBlockSize=%u AlignmentGranularity=%llu LowestAlignedLBA=%llu\n",
                   f->align ? "Y" : "N",
                   f->logicalBlockSize,
                   static_cast<unsigned long long>(f->alignmentGranularity),
                   static_cast<unsigned long long>(f->lowestAlignedLBA));
        }
        else if (auto* f = dynamic_cast<const OpalV2Feature*>(feat.get())) {
            printf("      BaseComID=0x%04X NumComIDs=%u RangeCrossing=%s\n",
                   f->baseComId, f->numComIds, f->rangeCrossing ? "Y" : "N");
            printf("      Admins=%u Users=%u InitialPIN=%u RevertedPIN=%u\n",
                   f->numLockingSPAdminsSupported, f->numLockingSPUsersSupported,
                   f->initialPinIndicator, f->revertedPinIndicator);
        }
        else if (auto* f = dynamic_cast<const OpalV1Feature*>(feat.get())) {
            printf("      BaseComID=0x%04X NumComIDs=%u RangeCrossing=%s\n",
                   f->baseComId, f->numComIds, f->rangeCrossing ? "Y" : "N");
        }
        else if (auto* f = dynamic_cast<const EnterpriseFeature*>(feat.get())) {
            printf("      BaseComID=0x%04X NumComIDs=%u RangeCrossing=%s\n",
                   f->baseComId, f->numComIds, f->rangeCrossing ? "Y" : "N");
        }
        else if (auto* f = dynamic_cast<const PyriteV1Feature*>(feat.get())) {
            printf("      BaseComID=0x%04X NumComIDs=%u InitialPIN=%u RevertedPIN=%u\n",
                   f->baseComId, f->numComIds, f->initialPinIndicator, f->revertedPinIndicator);
        }
        else if (auto* f = dynamic_cast<const PyriteV2Feature*>(feat.get())) {
            printf("      BaseComID=0x%04X NumComIDs=%u InitialPIN=%u RevertedPIN=%u\n",
                   f->baseComId, f->numComIds, f->initialPinIndicator, f->revertedPinIndicator);
        }
    }
}

} // namespace eval
} // namespace libsed
