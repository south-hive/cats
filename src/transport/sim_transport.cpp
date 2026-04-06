/// @file sim_transport.cpp
/// @brief 소프트웨어 SED 시뮬레이터 구현

#include "libsed/transport/sim_transport.h"
#include "libsed/core/log.h"
#include <algorithm>
#include <random>
#include <chrono>
#include <cstring>

namespace libsed {

using namespace uid;

// ═══════════════════════════════════════════════════════
//  생성자 / 초기화
// ═══════════════════════════════════════════════════════

SimTransport::SimTransport() : SimTransport(SimConfig{}) {}

SimTransport::SimTransport(const SimConfig& config) : config_(config) {
    factoryReset();
}

void SimTransport::factoryReset() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    // MSID 생성 (공장 기본)
    if (config_.msid.empty()) {
        msid_.resize(20);
        std::mt19937 rng(42);  // 재현 가능한 시드
        for (auto& b : msid_) b = static_cast<uint8_t>(rng() & 0xFF);
    } else {
        msid_ = config_.msid;
    }

    // SP 상태
    adminSpLifecycle_ = SpLifecycle::Manufactured;
    lockingSpLifecycle_ = SpLifecycle::ManufacturedInactive;

    // 세션 초기화
    nextTsn_ = 1;
    sessions_.clear();

    // C_PIN 초기화 — 공장 상태에서 SID == MSID
    cpins_.clear();
    cpins_[CPIN_MSID] = {true, msid_, 0};  // MSID: 항상 활성, 무제한 시도
    cpins_[CPIN_SID]  = {true, msid_, 0};  // SID: 초기값 = MSID
    cpins_[CPIN_ADMIN1] = {true, msid_, config_.pinTryLimit};
    for (uint32_t i = 1; i <= config_.maxUsers; ++i) {
        cpins_[makeCpinUserUid(i).toUint64()] = {false, {}, config_.pinTryLimit};
    }

    // Authority 초기화
    authorities_.clear();
    authorities_[AUTH_SID] = true;
    authorities_[AUTH_MSID] = true;
    authorities_[AUTH_PSID] = true;
    authorities_[AUTH_ADMIN1] = true;
    for (uint32_t i = 1; i <= config_.maxUsers; ++i) {
        authorities_[makeUserUid(i).toUint64()] = false;
    }

    // Locking Range 초기화
    ranges_.clear();
    for (uint32_t i = 0; i <= config_.maxRanges; ++i) {
        ranges_[i] = {};
    }

    // MBR
    mbrEnabled_ = false;
    mbrDone_ = false;
    mbrData_.assign(config_.mbrSize, 0);

    // DataStore
    dataStore_.assign(config_.dataStoreSize, 0);

    // ComID
    comIdState_ = ComIdState::Idle;
    pendingResponse_.clear();
    responseReady_ = false;

    keyCounter_ = 0x1000;
}

// ═══════════════════════════════════════════════════════
//  ITransport 구현
// ═══════════════════════════════════════════════════════

Result SimTransport::ifSend(uint8_t protocolId, uint16_t comId, ByteSpan payload) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    if (protocolId == 0x01) {
        // Discovery는 ifRecv만 사용
        handleSessionProtocol(comId, payload);
    } else if (protocolId == 0x02) {
        handleComIdManagement(comId, payload);
    }

    return ErrorCode::Success;
}

Result SimTransport::ifRecv(uint8_t protocolId, uint16_t comId,
                             MutableByteSpan buffer, size_t& bytesReceived) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    if (protocolId == 0x01 && !responseReady_) {
        // Discovery: ifRecv 직접 호출 (ifSend 없이)
        auto disc = buildDiscoveryResponse();
        size_t copyLen = std::min(disc.size(), buffer.size());
        std::memcpy(buffer.data(), disc.data(), copyLen);
        bytesReceived = copyLen;
        return ErrorCode::Success;
    }

    if (!responseReady_) {
        bytesReceived = 0;
        return ErrorCode::Success;
    }

    size_t copyLen = std::min(pendingResponse_.size(), buffer.size());
    std::memcpy(buffer.data(), pendingResponse_.data(), copyLen);
    bytesReceived = copyLen;

    pendingResponse_.clear();
    responseReady_ = false;

    return ErrorCode::Success;
}

// ═══════════════════════════════════════════════════════
//  Protocol Handlers
// ═══════════════════════════════════════════════════════

void SimTransport::handleSessionProtocol(uint16_t comId, ByteSpan payload) {
    // ComPacket 파싱
    if (payload.size() < 56) return;  // 20 ComPkt + 24 Pkt + 12 SubPkt

    // 패킷 헤더에서 TSN/HSN 읽기
    uint32_t tsn = Endian::readBe32(payload.data() + 20);
    uint32_t hsn = Endian::readBe32(payload.data() + 24);

    // SubPacket 길이
    uint32_t subPktLen = Endian::readBe32(payload.data() + 52);
    if (56 + subPktLen > payload.size()) return;

    // 토큰 디코딩
    TokenDecoder decoder;
    decoder.decode(payload.data() + 56, subPktLen);
    auto& tokens = decoder.tokens();
    if (tokens.empty()) return;

    if (tsn == 0 && hsn == 0) {
        // Session Manager 메서드
        auto response = handleSmMethod(comId, tokens);
        pendingResponse_ = response;
        responseReady_ = true;
    } else {
        // In-session 메서드
        auto response = handleSessionMethod(comId, tsn, hsn, tokens);
        pendingResponse_ = response;
        responseReady_ = true;
    }
}

void SimTransport::handleComIdManagement(uint16_t comId, ByteSpan payload) {
    // StackReset 또는 VerifyComId
    if (payload.size() < 8) return;

    uint32_t requestCode = Endian::readBe32(payload.data() + 4);

    if (requestCode == 0x00000002) {
        // STACK_RESET
        // 모든 세션 종료
        sessions_.clear();
        comIdState_ = ComIdState::Idle;
    }

    // 응답: ComID + requestCode + available + state
    Bytes response(2048, 0);
    Endian::writeBe16(response.data(), comId);
    Endian::writeBe32(response.data() + 4, requestCode);
    Endian::writeBe32(response.data() + 8, 0);  // availableDataLen
    uint32_t state = (comIdState_ == ComIdState::Idle) ? 0 : 1;
    Endian::writeBe32(response.data() + 12, state);

    pendingResponse_ = response;
    responseReady_ = true;
}

// ═══════════════════════════════════════════════════════
//  Discovery
// ═══════════════════════════════════════════════════════

Bytes SimTransport::buildDiscoveryResponse() {
    Bytes resp(512, 0);

    // Header (48 bytes)
    size_t offset = 48;

    // TPer feature (0x0001)
    Endian::writeBe16(resp.data() + offset, 0x0001);
    resp[offset + 2] = 0x10;  // version 1
    resp[offset + 3] = 16;
    resp[offset + 4] = 0x01;  // sync supported
    offset += 20;

    // Locking feature (0x0002)
    Endian::writeBe16(resp.data() + offset, 0x0002);
    resp[offset + 2] = 0x10;
    resp[offset + 3] = 16;
    uint8_t lockingFlags = 0x01;  // supported
    if (lockingSpLifecycle_ == SpLifecycle::Manufactured) {
        lockingFlags |= 0x02;  // enabled
        // Check if any range is locked
        for (auto& [id, r] : ranges_) {
            if (r.readLocked || r.writeLocked) { lockingFlags |= 0x04; break; }
        }
    }
    if (mbrEnabled_) lockingFlags |= 0x10;
    if (mbrDone_) lockingFlags |= 0x20;
    resp[offset + 4] = lockingFlags;
    offset += 20;

    // SSC feature
    uint16_t featureCode = 0x0203;
    switch (config_.sscType) {
        case SscType::Enterprise: featureCode = 0x0100; break;
        case SscType::Pyrite10:   featureCode = 0x0302; break;
        case SscType::Pyrite20:   featureCode = 0x0303; break;
        default: break;
    }
    Endian::writeBe16(resp.data() + offset, featureCode);
    resp[offset + 2] = 0x10;
    resp[offset + 3] = 16;
    Endian::writeBe16(resp.data() + offset + 4, config_.baseComId);
    Endian::writeBe16(resp.data() + offset + 6, config_.numComIds);
    offset += 20;

    // Total length (offset 0-3)
    Endian::writeBe32(resp.data(), static_cast<uint32_t>(offset - 4));

    return resp;
}

// ═══════════════════════════════════════════════════════
//  SM Method Handler
// ═══════════════════════════════════════════════════════

Bytes SimTransport::handleSmMethod(uint16_t comId, const std::vector<Token>& tokens) {
    // CALL + InvokingUID + MethodUID + params
    if (tokens.size() < 3) return wrapSmPacket(comId, buildErrorResponse(0x0F));

    // Find method UID
    uint64_t methodUid = 0;
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i].type == TokenType::Call && i + 2 < tokens.size()) {
            if (tokens[i + 2].isAtom() && tokens[i + 2].isByteSequence) {
                methodUid = 0;
                auto& b = tokens[i + 2].getBytes();
                for (size_t j = 0; j < std::min(b.size(), size_t(8)); ++j)
                    methodUid = (methodUid << 8) | b[j];
            }
            break;
        }
    }

    Bytes responseTokens;
    if (methodUid == method::SM_PROPERTIES) {
        responseTokens = handleProperties(tokens);
    } else if (methodUid == method::SM_START_SESSION) {
        responseTokens = handleStartSession(tokens);
    } else {
        responseTokens = buildErrorResponse(0x0F);
    }

    return wrapSmPacket(comId, responseTokens);
}

// ═══════════════════════════════════════════════════════
//  Properties Handler
// ═══════════════════════════════════════════════════════

Bytes SimTransport::handleProperties(const std::vector<Token>& /*tokens*/) {
    TokenEncoder enc;
    enc.call();
    enc.encodeUid(SMUID);
    enc.encodeUid(method::SM_PROPERTIES);
    enc.startList();

    // TPerProperties
    enc.startName();
    enc.encodeString("TPerProperties");
    enc.startList();
    enc.encodeString("MaxMethods");        enc.encodeUint(1);
    enc.encodeString("MaxSubpackets");     enc.encodeUint(1);
    enc.encodeString("MaxPackets");        enc.encodeUint(1);
    enc.encodeString("MaxComPacketSize");  enc.encodeUint(config_.maxComPacketSize);
    enc.encodeString("MaxPacketSize");     enc.encodeUint(config_.maxPacketSize);
    enc.encodeString("MaxIndTokenSize");   enc.encodeUint(config_.maxIndTokenSize);
    enc.encodeString("MaxAggTokenSize");   enc.encodeUint(config_.maxIndTokenSize);
    enc.encodeString("ContinuedTokens");   enc.encodeUint(0);
    enc.encodeString("SequenceNumbers");   enc.encodeUint(0);
    enc.encodeString("AckNak");            enc.encodeUint(0);
    enc.encodeString("Async");             enc.encodeUint(0);
    enc.endList();
    enc.endName();

    // HostProperties echo
    enc.startName();
    enc.encodeString("HostProperties");
    enc.startList();
    enc.encodeString("MaxComPacketSize");  enc.encodeUint(config_.maxComPacketSize);
    enc.encodeString("MaxPacketSize");     enc.encodeUint(config_.maxPacketSize);
    enc.encodeString("MaxIndTokenSize");   enc.encodeUint(config_.maxIndTokenSize);
    enc.endList();
    enc.endName();

    enc.endList();
    enc.endOfData();
    enc.startList(); enc.encodeUint(0); enc.encodeUint(0); enc.encodeUint(0); enc.endList();

    return enc.data();
}

// ═══════════════════════════════════════════════════════
//  StartSession Handler
// ═══════════════════════════════════════════════════════

Bytes SimTransport::handleStartSession(const std::vector<Token>& tokens) {
    // 파라미터 파싱: HSN, SPUID, Write, [Named params: HostChallenge, Authority]
    uint32_t hsn = 0;
    uint64_t spUid = 0;
    bool write = false;
    Bytes hostChallenge;
    uint64_t authUid = 0;

    // StartList 이후의 파라미터들 찾기
    size_t paramStart = 0;
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i].type == TokenType::StartList) {
            paramStart = i + 1;
            break;
        }
    }

    // Positional params
    size_t idx = paramStart;
    if (idx < tokens.size() && tokens[idx].isAtom() && !tokens[idx].isByteSequence) {
        hsn = static_cast<uint32_t>(tokens[idx].getUint());
        ++idx;
    }
    if (idx < tokens.size() && tokens[idx].isAtom() && tokens[idx].isByteSequence) {
        // SP UID
        spUid = 0;
        for (size_t j = 0; j < std::min(tokens[idx].getBytes().size(), size_t(8)); ++j)
            spUid = (spUid << 8) | tokens[idx].getBytes()[j];
        ++idx;
    }
    if (idx < tokens.size() && tokens[idx].isAtom() && !tokens[idx].isByteSequence) {
        write = tokens[idx].getUint() != 0;
        ++idx;
    }

    // Named optional params
    for (; idx < tokens.size(); ++idx) {
        if (tokens[idx].type == TokenType::StartName && idx + 2 < tokens.size()) {
            uint32_t name = static_cast<uint32_t>(tokens[idx + 1].getUint());
            if (name == 0 && tokens[idx + 2].isByteSequence) {
                hostChallenge = tokens[idx + 2].getBytes();
            } else if (name == 3 && tokens[idx + 2].isByteSequence) {
                authUid = 0;
                auto& authBytes = tokens[idx + 2].getBytes();
                for (size_t j = 0; j < std::min(authBytes.size(), size_t(8)); ++j)
                    authUid = (authUid << 8) | authBytes[j];
            }
        }
    }

    // SP 검증
    if (spUid == SP_LOCKING && lockingSpLifecycle_ != SpLifecycle::Manufactured) {
        if (write) {
            // Locking SP가 비활성이면 쓰기 세션 거부
            return buildSmSyncError(0x05);  // SpDisabled
        }
    }

    // 인증 검증 (authUid가 있으면)
    bool authenticated = false;
    if (authUid != 0 && !hostChallenge.empty()) {
        // C_PIN에서 해당 Authority의 PIN을 찾아 비교
        uint64_t cpinUid = 0;
        if (authUid == AUTH_SID)    cpinUid = CPIN_SID;
        else if (authUid == AUTH_PSID)   cpinUid = CPIN_MSID;  // PSID는 라벨 값
        else if (authUid == AUTH_ADMIN1) cpinUid = CPIN_ADMIN1;
        else if (authUid >= AUTH_USER1 && authUid <= AUTH_USER1 + 8) {
            cpinUid = makeCpinUserUid(static_cast<uint32_t>(authUid - AUTH_USER1 + 1)).toUint64();
        }

        if (cpinUid != 0) {
            auto it = cpins_.find(cpinUid);
            if (it != cpins_.end()) {
                if (it->second.pin == hostChallenge) {
                    authenticated = true;
                } else {
                    // PIN 시도 차감
                    if (it->second.triesRemaining > 0) {
                        it->second.triesRemaining--;
                    }
                    if (it->second.triesRemaining == 0) {
                        return buildSmSyncError(0x0F);  // AuthLockedOut
                    }
                    return buildSmSyncError(0x01);  // NotAuthorized
                }
            } else {
                return buildSmSyncError(0x01);
            }
        }
    }

    // 세션 생성
    uint32_t tsn = nextTsn_++;
    SessionState session;
    session.tsn = tsn;
    session.hsn = hsn;
    session.spUid = spUid;
    session.write = write;
    session.authUid = authUid;
    session.authenticated = authenticated;
    sessions_[tsn] = session;

    comIdState_ = ComIdState::Associated;

    // SyncSession 응답
    TokenEncoder enc;
    enc.call();
    enc.encodeUid(SMUID);
    enc.encodeUid(method::SM_SYNC_SESSION);
    enc.startList();
    enc.encodeUint(hsn);
    enc.encodeUint(tsn);
    enc.endList();
    enc.endOfData();
    enc.startList(); enc.encodeUint(0); enc.encodeUint(0); enc.encodeUint(0); enc.endList();

    return enc.data();
}

Bytes SimTransport::buildSmSyncError(uint8_t statusCode) {
    TokenEncoder enc;
    enc.call();
    enc.encodeUid(SMUID);
    enc.encodeUid(method::SM_SYNC_SESSION);
    enc.startList();
    enc.encodeUint(0);
    enc.encodeUint(0);
    enc.endList();
    enc.endOfData();
    enc.startList();
    enc.encodeUint(statusCode);
    enc.encodeUint(0);
    enc.encodeUint(0);
    enc.endList();
    return enc.data();
}

// ═══════════════════════════════════════════════════════
//  In-Session Method Handler
// ═══════════════════════════════════════════════════════

Bytes SimTransport::handleSessionMethod(uint16_t comId, uint32_t tsn, uint32_t hsn,
                                          const std::vector<Token>& tokens) {
    // CloseSession 처리 (EndOfSession 토큰)
    for (auto& t : tokens) {
        if (t.type == TokenType::EndOfSession) {
            return handleCloseSession(tsn, hsn);
        }
    }

    // 세션 검증
    auto sessionIt = sessions_.find(tsn);
    if (sessionIt == sessions_.end()) {
        return wrapSessionPacket(comId, tsn, hsn, buildErrorResponse(0x01));
    }

    // CALL + ObjectUID + MethodUID 파싱
    uint64_t objectUid = 0, methodUid = 0;
    size_t paramStart = 0;
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i].type == TokenType::Call && i + 2 < tokens.size()) {
            // ObjectUID
            if (tokens[i + 1].isAtom() && tokens[i + 1].isByteSequence) {
                objectUid = 0;
                for (size_t j = 0; j < std::min(tokens[i + 1].getBytes().size(), size_t(8)); ++j)
                    objectUid = (objectUid << 8) | tokens[i + 1].getBytes()[j];
            }
            // MethodUID
            if (tokens[i + 2].isAtom() && tokens[i + 2].isByteSequence) {
                methodUid = 0;
                for (size_t j = 0; j < std::min(tokens[i + 2].getBytes().size(), size_t(8)); ++j)
                    methodUid = (methodUid << 8) | tokens[i + 2].getBytes()[j];
            }
            paramStart = i + 3;
            break;
        }
    }

    // 파라미터 토큰 수집 (StartList ~ EndList)
    std::vector<Token> params;
    for (size_t i = paramStart; i < tokens.size(); ++i) {
        if (tokens[i].type == TokenType::EndOfData) break;
        params.push_back(tokens[i]);
    }

    Bytes responseTokens;
    if (methodUid == method::GET) {
        responseTokens = handleGet(objectUid, params, sessionIt->second);
    } else if (methodUid == method::SET) {
        responseTokens = handleSet(objectUid, params, sessionIt->second);
    } else if (methodUid == method::AUTHENTICATE) {
        responseTokens = handleAuthenticate(params, sessionIt->second);
    } else if (methodUid == method::ACTIVATE) {
        responseTokens = handleActivate(objectUid, sessionIt->second);
    } else if (methodUid == method::REVERTSP) {
        responseTokens = handleRevertSP(objectUid, sessionIt->second);
    } else if (methodUid == method::GENKEY) {
        responseTokens = handleGenKey(objectUid, sessionIt->second);
    } else if (methodUid == method::ERASE) {
        responseTokens = handleErase(objectUid, sessionIt->second);
    } else if (methodUid == method::RANDOM) {
        responseTokens = handleRandom(params, sessionIt->second);
    } else if (methodUid == method::REVERT) {
        // PSID revert uses REVERT method (not REVERT_SP)
        responseTokens = handleRevertSP(objectUid, sessionIt->second);
    } else {
        // Unknown method → success (permissive simulator)
        responseTokens = buildSuccessResponse();
    }

    return wrapSessionPacket(comId, tsn, hsn, responseTokens);
}

Bytes SimTransport::handleCloseSession(uint32_t tsn, uint32_t hsn) {
    sessions_.erase(tsn);
    if (sessions_.empty()) {
        comIdState_ = ComIdState::Idle;
    }

    // EndOfSession 응답
    TokenEncoder enc;
    enc.endOfSession();
    return wrapSmPacket(config_.baseComId, enc.data());
}

// ═══════════════════════════════════════════════════════
//  Get Handler
// ═══════════════════════════════════════════════════════

Bytes SimTransport::handleGet(uint64_t objectUid, const std::vector<Token>& params,
                                const SessionState& session) {
    // CellBlock 파싱: startCol, endCol
    uint32_t startCol = 0, endCol = 255;
    for (size_t i = 0; i < params.size(); ++i) {
        if (params[i].type == TokenType::StartName && i + 2 < params.size()) {
            uint32_t name = static_cast<uint32_t>(params[i + 1].getUint());
            uint64_t val = params[i + 2].getUint();
            if (name == 3) startCol = static_cast<uint32_t>(val);
            if (name == 4) endCol = static_cast<uint32_t>(val);
        }
    }

    // C_PIN 테이블 읽기
    if (isCpinUid(objectUid)) {
        auto it = cpins_.find(objectUid);
        if (it != cpins_.end()) {
            std::vector<std::pair<uint32_t, Bytes>> byteCols;
            std::vector<std::pair<uint32_t, uint64_t>> uintCols;
            for (uint32_t c = startCol; c <= endCol; ++c) {
                if (c == col::PIN) {
                    // MSID는 누구나 읽기 가능, 나머지는 권한 필요
                    if (objectUid == CPIN_MSID || session.authenticated) {
                        byteCols.push_back({c, it->second.pin});
                    }
                } else if (c == col::PIN_TRIES_REMAINING) {
                    uintCols.push_back({c, it->second.triesRemaining});
                }
            }
            return buildGetMixedResponse(uintCols, byteCols);
        }
        return buildErrorResponse(0x01);
    }

    // Locking Range 읽기
    if (isLockingRangeUid(objectUid)) {
        uint32_t rangeId = lockingRangeIndex(objectUid);
        auto it = ranges_.find(rangeId);
        if (it != ranges_.end()) {
            std::vector<std::pair<uint32_t, uint64_t>> cols;
            auto& r = it->second;
            for (uint32_t c = startCol; c <= endCol; ++c) {
                switch (c) {
                    case col::RANGE_START:    cols.push_back({c, r.rangeStart}); break;
                    case col::RANGE_LENGTH:   cols.push_back({c, r.rangeLength}); break;
                    case col::READ_LOCK_EN:   cols.push_back({c, r.readLockEnabled ? 1u : 0u}); break;
                    case col::WRITE_LOCK_EN:  cols.push_back({c, r.writeLockEnabled ? 1u : 0u}); break;
                    case col::READ_LOCKED:    cols.push_back({c, r.readLocked ? 1u : 0u}); break;
                    case col::WRITE_LOCKED:   cols.push_back({c, r.writeLocked ? 1u : 0u}); break;
                    case col::LOCK_ON_RESET:  cols.push_back({c, r.lockOnReset ? 1u : 0u}); break;
                    case col::ACTIVE_KEY: {
                        // ActiveKey는 UID (8바이트 bytesequence)로 반환해야 함
                        Uid keyUid(r.activeKey);
                        Bytes keyBytes(keyUid.bytes.begin(), keyUid.bytes.end());
                        // 이 컬럼만 요청된 경우 바로 반환
                        if (startCol == endCol && startCol == col::ACTIVE_KEY) {
                            return buildGetBytesResponse({{c, keyBytes}});
                        }
                        cols.push_back({c, r.activeKey}); break;
                    }
                }
            }
            return buildGetUintResponse(cols);
        }
    }

    // SP 테이블 (Lifecycle)
    if (objectUid == SP_ADMIN || objectUid == SP_LOCKING) {
        uint8_t lifecycle = (objectUid == SP_ADMIN)
            ? static_cast<uint8_t>(adminSpLifecycle_)
            : static_cast<uint8_t>(lockingSpLifecycle_);
        return buildGetUintResponse({{col::LIFECYCLE, lifecycle}});
    }

    // Authority 테이블
    if (isAuthorityUid(objectUid)) {
        auto it = authorities_.find(objectUid);
        bool enabled = (it != authorities_.end()) ? it->second : false;
        return buildGetUintResponse({{col::AUTH_ENABLED, enabled ? 1u : 0u}});
    }

    // MBR Control
    if (objectUid == MBRCTRL_SET) {
        std::vector<std::pair<uint32_t, uint64_t>> cols;
        for (uint32_t c = startCol; c <= endCol; ++c) {
            if (c == col::MBR_ENABLE) cols.push_back({c, mbrEnabled_ ? 1u : 0u});
            if (c == col::MBR_DONE)   cols.push_back({c, mbrDone_ ? 1u : 0u});
        }
        return buildGetUintResponse(cols);
    }

    // ByteTable (DataStore) 읽기 — Get with CellBlock(startRow=offset, endRow=end)
    if (isDataStoreUid(objectUid)) {
        // DataStore Get은 startCol/endCol 대신 startRow/endRow를 사용 (바이트 오프셋)
        uint32_t rowStart = 0, rowEnd = static_cast<uint32_t>(dataStore_.size() - 1);
        bool hasRow = false;
        for (size_t i = 0; i < params.size(); ++i) {
            if (params[i].type == TokenType::StartName && i + 2 < params.size()) {
                uint32_t name = static_cast<uint32_t>(params[i + 1].getUint());
                if (name == 1) { rowStart = static_cast<uint32_t>(params[i + 2].getUint()); hasRow = true; }
                if (name == 2) { rowEnd = static_cast<uint32_t>(params[i + 2].getUint()); hasRow = true; }
                // startCol/endCol(3,4)은 column 기반 → ByteTableInfo 조회
                if (name == 3 || name == 4) {
                    // Column-based Get → ByteTableInfo
                    return buildGetUintResponse({
                        {col::MAX_SIZE, static_cast<uint64_t>(config_.dataStoreSize)},
                        {col::USED_SIZE, 0u}
                    });
                }
            }
        }
        uint32_t offset = rowStart;
        uint32_t length = (rowEnd >= rowStart) ? (rowEnd - rowStart + 1) : 0;
        if (offset + length > dataStore_.size()) {
            return buildErrorResponse(0x0C);  // InvalidParameter
        }
        Bytes data(dataStore_.begin() + offset, dataStore_.begin() + offset + length);
        // ByteTable Read 응답: bare byte sequence (StartName 없이)
        TokenEncoder enc;
        enc.startList();
        enc.encodeBytes(data);
        enc.endList();
        enc.endOfData();
        enc.startList(); enc.encodeUint(0); enc.encodeUint(0); enc.encodeUint(0); enc.endList();
        return enc.data();
    }

    // MBR 테이블 읽기
    if (objectUid == TABLE_MBR || (objectUid & 0xFFFFFFFF00000000ULL) == TABLE_MBR) {
        uint32_t rowStart = 0, rowEnd = static_cast<uint32_t>(mbrData_.size() - 1);
        for (size_t i = 0; i < params.size(); ++i) {
            if (params[i].type == TokenType::StartName && i + 2 < params.size()) {
                uint32_t name = static_cast<uint32_t>(params[i + 1].getUint());
                if (name == 1) rowStart = static_cast<uint32_t>(params[i + 2].getUint());
                if (name == 2) rowEnd = static_cast<uint32_t>(params[i + 2].getUint());
            }
        }
        uint32_t offset = rowStart;
        uint32_t length = (rowEnd >= rowStart) ? (rowEnd - rowStart + 1) : 0;
        if (offset + length > mbrData_.size()) {
            return buildErrorResponse(0x0C);
        }
        Bytes data(mbrData_.begin() + offset, mbrData_.begin() + offset + length);
        // MBR Read: bare byte sequence
        TokenEncoder enc;
        enc.startList();
        enc.encodeBytes(data);
        enc.endList();
        enc.endOfData();
        enc.startList(); enc.encodeUint(0); enc.encodeUint(0); enc.encodeUint(0); enc.endList();
        return enc.data();
    }

    // ByteTable info (TABLE_DATASTORE Get with col 3=maxSize, 4=usedSize)
    // 이미 위 DataStore에서 처리되므로 여기서는 컬럼 기반 Get 처리
    // (startCol/endCol이 설정된 경우)

    // 알 수 없는 객체 → 빈 성공 응답
    return buildSuccessResponse();
}

// ═══════════════════════════════════════════════════════
//  Set Handler
// ═══════════════════════════════════════════════════════

Bytes SimTransport::handleSet(uint64_t objectUid, const std::vector<Token>& params,
                                const SessionState& session) {
    if (!session.write) return buildErrorResponse(0x01);

    // Values 파싱: Where(skip) + Values
    // Find Values block (name=1)
    size_t valuesStart = 0;
    for (size_t i = 0; i < params.size(); ++i) {
        if (params[i].type == TokenType::StartName) {
            if (i + 1 < params.size() && params[i + 1].isAtom()) {
                uint32_t name = static_cast<uint32_t>(params[i + 1].getUint());
                if (name == 1) {
                    valuesStart = i + 2;  // skip StartName + name
                    break;
                }
            }
        }
    }

    // 값 파싱 (StartName col value EndName 패턴)
    std::vector<std::pair<uint32_t, Token>> columnValues;
    for (size_t i = valuesStart; i < params.size(); ++i) {
        if (params[i].type == TokenType::StartName && i + 2 < params.size()) {
            uint32_t col = static_cast<uint32_t>(params[i + 1].getUint());
            columnValues.push_back({col, params[i + 2]});
        }
    }

    // C_PIN 설정
    if (isCpinUid(objectUid)) {
        auto it = cpins_.find(objectUid);
        if (it != cpins_.end()) {
            for (auto& [c, val] : columnValues) {
                if (c == col::PIN) {
                    it->second.pin = val.getBytes();
                }
            }
            return buildSuccessResponse();
        }
        return buildErrorResponse(0x01);
    }

    // Locking Range 설정
    if (isLockingRangeUid(objectUid)) {
        uint32_t rangeId = lockingRangeIndex(objectUid);
        auto it = ranges_.find(rangeId);
        if (it != ranges_.end()) {
            for (auto& [c, val] : columnValues) {
                switch (c) {
                    case col::RANGE_START:    it->second.rangeStart = val.getUint(); break;
                    case col::RANGE_LENGTH:   it->second.rangeLength = val.getUint(); break;
                    case col::READ_LOCK_EN:   it->second.readLockEnabled = val.getUint() != 0; break;
                    case col::WRITE_LOCK_EN:  it->second.writeLockEnabled = val.getUint() != 0; break;
                    case col::READ_LOCKED:    it->second.readLocked = val.getUint() != 0; break;
                    case col::WRITE_LOCKED:   it->second.writeLocked = val.getUint() != 0; break;
                    case col::LOCK_ON_RESET:  it->second.lockOnReset = val.getUint() != 0; break;
                }
            }
            return buildSuccessResponse();
        }
    }

    // Authority 설정 (enable/disable)
    if (isAuthorityUid(objectUid)) {
        for (auto& [c, val] : columnValues) {
            if (c == col::AUTH_ENABLED) {
                authorities_[objectUid] = val.getUint() != 0;
            }
        }
        return buildSuccessResponse();
    }

    // MBR Control
    if (objectUid == MBRCTRL_SET) {
        for (auto& [c, val] : columnValues) {
            if (c == col::MBR_ENABLE) mbrEnabled_ = val.getUint() != 0;
            if (c == col::MBR_DONE)   mbrDone_ = val.getUint() != 0;
        }
        return buildSuccessResponse();
    }

    // DataStore 쓰기 — Set with Where=offset(name=0), Values=data(name=1)
    if (isDataStoreUid(objectUid)) {
        uint32_t offset = 0;
        Bytes data;
        for (size_t i = 0; i < params.size(); ++i) {
            if (params[i].type == TokenType::StartName && i + 2 < params.size()) {
                uint32_t name = static_cast<uint32_t>(params[i + 1].getUint());
                if (name == 0) offset = static_cast<uint32_t>(params[i + 2].getUint());
                if (name == 1) data = params[i + 2].getBytes();
            }
        }
        if (offset + data.size() > dataStore_.size()) {
            return buildErrorResponse(0x0C);
        }
        std::copy(data.begin(), data.end(), dataStore_.begin() + offset);
        return buildSuccessResponse();
    }

    // MBR 데이터 쓰기
    if (objectUid == TABLE_MBR || (objectUid & 0xFFFFFFFF00000000ULL) == TABLE_MBR) {
        uint32_t offset = 0;
        Bytes data;
        for (size_t i = 0; i < params.size(); ++i) {
            if (params[i].type == TokenType::StartName && i + 2 < params.size()) {
                uint32_t name = static_cast<uint32_t>(params[i + 1].getUint());
                if (name == 0) offset = static_cast<uint32_t>(params[i + 2].getUint());
                if (name == 1) data = params[i + 2].getBytes();
            }
        }
        if (offset + data.size() > mbrData_.size()) {
            return buildErrorResponse(0x0C);
        }
        std::copy(data.begin(), data.end(), mbrData_.begin() + offset);
        return buildSuccessResponse();
    }

    // 기본: 성공
    return buildSuccessResponse();
}

// ═══════════════════════════════════════════════════════
//  Authenticate Handler
// ═══════════════════════════════════════════════════════

Bytes SimTransport::handleAuthenticate(const std::vector<Token>& params,
                                         SessionState& session) {
    // params: StartList UID(authority) StartName 0 bytes(challenge) EndName EndList
    uint64_t authUid = 0;
    Bytes challenge;

    for (size_t i = 0; i < params.size(); ++i) {
        if (params[i].isAtom() && params[i].isByteSequence && params[i].getBytes().size() == 8 && authUid == 0) {
            for (auto b : params[i].getBytes()) authUid = (authUid << 8) | b;
        }
        if (params[i].type == TokenType::StartName && i + 2 < params.size()) {
            if (params[i + 1].getUint() == 0) {
                challenge = params[i + 2].getBytes();
            }
        }
    }

    // PIN 검증
    uint64_t cpinUid = 0;
    if (authUid == AUTH_SID) cpinUid = CPIN_SID;
    else if (authUid == AUTH_ADMIN1) cpinUid = CPIN_ADMIN1;
    else if (authUid >= AUTH_USER1 && authUid <= AUTH_USER1 + 8) {
        cpinUid = makeCpinUserUid(static_cast<uint32_t>(authUid - AUTH_USER1 + 1)).toUint64();
    }

    if (cpinUid != 0) {
        auto it = cpins_.find(cpinUid);
        if (it != cpins_.end() && it->second.pin == challenge) {
            session.authUid = authUid;
            session.authenticated = true;
            return buildSuccessResponse();
        }
    }

    return buildErrorResponse(0x01);  // NotAuthorized
}

// ═══════════════════════════════════════════════════════
//  Activate / Revert / GenKey
// ═══════════════════════════════════════════════════════

Bytes SimTransport::handleActivate(uint64_t objectUid, const SessionState& session) {
    if (objectUid == SP_LOCKING) {
        if (lockingSpLifecycle_ == SpLifecycle::Manufactured) {
            return buildErrorResponse(0x3F);  // 이미 활성
        }
        lockingSpLifecycle_ = SpLifecycle::Manufactured;
        return buildSuccessResponse();
    }
    return buildErrorResponse(0x01);
}

Bytes SimTransport::handleRevertSP(uint64_t objectUid, SessionState& session) {
    if (!session.write || !session.authenticated) return buildErrorResponse(0x01);

    if (objectUid == SP_ADMIN) {
        // RevertSP on AdminSP resets everything. Session is terminated by TPer.
        // Return success with EndOfSession to signal session termination.
        TokenEncoder enc;
        enc.startList(); enc.endList();
        enc.endOfData();
        enc.startList(); enc.encodeUint(0); enc.encodeUint(0); enc.encodeUint(0); enc.endList();
        enc.endOfSession();
        auto result = enc.data();
        factoryReset();
        return result;
    }
    if (objectUid == SP_LOCKING) {
        lockingSpLifecycle_ = SpLifecycle::ManufacturedInactive;
        // Range/User/MBR 초기화
        for (auto& [id, r] : ranges_) r = {};
        for (uint32_t i = 1; i <= config_.maxUsers; ++i) {
            cpins_[makeCpinUserUid(i).toUint64()] = {false, {}, config_.pinTryLimit};
            authorities_[makeUserUid(i).toUint64()] = false;
        }
        cpins_[CPIN_ADMIN1] = {true, msid_, config_.pinTryLimit};
        mbrEnabled_ = false;
        mbrDone_ = false;
        // RevertSP terminates the session
        sessions_.erase(session.tsn);
        TokenEncoder enc;
        enc.startList(); enc.endList();
        enc.endOfData();
        enc.startList(); enc.encodeUint(0); enc.encodeUint(0); enc.encodeUint(0); enc.endList();
        enc.endOfSession();
        return enc.data();
    }
    return buildErrorResponse(0x01);
}

Bytes SimTransport::handleGenKey(uint64_t objectUid, const SessionState& session) {
    if (!session.write) return buildErrorResponse(0x01);
    keyCounter_++;

    // Range-specific 키 변경 (cryptoErase가 rangeUid로 GenKey를 호출)
    if (isLockingRangeUid(objectUid)) {
        uint32_t rangeId = lockingRangeIndex(objectUid);
        auto it = ranges_.find(rangeId);
        if (it != ranges_.end()) {
            it->second.activeKey = keyCounter_;
        }
    } else {
        // K_AES UID나 기타 — 해당 range 찾기
        for (auto& [id, r] : ranges_) {
            r.activeKey = keyCounter_;
        }
    }
    return buildSuccessResponse();
}

Bytes SimTransport::handleErase(uint64_t objectUid, const SessionState& session) {
    if (!session.write) return buildErrorResponse(0x01);
    // CryptoErase: 새 키 생성 (기존 데이터 복호화 불가)
    keyCounter_++;
    // Range별 키 교체
    if (isLockingRangeUid(objectUid)) {
        uint32_t rangeId = lockingRangeIndex(objectUid);
        auto it = ranges_.find(rangeId);
        if (it != ranges_.end()) {
            it->second.activeKey = keyCounter_;
        }
    } else {
        // 모든 range 키 교체
        for (auto& [id, r] : ranges_) r.activeKey = keyCounter_;
    }
    return buildSuccessResponse();
}

Bytes SimTransport::handleRandom(const std::vector<Token>& params,
                                   const SessionState& /*session*/) {
    // 요청된 바이트 수만큼 난수 생성
    uint32_t count = 32;
    for (size_t i = 0; i < params.size(); ++i) {
        if (params[i].isAtom() && !params[i].isByteSequence) {
            count = static_cast<uint32_t>(params[i].getUint());
            break;
        }
    }

    Bytes randomData(count);
    auto seed = static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    std::mt19937 rng(seed + keyCounter_);
    for (auto& b : randomData) b = static_cast<uint8_t>(rng() & 0xFF);

    return buildGetBytesResponse({{0, randomData}});
}

// ═══════════════════════════════════════════════════════
//  Response Builders
// ═══════════════════════════════════════════════════════

Bytes SimTransport::buildSuccessResponse() {
    TokenEncoder enc;
    enc.startList(); enc.endList();
    enc.endOfData();
    enc.startList(); enc.encodeUint(0); enc.encodeUint(0); enc.encodeUint(0); enc.endList();
    return enc.data();
}

Bytes SimTransport::buildErrorResponse(uint8_t statusCode) {
    TokenEncoder enc;
    enc.startList(); enc.endList();
    enc.endOfData();
    enc.startList();
    enc.encodeUint(statusCode);
    enc.encodeUint(0);
    enc.encodeUint(0);
    enc.endList();
    return enc.data();
}

Bytes SimTransport::buildGetUintResponse(
    const std::vector<std::pair<uint32_t, uint64_t>>& cols) {
    TokenEncoder enc;
    enc.startList();
    for (auto& [c, val] : cols) {
        enc.startName(); enc.encodeUint(c); enc.encodeUint(val); enc.endName();
    }
    enc.endList();
    enc.endOfData();
    enc.startList(); enc.encodeUint(0); enc.encodeUint(0); enc.encodeUint(0); enc.endList();
    return enc.data();
}

Bytes SimTransport::buildGetBytesResponse(
    const std::vector<std::pair<uint32_t, Bytes>>& cols) {
    TokenEncoder enc;
    enc.startList();
    for (auto& [c, val] : cols) {
        enc.startName(); enc.encodeUint(c); enc.encodeBytes(val); enc.endName();
    }
    enc.endList();
    enc.endOfData();
    enc.startList(); enc.encodeUint(0); enc.encodeUint(0); enc.encodeUint(0); enc.endList();
    return enc.data();
}

Bytes SimTransport::buildGetMixedResponse(
    const std::vector<std::pair<uint32_t, uint64_t>>& uintCols,
    const std::vector<std::pair<uint32_t, Bytes>>& bytesCols) {
    TokenEncoder enc;
    enc.startList();
    for (auto& [c, val] : uintCols) {
        enc.startName(); enc.encodeUint(c); enc.encodeUint(val); enc.endName();
    }
    for (auto& [c, val] : bytesCols) {
        enc.startName(); enc.encodeUint(c); enc.encodeBytes(val); enc.endName();
    }
    enc.endList();
    enc.endOfData();
    enc.startList(); enc.encodeUint(0); enc.encodeUint(0); enc.encodeUint(0); enc.endList();
    return enc.data();
}

Bytes SimTransport::wrapSmPacket(uint16_t comId, const Bytes& tokenPayload) {
    PacketBuilder builder;
    builder.setComId(comId);
    builder.setSessionNumbers(0, 0);
    return builder.buildSessionManagerPacket(tokenPayload);
}

Bytes SimTransport::wrapSessionPacket(uint16_t comId, uint32_t tsn, uint32_t hsn,
                                        const Bytes& tokenPayload) {
    PacketBuilder builder;
    builder.setComId(comId);
    builder.setSessionNumbers(tsn, hsn);
    return builder.buildComPacket(tokenPayload);
}

// ═══════════════════════════════════════════════════════
//  UID Helpers
// ═══════════════════════════════════════════════════════

bool SimTransport::isCpinUid(uint64_t uid) const {
    return (uid & 0xFFFFFFFF00000000ULL) == TABLE_CPIN;
}

bool SimTransport::isLockingRangeUid(uint64_t uid) const {
    return uid >= LOCKING_GLOBALRANGE && uid <= LOCKING_GLOBALRANGE + config_.maxRanges;
}

uint32_t SimTransport::lockingRangeIndex(uint64_t uid) const {
    return static_cast<uint32_t>(uid - LOCKING_GLOBALRANGE);
}

bool SimTransport::isAuthorityUid(uint64_t uid) const {
    return (uid & 0xFFFFFFFF00000000ULL) == 0x0000000900000000ULL;
}

bool SimTransport::isDataStoreUid(uint64_t uid) const {
    return (uid & 0xFFFFFFFF00000000ULL) == TABLE_DATASTORE;
}

bool SimTransport::isAuthorizedForGet(const SessionState& session, uint64_t objectUid) {
    return true;  // 간소화: Get은 항상 허용
}

bool SimTransport::isAuthorizedForSet(const SessionState& session, uint64_t objectUid) {
    return session.write && session.authenticated;
}

bool SimTransport::isAuthorizedForActivate(const SessionState& session) {
    return session.write && session.authenticated;
}

} // namespace libsed
