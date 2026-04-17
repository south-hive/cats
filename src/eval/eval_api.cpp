#include "libsed/eval/eval_api.h"
#include "libsed/transport/nvme_transport.h"
#include "libsed/method/method_call.h"
#include "libsed/method/method_result.h"
#include "libsed/method/method_uids.h"
#include "libsed/method/param_encoder.h"
#include "libsed/method/param_decoder.h"
#include "libsed/codec/token_encoder.h"
#include "libsed/codec/token_decoder.h"
#include "libsed/packet/packet_builder.h"
#include "libsed/security/hash_password.h"
#include "libsed/core/uid.h"
#include "libsed/core/endian.h"
#include "libsed/core/log.h"
#include "eval_api_internal.h"
#include <thread>
#include <chrono>

namespace libsed {
namespace eval {

// ═══════════════════��═══════════════════════════���════════
//  Discovery
// ════════════���═══════════════════════════════════════════

Result EvalApi::discovery0(std::shared_ptr<ITransport> transport,
                            DiscoveryInfo& info) {
    Discovery disc;
    auto r = disc.discover(transport);
    if (r.ok()) info = disc.buildInfo();
    return r;
}

Result EvalApi::discovery0Raw(std::shared_ptr<ITransport> transport,
                               Bytes& rawResponse) {
    // Discovery response is NOT a ComPacket — bytes 16-19 are reserved zeros,
    // not a ComPacket.length field. Cannot use pollRecv() here because it
    // checks ComPacket.length > 0 and would poll forever.
    return transport->ifRecv(0x01, 0x0001, rawResponse, 2048);
}

Result EvalApi::discovery0Custom(std::shared_ptr<ITransport> transport,
                                  uint8_t protocolId, uint16_t comId,
                                  Bytes& rawResponse) {
    // Discovery responses are not ComPackets — use direct ifRecv, not pollRecv.
    return transport->ifRecv(protocolId, comId, rawResponse, 2048);
}

// ══════════��═════════════════════════════════════════════
//  Discovery Namespace (with raw)
// ═══════════════════════════���════════════════════════════

Result EvalApi::discovery0Parsed(std::shared_ptr<ITransport> transport,
                                  DiscoveryInfo& info, RawResult& result) {
    Bytes rawData;
    auto r = transport->ifRecv(0x01, 0x0001, rawData, 2048);
    if (r.failed()) { result.transportError = r.code(); return r; }
    result.rawRecvPayload = rawData;

    Discovery disc;
    r = disc.parse(rawData);
    if (r.ok()) info = disc.buildInfo();
    return r;
}

// ═══════════���══════════════════════���═════════════════════
//  Properties
// ══════════���═════════════════════════════════════════════

Result EvalApi::exchangeProperties(std::shared_ptr<ITransport> transport,
                                    uint16_t comId,
                                    PropertiesResult& result) {
    // sedutil 기본값: MaxComPacketSize=2048, MaxPacketSize=2028, MaxIndTokenSize=1992
    return exchangePropertiesCustom(transport, comId, 2048, 2028, 1992, result);
}

Result EvalApi::exchangePropertiesCustom(std::shared_ptr<ITransport> transport,
                                          uint16_t comId,
                                          uint32_t maxComPacketSize,
                                          uint32_t maxPacketSize,
                                          uint32_t maxIndTokenSize,
                                          PropertiesResult& result) {
    // TCG Core Spec: ComID must be in Issued(idle) state before Properties.
    // sedutil always does StackReset before Properties. Without this, the
    // TPer may reject Properties if the ComID is still Associated from a
    // previous session (e.g. after abnormal termination or power cycle).
    auto resetResult = stackReset(transport, comId);
    if (resetResult.failed()) {
        LIBSED_WARN("StackReset before Properties failed (continuing): %s",
                     resetResult.message().c_str());
        // Continue anyway — some TPers may not support StackReset
    }

    ParamEncoder::HostProperties hostProps;
    hostProps.maxComPacketSize = maxComPacketSize;
    hostProps.maxResponseComPacketSize = maxComPacketSize;
    hostProps.maxPacketSize = maxPacketSize;
    hostProps.maxIndTokenSize = maxIndTokenSize;
    hostProps.maxAggTokenSize = maxIndTokenSize;

    Bytes params = ParamEncoder::encodeProperties(hostProps);
    Bytes methodTokens = MethodCall::buildSmCall(method::SM_PROPERTIES, params);

    PacketBuilder pb;
    pb.setComId(comId);
    Bytes sendData = pb.buildSessionManagerPacket(methodTokens);
    result.raw.rawSendPayload = sendData;

    auto r = transport->ifSend(0x01, comId, ByteSpan(sendData.data(), sendData.size()));
    if (r.failed()) { result.raw.transportError = r.code(); return r; }

    // IF-RECV with polling — TPer가 응답 준비될 때까지 반복
    // sedutil 기준: MIN_BUFFER_LENGTH = 2048
    static constexpr size_t PROPS_RECV_SIZE = 2048;
    Bytes recvBuffer;
    PacketBuilder::ParsedResponse parsed;
    for (int attempt = 0; attempt < 20; attempt++) {
        recvBuffer.clear();
        r = transport->ifRecv(0x01, comId, recvBuffer, PROPS_RECV_SIZE);
        if (r.failed()) { result.raw.transportError = r.code(); return r; }

        r = pb.parseResponse(recvBuffer, parsed);
        if (r.failed()) return r;

        // ComPacket.length > 0이면 실제 응답 수신 완료
        if (parsed.comPacketHeader.length > 0) break;

        // length == 0이면 TPer가 아직 처리 중 — 대기 후 재시도
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    result.raw.rawRecvPayload = recvBuffer;

    r = result.raw.methodResult.parse(parsed.tokenPayload);
    if (r.failed()) return r;

    if (!result.raw.methodResult.isSuccess())
        return result.raw.methodResult.toResult();

    // Decode properties from response
    // TCG Core Spec: Response contains two named blocks in order:
    //   STARTNAME "TPerProperties" { tper values } ENDNAME
    //   STARTNAME "HostProperties" { echoed host values } ENDNAME
    auto stream = result.raw.methodResult.resultStream();

    ParamDecoder::TPerProperties tperProps;

    // Parse up to two named blocks, identifying each by its name string
    for (int block = 0; block < 2 && stream.isStartName(); block++) {
        stream.expectStartName();
        auto nameStr = stream.readString();

        if (nameStr && *nameStr == "TPerProperties") {
            if (stream.isStartList()) {
                stream.expectStartList();
                ParamDecoder::decodeProperties(stream, tperProps);
                stream.expectEndList();
            }
            stream.expectEndName();
        } else if (nameStr && *nameStr == "HostProperties") {
            // Skip echoed host properties
            stream.skipList();
            stream.expectEndName();
        } else {
            // Unknown block — skip it
            stream.skipList();
            stream.expectEndName();
        }
    }

    result.tperMaxComPacketSize = tperProps.maxComPacketSize;
    result.tperMaxPacketSize    = tperProps.maxPacketSize;
    result.tperMaxIndTokenSize  = tperProps.maxIndTokenSize;
    result.tperMaxAggTokenSize  = tperProps.maxAggTokenSize;
    result.tperMaxMethods       = tperProps.maxMethods;
    result.tperMaxSubPackets    = tperProps.maxSubPackets;

    return ErrorCode::Success;
}

// ═══════════════════════════════════���════════════════════
//  Session lifecycle
// ═════════��════════════════════════���═════════════════════

Result EvalApi::startSession(Session& session, uint64_t spUid, bool write,
                              StartSessionResult& result) {
    auto r = session.startSession(Uid(spUid), write);
    result.hostSessionNumber = session.hostSessionNumber();
    result.tperSessionNumber = session.tperSessionNumber();
    return r;
}

Result EvalApi::startSessionWithAuth(Session& session, uint64_t spUid, bool write,
                                      uint64_t authorityUid, const Bytes& credential,
                                      StartSessionResult& result) {
    auto r = session.startSession(Uid(spUid), write, Uid(authorityUid), credential);
    result.hostSessionNumber = session.hostSessionNumber();
    result.tperSessionNumber = session.tperSessionNumber();
    return r;
}

Result EvalApi::closeSession(Session& session) {
    return session.closeSession();
}

// ═══���═════════════════════════════════���══════════════════
//  Split StartSession / SyncSession
// ════════════════════════════════════════════════════════

Result EvalApi::sendStartSession(std::shared_ptr<ITransport> transport,
                                  uint16_t comId,
                                  const StartSessionParams& params,
                                  Bytes& rawSentPayload) {
    // Build StartSession parameters manually for full control
    TokenEncoder paramEnc;
    uint32_t hsn = params.hostSessionId;
    if (hsn == 0) {
        static uint32_t autoHsn = 1;
        hsn = autoHsn++;
    }
    paramEnc.encodeUint(hsn);
    paramEnc.encodeUid(params.spUid);
    paramEnc.encodeBool(params.write);

    // StartSession_OPT fields (Opal SSC: optional named params indexed from 0)
    if (!params.hostChallenge.empty()) {
        paramEnc.startName();
        paramEnc.encodeUint(0);  // HostChallenge (sedutil uses 0)
        paramEnc.encodeBytes(params.hostChallenge);
        paramEnc.endName();
    }
    if (params.hostExchangeAuthority != 0) {
        paramEnc.startName();
        paramEnc.encodeUint(3);  // HostExchangeAuthority keyword
        paramEnc.encodeUid(params.hostExchangeAuthority);
        paramEnc.endName();
    }
    if (!params.hostExchangeCert.empty()) {
        paramEnc.startName();
        paramEnc.encodeUint(2);  // HostExchangeCert keyword
        paramEnc.encodeBytes(params.hostExchangeCert);
        paramEnc.endName();
    }
    if (params.hostSigningAuthority != 0) {
        paramEnc.startName();
        paramEnc.encodeUint(4);  // HostSigningAuthority keyword
        paramEnc.encodeUid(params.hostSigningAuthority);
        paramEnc.endName();
    }

    Bytes methodTokens = MethodCall::buildSmCall(method::SM_START_SESSION, paramEnc.data());

    PacketBuilder pb;
    pb.setComId(comId);
    Bytes sendData = pb.buildSessionManagerPacket(methodTokens);
    rawSentPayload = sendData;

    return transport->ifSend(0x01, comId, ByteSpan(sendData.data(), sendData.size()));
}

Result EvalApi::recvSyncSession(std::shared_ptr<ITransport> transport,
                                 uint16_t comId,
                                 SyncSessionResult& result) {
    Bytes recvBuffer;
    auto r = transport->ifRecv(0x01, comId, recvBuffer, 65536);
    if (r.failed()) { result.raw.transportError = r.code(); return r; }
    result.raw.rawRecvPayload = recvBuffer;

    PacketBuilder pb;
    pb.setComId(comId);
    PacketBuilder::ParsedResponse parsed;
    r = pb.parseResponse(recvBuffer, parsed);
    if (r.failed()) return r;

    r = result.raw.methodResult.parse(parsed.tokenPayload);
    if (r.failed()) return r;

    if (!result.raw.methodResult.isSuccess()) {
        result.raw.protocolError = result.raw.methodResult.toResult().code();
        return result.raw.methodResult.toResult();
    }

    // Parse SyncSession REQ fields
    auto stream = result.raw.methodResult.resultStream();
    ParamDecoder::SessionParams sessionParams;
    ParamDecoder::decodeSyncSession(stream, sessionParams);

    result.tperSessionNumber = sessionParams.tperSessionNumber;
    result.hostSessionNumber = sessionParams.hostSessionNumber;

    // Parse SyncSession_OPT fields (remaining named values in stream)
    while (stream.hasMore()) {
        if (stream.isStartName()) {
            stream.expectStartName();
            if (!stream.hasMore()) break;
            uint32_t key = static_cast<uint32_t>(stream.next()->getUint());
            if (!stream.hasMore()) break;
            const auto* valToken = stream.next();

            switch (key) {
                case 0: // SPChallenge
                    result.spChallenge = valToken->getBytes();
                    break;
                case 4: // TransTimeout
                    result.transTimeout = valToken->getUint();
                    break;
                case 5: // InitialCredits
                    result.initialCredits = valToken->getUint();
                    break;
                case 6: // SignedHash
                    result.signedHash = valToken->getBytes();
                    break;
            }
            if (stream.isEndName()) stream.expectEndName();
        } else {
            break;
        }
    }

    return ErrorCode::Success;
}

Result EvalApi::startSyncSession(Session& session,
                                  const StartSessionParams& params,
                                  SyncSessionResult& result) {
    auto r = session.startSession(
        Uid(params.spUid), params.write,
        Uid(params.hostExchangeAuthority),
        params.hostChallenge);

    result.tperSessionNumber = session.tperSessionNumber();
    result.hostSessionNumber = session.hostSessionNumber();
    return r;
}

// ═════════════════���══════════════════════════════════════
//  Authentication
// ═══════��════════════════════════════��═══════════════════

Result EvalApi::authenticate(Session& session, uint64_t authorityUid,
                              const Bytes& credential, RawResult& result) {
    Bytes tokens = MethodCall::buildAuthenticate(Uid(authorityUid), credential, method::authenticateUidFor(session.sscType()));
    return sendMethod(session, tokens, result);
}

Result EvalApi::authenticate(Session& session, uint64_t authorityUid,
                              const std::string& password, RawResult& result) {
    Bytes credential = HashPassword::passwordToBytes(password);
    return authenticate(session, authorityUid, credential, result);
}

// ════════════════════════════════════════════════════════
//  Raw method send
// ════��═══════════════════════════��═══════════════════════

Result EvalApi::sendRawMethod(Session& session, const Bytes& methodTokens,
                               RawResult& result) {
    return sendMethod(session, methodTokens, result);
}

Result EvalApi::sendRawComPacket(Session& session, const Bytes& comPacketData,
                                  Bytes& rawResponse) {
    auto r = session.sendRaw(comPacketData);
    if (r.failed()) return r;
    return session.recvRaw(rawResponse);
}

// ═══════════��════════════════════════════════════════════
//  Static utilities
// ═══════════��════════════════════════════════════════════

Bytes EvalApi::buildMethodCall(uint64_t invokingUid, uint64_t methodUid,
                                const Bytes& paramTokens) {
    MethodCall call{Uid(invokingUid), Uid(methodUid)};
    if (!paramTokens.empty()) {
        call.setParams(paramTokens);
    }
    return call.build();
}

Bytes EvalApi::buildComPacket(Session& session, const Bytes& tokens) {
    PacketBuilder pb;
    pb.setComId(0); // caller should set this properly
    pb.setSessionNumbers(session.tperSessionNumber(), session.hostSessionNumber());
    return pb.buildComPacket(tokens);
}

Result EvalApi::pollRecv(std::shared_ptr<ITransport> transport,
                          uint8_t protocolId, uint16_t comId,
                          Bytes& outBuffer, size_t maxSize,
                          int maxAttempts) {
    // LAW 14: ifRecv must poll until ComPacket.length > 0
    for (int attempt = 0; attempt < maxAttempts; attempt++) {
        outBuffer.clear();
        auto r = transport->ifRecv(protocolId, comId, outBuffer, maxSize);
        if (r.failed()) return r;

        // Check ComPacket.length at offset 16-19 (Rosetta Stone §1)
        if (outBuffer.size() >= 20) {
            uint32_t len = Endian::readBe32(outBuffer.data() + 16);
            if (len > 0) return ErrorCode::Success;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    LIBSED_WARN("pollRecv timeout: protocol=0x%02X comId=0x%04X after %d attempts",
                protocolId, comId, maxAttempts);
    return ErrorCode::TransportTimeout;
}

// ═══════���═════════════════════════════════���══════════════
//  Raw Transport
// ══════════════════════════════���═════════════════════════

Result EvalApi::rawIfSend(std::shared_ptr<ITransport> transport,
                           uint8_t protocolId, uint16_t comId,
                           const Bytes& data) {
    return transport->ifSend(protocolId, comId, ByteSpan(data.data(), data.size()));
}

Result EvalApi::rawIfRecv(std::shared_ptr<ITransport> transport,
                           uint8_t protocolId, uint16_t comId,
                           Bytes& data, size_t maxSize) {
    return transport->ifRecv(protocolId, comId, data, maxSize);
}

// ═════════���═════════════════════════════���════════════════
//  Session State & Control
// ═════════��════════════════════���═════════════════════════

EvalApi::SessionInfo EvalApi::getSessionInfo(const Session& session) {
    SessionInfo info;
    info.active = (session.tperSessionNumber() != 0);
    info.hostSessionNumber = session.hostSessionNumber();
    info.tperSessionNumber = session.tperSessionNumber();
    info.maxComPacketSize  = session.maxComPacketSize();
    return info;
}

void EvalApi::setSessionTimeout(Session& session, uint32_t ms) {
    session.setTimeout(ms);
}

void EvalApi::setSessionMaxComPacket(Session& session, uint32_t size) {
    session.setMaxComPacketSize(size);
}

// ═══════════���════════════════════════���═══════════════════
//  ComID Management
// ═══════════��═════════════════════���════════════════════���═

Result EvalApi::stackReset(std::shared_ptr<ITransport> transport, uint16_t comId) {
    // TCG Core Spec: STACK_RESET via Security Protocol 0x02
    // Request format (Table 202): ComID(2) + Extension(2) + RequestCode(4)
    Bytes request(512, 0);
    Endian::writeBe16(request.data(), comId);        // bytes 0-1: ComID
    Endian::writeBe16(request.data() + 2, 0);        // bytes 2-3: Extended ComID
    Endian::writeBe32(request.data() + 4, 2);        // bytes 4-7: request code = STACK_RESET

    auto r = transport->ifSend(0x02, comId, ByteSpan(request.data(), request.size()));
    if (r.failed()) return r;

    // TCG Core Spec: Stack Reset 후 VERIFY_COMID로 ComID 상태가 idle(0)이 될 때까지 polling
    // Response format (Table 203): ComID(2) + Ext(2) + RequestCode(4) + AvailDataLen(4) + State(4)
    // State: 0=Issued(idle), 1=Associated, 2=Associated+StackResetInProgress
    for (int attempt = 0; attempt < 20; attempt++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        // VERIFY_COMID 요청 전송 (RequestCode = 0)
        Bytes verifyReq(512, 0);
        Endian::writeBe16(verifyReq.data(), comId);
        Endian::writeBe16(verifyReq.data() + 2, 0);
        Endian::writeBe32(verifyReq.data() + 4, 0);  // RequestCode = VERIFY

        r = transport->ifSend(0x02, comId, ByteSpan(verifyReq.data(), verifyReq.size()));
        if (r.failed()) return r;

        Bytes response;
        r = transport->ifRecv(0x02, comId, response, 512);
        if (r.failed()) return r;

        if (response.size() >= 16) {
            uint32_t state = Endian::readBe32(response.data() + 12);  // offset 12: ComID State
            if (state == 0) {
                LIBSED_INFO("Stack reset complete for ComID 0x%04X", comId);
                return ErrorCode::Success;
            }
            LIBSED_DEBUG("StackReset poll: ComID 0x%04X state=%u, retrying", comId, state);
        }
    }

    LIBSED_WARN("StackReset timeout for ComID 0x%04X", comId);
    return ErrorCode::Success;  // 타임아웃이어도 진행 허용
}

Result EvalApi::verifyComId(std::shared_ptr<ITransport> transport,
                             uint16_t comId, bool& active) {
    // TCG Core Spec: VERIFY_COMID via Security Protocol 0x02
    // Request format (Table 202): ComID(2) + Extension(2) + RequestCode(4)
    Bytes request(512, 0);
    Endian::writeBe16(request.data(), comId);
    Endian::writeBe16(request.data() + 2, 0);
    Endian::writeBe32(request.data() + 4, 0);   // RequestCode = VERIFY

    auto r = transport->ifSend(0x02, comId, ByteSpan(request.data(), request.size()));
    if (r.failed()) {
        active = false;
        return r;
    }

    Bytes response;
    r = transport->ifRecv(0x02, comId, response, 512);
    if (r.failed()) {
        active = false;
        return r;
    }

    // Response format (Table 203): ComID(2) + Ext(2) + RequestCode(4) + AvailDataLen(4) + State(4)
    if (response.size() >= 16) {
        uint32_t state = Endian::readBe32(response.data() + 12);  // offset 12: ComID State
        active = (state == 0 || state == 1);  // 0=Issued/idle, 1=Associated
    } else {
        active = false;
    }
    return ErrorCode::Success;
}

// ═══════════��══════════════════════════════════════════════
//  Simplified overloads (RawResult omitted) — core section
// ════════════��═══════════════════���═════════════════════════

Result EvalApi::authenticate(Session& session, uint64_t authorityUid, const Bytes& credential) {
    RawResult raw;
    return authenticate(session, authorityUid, credential, raw);
}

Result EvalApi::authenticate(Session& session, uint64_t authorityUid, const std::string& password) {
    RawResult raw;
    return authenticate(session, authorityUid, password, raw);
}

// ════════════════════════════════════════════════════════
//  Step-by-step sequences
// ═══════════��═════════════���══════════════════════════════

namespace sequence {

Result takeOwnershipStepByStep(
    std::shared_ptr<ITransport> transport,
    uint16_t comId,
    const std::string& newSidPassword,
    StepObserver observer) {

    EvalApi api;
    RawResult raw;
    auto notify = [&](const std::string& step) -> bool {
        if (observer) return observer(step, raw);
        return true; // continue
    };

    // Step 1: Discovery
    DiscoveryInfo info;
    auto r = api.discovery0(transport, info);
    raw.transportError = r.code();
    if (!notify("discovery0")) return r;
    if (r.failed()) return r;

    // Step 2: Properties
    PropertiesResult props;
    r = api.exchangeProperties(transport, comId, props);
    raw = props.raw;
    if (!notify("exchangeProperties")) return r;
    if (r.failed()) return r;

    // Step 3: StartSession to Admin SP (no auth — will read MSID)
    Session msidSession(transport, comId);
    msidSession.setMaxComPacketSize(props.tperMaxComPacketSize);
    StartSessionResult ssr;
    r = api.startSession(msidSession, uid::SP_ADMIN, false, ssr);
    raw = ssr.raw;
    if (!notify("startSession(AdminSP, read)")) return r;
    if (r.failed()) return r;

    // Step 4: Get MSID PIN
    Bytes msidPin;
    r = api.getCPin(msidSession, uid::CPIN_MSID, msidPin, raw);
    if (!notify("getCPin(MSID)")) { api.closeSession(msidSession); return r; }
    if (r.failed()) { api.closeSession(msidSession); return r; }

    // Step 5: Close MSID session
    r = api.closeSession(msidSession);
    if (!notify("closeSession(MSID)")) return r;

    // Step 6: StartSession to Admin SP as SID using MSID credential
    Session sidSession(transport, comId);
    sidSession.setMaxComPacketSize(props.tperMaxComPacketSize);
    r = api.startSessionWithAuth(sidSession, uid::SP_ADMIN, true,
                                  uid::AUTH_SID, msidPin, ssr);
    raw = ssr.raw;
    if (!notify("startSessionWithAuth(AdminSP, SID, MSID)")) return r;
    if (r.failed()) return r;

    // Step 7: Set C_PIN(SID) = new password
    r = api.setCPin(sidSession, uid::CPIN_SID, newSidPassword, raw);
    if (!notify("setCPin(SID, newPassword)")) { api.closeSession(sidSession); return r; }

    // Step 8: Close session
    api.closeSession(sidSession);
    notify("closeSession(SID)");

    return r;
}

Result fullOpalSetupStepByStep(
    std::shared_ptr<ITransport> transport,
    uint16_t comId,
    const std::string& sidPassword,
    const std::string& admin1Password,
    const std::string& user1Password,
    StepObserver observer) {

    EvalApi api;
    RawResult raw;
    auto notify = [&](const std::string& step) -> bool {
        if (observer) return observer(step, raw);
        return true;
    };

    // Step 1: Take ownership
    auto r = takeOwnershipStepByStep(transport, comId, sidPassword, observer);
    if (r.failed()) return r;

    // Step 2: Properties (refresh)
    PropertiesResult props;
    r = api.exchangeProperties(transport, comId, props);
    raw = props.raw;
    if (!notify("exchangeProperties(refresh)")) return r;
    if (r.failed()) return r;

    Bytes sidCred = HashPassword::passwordToBytes(sidPassword);

    // Step 3: StartSession AdminSP as SID
    Session adminSession(transport, comId);
    adminSession.setMaxComPacketSize(props.tperMaxComPacketSize);
    StartSessionResult ssr;
    r = api.startSessionWithAuth(adminSession, uid::SP_ADMIN, true,
                                  uid::AUTH_SID, sidCred, ssr);
    raw = ssr.raw;
    if (!notify("startSessionWithAuth(AdminSP, SID)")) return r;
    if (r.failed()) return r;

    // Step 4: Activate Locking SP
    r = api.activate(adminSession, uid::SP_LOCKING, raw);
    if (!notify("activate(LockingSP)")) { api.closeSession(adminSession); return r; }
    if (r.failed()) { api.closeSession(adminSession); return r; }

    // Step 5: Close Admin session
    api.closeSession(adminSession);
    notify("closeSession(AdminSP)");

    // Step 6: StartSession LockingSP as Admin1 (using SID password initially)
    Session lockSession(transport, comId);
    lockSession.setMaxComPacketSize(props.tperMaxComPacketSize);
    r = api.startSessionWithAuth(lockSession, uid::SP_LOCKING, true,
                                  uid::AUTH_ADMIN1, sidCred, ssr);
    raw = ssr.raw;
    if (!notify("startSessionWithAuth(LockingSP, Admin1)")) return r;
    if (r.failed()) return r;

    // Step 7: Set Admin1 password
    r = api.setCPin(lockSession, uid::CPIN_ADMIN1, admin1Password, raw);
    if (!notify("setCPin(Admin1)")) { api.closeSession(lockSession); return r; }
    if (r.failed()) { api.closeSession(lockSession); return r; }

    // Step 8: Enable User1
    r = api.setAuthorityEnabled(lockSession, uid::AUTH_USER1, true, raw);
    if (!notify("setAuthorityEnabled(User1)")) { api.closeSession(lockSession); return r; }
    if (r.failed()) { api.closeSession(lockSession); return r; }

    // Step 9: Set User1 password
    r = api.setCPin(lockSession, uid::CPIN_USER1, user1Password, raw);
    if (!notify("setCPin(User1)")) { api.closeSession(lockSession); return r; }
    if (r.failed()) { api.closeSession(lockSession); return r; }

    // Step 10: Configure global range lock enable
    r = api.setRange(lockSession, 0, 0, 0, true, true, raw);
    if (!notify("setRange(GlobalRange, lockEnable)")) { api.closeSession(lockSession); return r; }

    // Step 11: Close
    api.closeSession(lockSession);
    notify("closeSession(LockingSP)");

    return r;
}

} // namespace sequence

} // namespace eval
} // namespace libsed
