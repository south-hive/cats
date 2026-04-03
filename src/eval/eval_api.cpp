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
#include "libsed/transport/nvme_transport.h"
#include "libsed/security/hash_password.h"
#include "libsed/core/uid.h"
#include "libsed/core/endian.h"
#include "libsed/core/log.h"
#include <thread>
#include <chrono>

namespace libsed {
namespace eval {

// ════════════════════════════════════════════════════════
//  Internal helper: send method on session, capture raw
// ════════════════════════════════════════════════════════

static Result sendMethod(Session& session, const Bytes& methodTokens, RawResult& raw) {
    raw.rawSendPayload = methodTokens;

    auto r = session.sendMethod(methodTokens, raw.methodResult);
    raw.transportError = r.code();

    if (r.ok() && !raw.methodResult.isSuccess()) {
        raw.protocolError = raw.methodResult.toResult().code();
    }

    return r;
}

// ════════════════════════════════════════════════════════
//  Discovery
// ════════════════════════════════════════════════════════

Result EvalApi::discovery0(std::shared_ptr<ITransport> transport,
                            DiscoveryInfo& info) {
    Discovery disc;
    auto r = disc.discover(transport);
    if (r.ok()) info = disc.buildInfo();
    return r;
}

Result EvalApi::discovery0Raw(std::shared_ptr<ITransport> transport,
                               Bytes& rawResponse) {
    return transport->ifRecv(0x01, 0x0001, rawResponse, 2048);
}

Result EvalApi::discovery0Custom(std::shared_ptr<ITransport> transport,
                                  uint8_t protocolId, uint16_t comId,
                                  Bytes& rawResponse) {
    return transport->ifRecv(protocolId, comId, rawResponse, 2048);
}

// ════════════════════════════════════════════════════════
//  Properties
// ════════════════════════════════════════════════════════

Result EvalApi::exchangeProperties(std::shared_ptr<ITransport> transport,
                                    uint16_t comId,
                                    PropertiesResult& result) {
    // TCG Core Spec: Properties는 세션 전 기본 ComPacket 크기로 교환
    return exchangePropertiesCustom(transport, comId, 1024, 980, 944, result);
}

Result EvalApi::exchangePropertiesCustom(std::shared_ptr<ITransport> transport,
                                          uint16_t comId,
                                          uint32_t maxComPacketSize,
                                          uint32_t maxPacketSize,
                                          uint32_t maxIndTokenSize,
                                          PropertiesResult& result) {
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
    // Properties는 세션 전이므로 TPer 기본 ComPacket 크기 사용
    static constexpr size_t PROPS_RECV_SIZE = 512;
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

    // Decode TPer properties
    auto stream = result.raw.methodResult.resultStream();
    if (stream.isStartList()) stream.skipList(); // skip host echo

    ParamDecoder::TPerProperties tperProps;
    if (stream.isStartList()) {
        stream.expectStartList();
        ParamDecoder::decodeProperties(stream, tperProps);
        stream.expectEndList();
    }

    result.tperMaxComPacketSize = tperProps.maxComPacketSize;
    result.tperMaxPacketSize    = tperProps.maxPacketSize;
    result.tperMaxIndTokenSize  = tperProps.maxIndTokenSize;
    result.tperMaxAggTokenSize  = tperProps.maxAggTokenSize;

    return ErrorCode::Success;
}

// ════════════════════════════════════════════════════════
//  Session lifecycle
// ════════════════════════════════════════════════════════

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

// ════════════════════════════════════════════════════════
//  Authentication
// ════════════════════════════════════════════════════════

Result EvalApi::authenticate(Session& session, uint64_t authorityUid,
                              const Bytes& credential, RawResult& result) {
    Bytes tokens = MethodCall::buildAuthenticate(Uid(authorityUid), credential);
    return sendMethod(session, tokens, result);
}

Result EvalApi::authenticate(Session& session, uint64_t authorityUid,
                              const std::string& password, RawResult& result) {
    Bytes credential = HashPassword::passwordToBytes(password);
    return authenticate(session, authorityUid, credential, result);
}

// ════════════════════════════════════════════════════════
//  Table Get / Set
// ════════════════════════════════════════════════════════

Result EvalApi::tableGet(Session& session, uint64_t objectUid,
                          uint32_t startCol, uint32_t endCol,
                          TableResult& result) {
    CellBlock cb;
    cb.startColumn = startCol;
    cb.endColumn = endCol;
    Bytes tokens = MethodCall::buildGet(Uid(objectUid), cb);
    auto r = sendMethod(session, tokens, result.raw);
    if (r.failed()) return r;

    if (result.raw.methodResult.isSuccess()) {
        auto stream = result.raw.methodResult.resultStream();
        ParamDecoder::ColumnValues values;
        ParamDecoder::decodeGetResponse(stream, values);
        for (auto& [col, tok] : values) {
            result.columns.emplace_back(col, std::move(tok));
        }
    }
    return r;
}

Result EvalApi::tableGetAll(Session& session, uint64_t objectUid,
                             TableResult& result) {
    Bytes tokens = MethodCall::buildGet(Uid(objectUid));
    auto r = sendMethod(session, tokens, result.raw);
    if (r.failed()) return r;

    if (result.raw.methodResult.isSuccess()) {
        auto stream = result.raw.methodResult.resultStream();
        ParamDecoder::ColumnValues values;
        ParamDecoder::decodeGetResponse(stream, values);
        for (auto& [col, tok] : values) {
            result.columns.emplace_back(col, std::move(tok));
        }
    }
    return r;
}

Result EvalApi::tableSet(Session& session, uint64_t objectUid,
                          const std::vector<std::pair<uint32_t, Token>>& columns,
                          RawResult& result) {
    TokenList values;
    for (auto& [col, tok] : columns) {
        values.add(col, tok);
    }
    Bytes tokens = MethodCall::buildSet(Uid(objectUid), values);
    return sendMethod(session, tokens, result);
}

Result EvalApi::tableSetUint(Session& session, uint64_t objectUid,
                              uint32_t column, uint64_t value,
                              RawResult& result) {
    TokenList values;
    values.addUint(column, value);
    Bytes tokens = MethodCall::buildSet(Uid(objectUid), values);
    return sendMethod(session, tokens, result);
}

Result EvalApi::tableSetBool(Session& session, uint64_t objectUid,
                              uint32_t column, bool value,
                              RawResult& result) {
    return tableSetUint(session, objectUid, column, value ? 1 : 0, result);
}

Result EvalApi::tableSetBytes(Session& session, uint64_t objectUid,
                               uint32_t column, const Bytes& value,
                               RawResult& result) {
    TokenList values;
    values.addBytes(column, value);
    Bytes tokens = MethodCall::buildSet(Uid(objectUid), values);
    return sendMethod(session, tokens, result);
}

// ════════════════════════════════════════════════════════
//  C_PIN
// ════════════════════════════════════════════════════════

Result EvalApi::getCPin(Session& session, uint64_t cpinUid,
                         Bytes& pin, RawResult& result) {
    CellBlock cb;
    cb.startColumn = uid::col::PIN;
    cb.endColumn = uid::col::PIN;
    Bytes tokens = MethodCall::buildGet(Uid(cpinUid), cb);
    auto r = sendMethod(session, tokens, result);
    if (r.failed()) return r;

    if (result.methodResult.isSuccess()) {
        auto stream = result.methodResult.resultStream();
        ParamDecoder::ColumnValues values;
        ParamDecoder::decodeGetResponse(stream, values);
        auto it = values.find(uid::col::PIN);
        if (it != values.end()) {
            pin = it->second.getBytes();
        }
    }
    return r;
}

Result EvalApi::setCPin(Session& session, uint64_t cpinUid,
                         const Bytes& newPin, RawResult& result) {
    TokenList values;
    values.addBytes(uid::col::PIN, newPin);
    Bytes tokens = MethodCall::buildSet(Uid(cpinUid), values);
    return sendMethod(session, tokens, result);
}

Result EvalApi::setCPin(Session& session, uint64_t cpinUid,
                         const std::string& newPassword, RawResult& result) {
    Bytes pin = HashPassword::passwordToBytes(newPassword);
    return setCPin(session, cpinUid, pin, result);
}

// ════════════════════════════════════════════════════════
//  MBR
// ════════════════════════════════════════════════════════

Result EvalApi::setMbrEnable(Session& session, bool enable, RawResult& result) {
    return tableSetBool(session, uid::MBRCTRL_SET, uid::col::MBR_ENABLE, enable, result);
}

Result EvalApi::setMbrDone(Session& session, bool done, RawResult& result) {
    return tableSetBool(session, uid::MBRCTRL_SET, uid::col::MBR_DONE, done, result);
}

Result EvalApi::writeMbrData(Session& session, uint32_t offset,
                              const Bytes& data, RawResult& result) {
    // MBR table write with Where = offset
    TokenEncoder enc;
    enc.startList();
    enc.namedUint(0, offset);  // Where
    enc.namedBytes(1, data);   // Values
    enc.endList();

    // Build Set call on MBR table
    Bytes tokens = buildMethodCall(uid::TABLE_MBR, method::SET, enc.data());
    return sendMethod(session, tokens, result);
}

Result EvalApi::readMbrData(Session& session, uint32_t offset, uint32_t length,
                             Bytes& data, RawResult& result) {
    CellBlock cb;
    cb.startRow = offset;
    cb.endRow = offset + length - 1;
    Bytes tokens = MethodCall::buildGet(Uid(uid::TABLE_MBR), cb);
    auto r = sendMethod(session, tokens, result);
    if (r.ok() && result.methodResult.isSuccess()) {
        auto stream = result.methodResult.resultStream();
        // Extract raw bytes from response
        if (stream.hasMore() && stream.peek()->isByteSequence) {
            data = stream.next()->getBytes();
        }
    }
    return r;
}

// ════════════════════════════════════════════════════════
//  Locking Range
// ════════════════════════════════════════════════════════

Result EvalApi::setRange(Session& session, uint32_t rangeId,
                          uint64_t rangeStart, uint64_t rangeLength,
                          bool readLockEnabled, bool writeLockEnabled,
                          RawResult& result) {
    uint64_t rangeUid = uid::makeLockingRangeUid(rangeId).toUint64();

    TokenList values;
    values.addUint(uid::col::RANGE_START, rangeStart);
    values.addUint(uid::col::RANGE_LENGTH, rangeLength);
    values.addUint(uid::col::READ_LOCK_EN, readLockEnabled ? 1 : 0);
    values.addUint(uid::col::WRITE_LOCK_EN, writeLockEnabled ? 1 : 0);

    Bytes tokens = MethodCall::buildSet(Uid(rangeUid), values);
    return sendMethod(session, tokens, result);
}

Result EvalApi::setRangeLock(Session& session, uint32_t rangeId,
                              bool readLocked, bool writeLocked,
                              RawResult& result) {
    uint64_t rangeUid = uid::makeLockingRangeUid(rangeId).toUint64();

    TokenList values;
    values.addUint(uid::col::READ_LOCKED, readLocked ? 1 : 0);
    values.addUint(uid::col::WRITE_LOCKED, writeLocked ? 1 : 0);

    Bytes tokens = MethodCall::buildSet(Uid(rangeUid), values);
    return sendMethod(session, tokens, result);
}

Result EvalApi::getRangeInfo(Session& session, uint32_t rangeId,
                              LockingRangeInfo& info, RawResult& result) {
    uint64_t rangeUid = uid::makeLockingRangeUid(rangeId).toUint64();
    Bytes tokens = MethodCall::buildGet(Uid(rangeUid));
    auto r = sendMethod(session, tokens, result);
    if (r.failed()) return r;

    if (result.methodResult.isSuccess()) {
        auto stream = result.methodResult.resultStream();
        ParamDecoder::ColumnValues values;
        ParamDecoder::decodeGetResponse(stream, values);
        info.rangeId = rangeId;
        ParamDecoder::decodeLockingRange(values, info);
    }
    return r;
}

// ════════════════════════════════════════════════════════
//  Authority / ACE
// ════════════════════════════════════════════════════════

Result EvalApi::setAuthorityEnabled(Session& session, uint64_t authorityUid,
                                     bool enabled, RawResult& result) {
    return tableSetBool(session, authorityUid, uid::col::AUTH_ENABLED, enabled, result);
}

Result EvalApi::addAuthorityToAce(Session& session, uint64_t aceUid,
                                   uint64_t authorityUid, RawResult& result) {
    // Read current ACE BooleanExpr, append authority, write back
    // This is a simplified version; full ACE manipulation requires
    // parsing the boolean expression token stream
    TableResult getResult;
    auto r = tableGetAll(session, aceUid, getResult);
    if (r.failed()) return r;

    // For now: set the ACE to reference the given authority
    // A full implementation would parse and modify the BooleanExpr
    TokenList values;
    // Column 3 = BooleanExpr in ACE table
    TokenEncoder boolExpr;
    boolExpr.startList();
    boolExpr.startName();
    boolExpr.encodeUid(authorityUid);
    boolExpr.endName();
    boolExpr.endList();
    values.addBytes(3, boolExpr.data());

    Bytes tokens = MethodCall::buildSet(Uid(aceUid), values);
    return sendMethod(session, tokens, result);
}

Result EvalApi::getAceInfo(Session& session, uint64_t aceUid,
                            AceInfo& info, RawResult& result) {
    TableResult getResult;
    auto r = tableGetAll(session, aceUid, getResult);
    result = getResult.raw;
    if (r.failed()) return r;

    info.aceUid = Uid(aceUid);
    for (auto& [col, tok] : getResult.columns) {
        if (col == 3 && tok.isByteSequence) {
            info.booleanExpr = tok.getBytes();
        }
    }
    return r;
}

// ════════════════════════════════════════════════════════
//  SP lifecycle
// ════════════════════════════════════════════════════════

Result EvalApi::activate(Session& session, uint64_t spUid, RawResult& result) {
    Bytes tokens = MethodCall::buildActivate(Uid(spUid));
    return sendMethod(session, tokens, result);
}

Result EvalApi::revertSP(Session& session, uint64_t spUid, RawResult& result) {
    Bytes tokens = MethodCall::buildRevertSP(Uid(spUid));
    return sendMethod(session, tokens, result);
}

// ════════════════════════════════════════════════════════
//  Crypto / Key
// ════════════════════════════════════════════════════════

Result EvalApi::genKey(Session& session, uint64_t objectUid, RawResult& result) {
    Bytes tokens = MethodCall::buildGenKey(Uid(objectUid));
    return sendMethod(session, tokens, result);
}

Result EvalApi::getRandom(Session& session, uint32_t count,
                           Bytes& randomData, RawResult& result) {
    TokenEncoder paramEnc;
    paramEnc.encodeUint(count);

    Bytes tokens = buildMethodCall(uid::THIS_SP, method::RANDOM, paramEnc.data());
    auto r = sendMethod(session, tokens, result);
    if (r.ok() && result.methodResult.isSuccess()) {
        auto stream = result.methodResult.resultStream();
        if (stream.hasMore() && stream.peek()->isByteSequence) {
            randomData = stream.next()->getBytes();
        }
    }
    return r;
}

Result EvalApi::erase(Session& session, uint64_t objectUid, RawResult& result) {
    Bytes tokens = MethodCall::buildErase(Uid(objectUid));
    return sendMethod(session, tokens, result);
}

// ════════════════════════════════════════════════════════
//  Raw method send
// ════════════════════════════════════════════════════════

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

// ════════════════════════════════════════════════════════
//  Step-by-step sequences
// ════════════════════════════════════════════════════════

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

// ════════════════════════════════════════════════════════
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

    // StartSession_OPT fields
    if (!params.hostChallenge.empty()) {
        paramEnc.startName();
        paramEnc.encodeUint(0);  // HostChallenge keyword
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

// ════════════════════════════════════════════════════════
//  MBR Control NSID=1
// ════════════════════════════════════════════════════════

Result EvalApi::setMbrControlNsidOne(Session& session, RawResult& result) {
    // Set MBR Control table: Enable=1, Done=0, then Done=1 for NSID=1
    auto r = setMbrEnable(session, true, result);
    if (r.failed()) return r;
    return setMbrDone(session, true, result);
}

// ════════════════════════════════════════════════════════
//  TC Library Util: getTcgOption
// ════════════════════════════════════════════════════════

Result EvalApi::getTcgOption(std::shared_ptr<ITransport> transport,
                              TcgOption& option) {
    Discovery disc;
    auto r = disc.discover(transport);
    if (r.failed()) return r;

    option.sscType = disc.detectSsc();
    option.baseComId = disc.baseComId();

    // Locking feature
    auto* locking = dynamic_cast<const LockingFeature*>(disc.findFeature(0x0002));
    if (locking) {
        option.lockingSupported = locking->lockingSupported;
        option.lockingEnabled   = locking->lockingEnabled;
        option.locked           = locking->locked;
        option.mediaEncryption  = locking->mediaEncryption;
        option.mbrSupported     = true;
        option.mbrEnabled       = locking->mbrEnabled;
        option.mbrDone          = locking->mbrDone;
    }

    // SSC-specific fields
    auto* opalV2 = dynamic_cast<const OpalV2Feature*>(disc.findFeature(0x0203));
    if (opalV2) {
        option.numComIds            = opalV2->numComIds;
        option.maxLockingAdmins     = opalV2->numLockingSPAdminsSupported;
        option.maxLockingUsers      = opalV2->numLockingSPUsersSupported;
        option.initialPinIndicator  = opalV2->initialPinIndicator;
        option.revertedPinIndicator = opalV2->revertedPinIndicator;
    }

    auto* opalV1 = dynamic_cast<const OpalV1Feature*>(disc.findFeature(0x0200));
    if (opalV1 && !opalV2) {
        option.numComIds = opalV1->numComIds;
    }

    auto* enterprise = dynamic_cast<const EnterpriseFeature*>(disc.findFeature(0x0100));
    if (enterprise) {
        option.numComIds = enterprise->numComIds;
    }

    auto* pyriteV2 = dynamic_cast<const PyriteV2Feature*>(disc.findFeature(0x0303));
    if (pyriteV2) {
        option.numComIds            = pyriteV2->numComIds;
        option.initialPinIndicator  = pyriteV2->initialPinIndicator;
        option.revertedPinIndicator = pyriteV2->revertedPinIndicator;
    }

    return ErrorCode::Success;
}

// ════════════════════════════════════════════════════════
//  TC Library Util: getSecurityStatus
// ════════════════════════════════════════════════════════

Result EvalApi::getSecurityStatus(std::shared_ptr<ITransport> transport,
                                   SecurityStatus& status) {
    Discovery disc;
    auto r = disc.discover(transport);
    if (r.failed()) return r;

    status.tperPresent       = disc.hasTPerFeature();
    status.lockingPresent    = disc.hasLockingFeature();
    status.geometryPresent   = disc.hasGeometryFeature();
    status.opalV1Present     = disc.hasOpalV1Feature();
    status.opalV2Present     = disc.hasOpalV2Feature();
    status.enterprisePresent = disc.hasEnterpriseFeature();
    status.pyriteV1Present   = disc.hasPyriteV1Feature();
    status.pyriteV2Present   = disc.hasPyriteV2Feature();
    status.primarySsc        = disc.detectSsc();

    return ErrorCode::Success;
}

// ════════════════════════════════════════════════════════
//  TC Library Util: getSecurityFeature / getAllSecurityFeatures
// ════════════════════════════════════════════════════════

static SecurityFeatureInfo featureToInfo(const FeatureDescriptor& fd) {
    SecurityFeatureInfo info;
    info.featureCode = fd.featureCode();
    info.featureName = fd.name();
    info.version     = fd.version();
    info.dataLength  = fd.dataLength();

    // Extract SSC-specific fields
    if (auto* opal = dynamic_cast<const OpalV2Feature*>(&fd)) {
        info.baseComId    = opal->baseComId;
        info.numComIds    = opal->numComIds;
        info.rangeCrossing = opal->rangeCrossing;
    } else if (auto* opal1 = dynamic_cast<const OpalV1Feature*>(&fd)) {
        info.baseComId    = opal1->baseComId;
        info.numComIds    = opal1->numComIds;
        info.rangeCrossing = opal1->rangeCrossing;
    } else if (auto* ent = dynamic_cast<const EnterpriseFeature*>(&fd)) {
        info.baseComId    = ent->baseComId;
        info.numComIds    = ent->numComIds;
        info.rangeCrossing = ent->rangeCrossing;
    } else if (auto* pyr2 = dynamic_cast<const PyriteV2Feature*>(&fd)) {
        info.baseComId    = pyr2->baseComId;
        info.numComIds    = pyr2->numComIds;
    } else if (auto* pyr1 = dynamic_cast<const PyriteV1Feature*>(&fd)) {
        info.baseComId    = pyr1->baseComId;
        info.numComIds    = pyr1->numComIds;
    }

    if (auto* lock = dynamic_cast<const LockingFeature*>(&fd)) {
        info.lockingSupported = lock->lockingSupported;
        info.lockingEnabled   = lock->lockingEnabled;
        info.locked           = lock->locked;
        info.mbrEnabled       = lock->mbrEnabled;
        info.mbrDone          = lock->mbrDone;
    }

    if (auto* unk = dynamic_cast<const UnknownFeature*>(&fd)) {
        info.rawFeatureData = unk->rawData;
    }

    return info;
}

Result EvalApi::getSecurityFeature(std::shared_ptr<ITransport> transport,
                                    uint16_t featureCode,
                                    SecurityFeatureInfo& info) {
    Discovery disc;
    auto r = disc.discover(transport);
    if (r.failed()) return r;

    auto* fd = disc.findFeature(featureCode);
    if (!fd) return ErrorCode::FeatureNotFound;

    info = featureToInfo(*fd);
    return ErrorCode::Success;
}

Result EvalApi::getAllSecurityFeatures(std::shared_ptr<ITransport> transport,
                                       std::vector<SecurityFeatureInfo>& features) {
    Discovery disc;
    auto r = disc.discover(transport);
    if (r.failed()) return r;

    features.clear();
    for (auto& fd : disc.features()) {
        features.push_back(featureToInfo(*fd));
    }
    return ErrorCode::Success;
}

// ════════════════════════════════════════════════════════
//  TC Library Util: getLockingInfo
// ════════════════════════════════════════════════════════

Result EvalApi::getLockingInfo(Session& session, uint32_t rangeId,
                                LockingInfo& info, RawResult& result) {
    uint64_t rangeUid = uid::makeLockingRangeUid(rangeId).toUint64();
    Bytes tokens = MethodCall::buildGet(Uid(rangeUid));
    auto r = sendMethod(session, tokens, result);
    if (r.failed()) return r;

    if (result.methodResult.isSuccess()) {
        auto stream = result.methodResult.resultStream();
        ParamDecoder::ColumnValues values;
        ParamDecoder::decodeGetResponse(stream, values);

        info.rangeId = rangeId;
        auto getU = [&](uint32_t col) -> uint64_t {
            auto it = values.find(col);
            return (it != values.end()) ? it->second.getUint() : 0;
        };
        auto getB = [&](uint32_t col) -> bool {
            return getU(col) != 0;
        };

        info.rangeStart       = getU(uid::col::RANGE_START);
        info.rangeLength      = getU(uid::col::RANGE_LENGTH);
        info.readLockEnabled  = getB(uid::col::READ_LOCK_EN);
        info.writeLockEnabled = getB(uid::col::WRITE_LOCK_EN);
        info.readLocked       = getB(uid::col::READ_LOCKED);
        info.writeLocked      = getB(uid::col::WRITE_LOCKED);
        info.activeKey        = getU(uid::col::ACTIVE_KEY);
    }
    return r;
}

Result EvalApi::getAllLockingInfo(Session& session,
                                   std::vector<LockingInfo>& ranges,
                                   uint32_t maxRanges,
                                   RawResult& result) {
    ranges.clear();

    // Range 0 = Global Range
    for (uint32_t i = 0; i <= maxRanges; i++) {
        LockingInfo info;
        auto r = getLockingInfo(session, i, info, result);
        if (r.failed()) {
            // If we fail reading a range, we've likely hit the end
            if (i > 0) break;
            return r;
        }
        ranges.push_back(info);
    }
    return ErrorCode::Success;
}

// ════════════════════════════════════════════════════════
//  TC Library Util: getByteTableInfo
// ════════════════════════════════════════════════════════

Result EvalApi::getByteTableInfo(Session& session, ByteTableInfo& info,
                                  RawResult& result) {
    info.tableUid = uid::TABLE_DATASTORE;

    // Read DataStore table descriptor to get size info
    TableResult tr;
    auto r = tableGetAll(session, uid::TABLE_DATASTORE, tr);
    result = tr.raw;
    if (r.failed()) return r;

    for (auto& [col, tok] : tr.columns) {
        if (!tok.isByteSequence && !tok.isSigned) {
            // Heuristic: column values from table descriptor
            switch (col) {
                case 3: info.maxSize  = static_cast<uint32_t>(tok.getUint()); break;
                case 4: info.usedSize = static_cast<uint32_t>(tok.getUint()); break;
            }
        }
    }
    return ErrorCode::Success;
}

// ════════════════════════════════════════════════════════
//  TC Library Util: TcgWrite / TcgRead / TcgCompare
// ════════════════════════════════════════════════════════

Result EvalApi::tcgWrite(Session& session, uint64_t tableUid,
                          uint32_t offset, const Bytes& data,
                          RawResult& result) {
    // Build Set method with Where=offset, Values=data
    TokenEncoder enc;
    enc.startList();
    enc.namedUint(0, offset);    // Where
    enc.namedBytes(1, data);     // Values
    enc.endList();

    Bytes tokens = buildMethodCall(tableUid, method::SET, enc.data());
    return sendMethod(session, tokens, result);
}

Result EvalApi::tcgRead(Session& session, uint64_t tableUid,
                         uint32_t offset, uint32_t length,
                         DataOpResult& result) {
    CellBlock cb;
    cb.startRow = offset;
    cb.endRow = offset + length - 1;

    Bytes tokens = MethodCall::buildGet(Uid(tableUid), cb);
    auto r = sendMethod(session, tokens, result.raw);
    if (r.ok() && result.raw.methodResult.isSuccess()) {
        auto stream = result.raw.methodResult.resultStream();
        if (stream.hasMore() && stream.peek()->isByteSequence) {
            result.data = stream.next()->getBytes();
        }
    }
    return r;
}

Result EvalApi::tcgCompare(Session& session, uint64_t tableUid,
                            uint32_t offset, const Bytes& expected,
                            DataOpResult& result) {
    // Write
    RawResult writeRaw;
    auto r = tcgWrite(session, tableUid, offset, expected, writeRaw);
    if (r.failed()) { result.raw = writeRaw; return r; }

    // Read back
    r = tcgRead(session, tableUid, offset,
                static_cast<uint32_t>(expected.size()), result);
    if (r.failed()) return r;

    // Compare
    result.compareMatch = (result.data == expected);
    return ErrorCode::Success;
}

Result EvalApi::tcgWriteDataStore(Session& session, uint32_t offset,
                                   const Bytes& data, RawResult& result) {
    return tcgWrite(session, uid::TABLE_DATASTORE, offset, data, result);
}

Result EvalApi::tcgReadDataStore(Session& session, uint32_t offset,
                                  uint32_t length, DataOpResult& result) {
    return tcgRead(session, uid::TABLE_DATASTORE, offset, length, result);
}

// ════════════════════════════════════════════════════════
//  Table Enumeration
// ════════════════════════════════════════════════════════

Result EvalApi::tableNext(Session& session, uint64_t tableUid,
                           uint64_t startRowUid, std::vector<Uid>& rows,
                           uint32_t count, RawResult& result) {
    TokenEncoder paramEnc;
    if (startRowUid != 0) {
        paramEnc.startName();
        paramEnc.encodeUint(0); // Where
        paramEnc.encodeUid(startRowUid);
        paramEnc.endName();
    }
    if (count > 0) {
        paramEnc.startName();
        paramEnc.encodeUint(1); // Count
        paramEnc.encodeUint(count);
        paramEnc.endName();
    }

    Bytes tokens = buildMethodCall(tableUid, method::NEXT, paramEnc.data());
    auto r = sendMethod(session, tokens, result);
    if (r.ok() && result.methodResult.isSuccess()) {
        auto stream = result.methodResult.resultStream();
        while (stream.hasMore()) {
            const auto* tok = stream.peek();
            if (tok->isByteSequence && tok->getBytes().size() == 8) {
                Bytes uidBytes = stream.next()->getBytes();
                rows.push_back(Uid(uidBytes));
            } else {
                break;
            }
        }
    }
    return r;
}

Result EvalApi::tableGetColumn(Session& session, uint64_t objectUid,
                                uint32_t column, Token& value,
                                RawResult& result) {
    TableResult tr;
    auto r = tableGet(session, objectUid, column, column, tr);
    result = tr.raw;
    if (r.ok()) {
        for (auto& [col, tok] : tr.columns) {
            if (col == column) {
                value = tok;
                return r;
            }
        }
    }
    return r;
}

// ════════════════════════════════════════════════════════
//  User / Authority Management
// ════════════════════════════════════════════════════════

Result EvalApi::enableUser(Session& session, uint32_t userId, RawResult& result) {
    uint64_t authUid = uid::makeUserUid(userId).toUint64();
    return setAuthorityEnabled(session, authUid, true, result);
}

Result EvalApi::disableUser(Session& session, uint32_t userId, RawResult& result) {
    uint64_t authUid = uid::makeUserUid(userId).toUint64();
    return setAuthorityEnabled(session, authUid, false, result);
}

Result EvalApi::setUserPassword(Session& session, uint32_t userId,
                                 const Bytes& newPin, RawResult& result) {
    uint64_t cpinUid = uid::makeCpinUserUid(userId).toUint64();
    return setCPin(session, cpinUid, newPin, result);
}

Result EvalApi::setUserPassword(Session& session, uint32_t userId,
                                 const std::string& newPassword, RawResult& result) {
    Bytes pin = HashPassword::passwordToBytes(newPassword);
    return setUserPassword(session, userId, pin, result);
}

Result EvalApi::isUserEnabled(Session& session, uint32_t userId,
                               bool& enabled, RawResult& result) {
    uint64_t authUid = uid::makeUserUid(userId).toUint64();
    Token val;
    auto r = tableGetColumn(session, authUid, uid::col::AUTH_ENABLED, val, result);
    if (r.ok()) {
        enabled = (val.getUint() != 0);
    }
    return r;
}

Result EvalApi::setAdmin1Password(Session& session, const Bytes& newPin,
                                   RawResult& result) {
    return setCPin(session, uid::CPIN_ADMIN1, newPin, result);
}

Result EvalApi::setAdmin1Password(Session& session, const std::string& newPassword,
                                   RawResult& result) {
    Bytes pin = HashPassword::passwordToBytes(newPassword);
    return setAdmin1Password(session, pin, result);
}

Result EvalApi::assignUserToRange(Session& session, uint32_t userId,
                                   uint32_t rangeId, RawResult& result) {
    // Modify ACE for ReadLocked and WriteLocked on the range to include this user
    // Build BooleanExpr: { User_N OR Admin1 }
    uint64_t userAuthUid = uid::makeUserUid(userId).toUint64();
    uint64_t admin1Uid = uid::AUTH_ADMIN1;

    TokenEncoder boolExpr;
    boolExpr.startList();
    boolExpr.startName();
    boolExpr.encodeUid(Uid(userAuthUid));
    boolExpr.encodeUid(Uid(userAuthUid));
    boolExpr.endName();
    boolExpr.startName();
    boolExpr.encodeUid(Uid(admin1Uid));
    boolExpr.encodeUid(Uid(admin1Uid));
    boolExpr.endName();
    // OR boolean
    boolExpr.encodeUint(0); // BooleanOR
    boolExpr.endList();

    // Set read ACE
    uint64_t rdAce = uid::makeAceLockingRangeSetRdLocked(rangeId).toUint64();
    TokenList rdValues;
    rdValues.addBytes(uid::col::ACE_BOOLEAN_EXPR, boolExpr.data());
    Bytes rdTokens = MethodCall::buildSet(Uid(rdAce), rdValues);
    auto r = sendMethod(session, rdTokens, result);
    if (r.failed()) return r;

    // Set write ACE
    uint64_t wrAce = uid::makeAceLockingRangeSetWrLocked(rangeId).toUint64();
    TokenList wrValues;
    wrValues.addBytes(uid::col::ACE_BOOLEAN_EXPR, boolExpr.data());
    Bytes wrTokens = MethodCall::buildSet(Uid(wrAce), wrValues);
    return sendMethod(session, wrTokens, result);
}

// ════════════════════════════════════════════════════════
//  SP Lifecycle Extended
// ════════════════════════════════════════════════════════

Result EvalApi::getSpLifecycle(Session& session, uint64_t spUid,
                                uint8_t& lifecycle, RawResult& result) {
    Token val;
    auto r = tableGetColumn(session, spUid, uid::col::LIFECYCLE, val, result);
    if (r.ok()) {
        lifecycle = static_cast<uint8_t>(val.getUint());
    }
    return r;
}

Result EvalApi::psidRevert(Session& session, RawResult& result) {
    return revertSP(session, uid::SP_ADMIN, result);
}

// ════════════════════════════════════════════════════════
//  MBR Extended
// ════════════════════════════════════════════════════════

Result EvalApi::getMbrStatus(Session& session, bool& mbrEnabled,
                              bool& mbrDone, RawResult& result) {
    TableResult tr;
    auto r = tableGetAll(session, uid::MBRCTRL_SET, tr);
    result = tr.raw;
    if (r.ok()) {
        for (auto& [col, tok] : tr.columns) {
            if (col == uid::col::MBR_ENABLE) mbrEnabled = (tok.getUint() != 0);
            if (col == uid::col::MBR_DONE) mbrDone = (tok.getUint() != 0);
        }
    }
    return r;
}

// ════════════════════════════════════════════════════════
//  Locking Range Extended
// ════════════════════════════════════════════════════════

Result EvalApi::setLockOnReset(Session& session, uint32_t rangeId,
                                bool lockOnReset, RawResult& result) {
    uint64_t rangeUid = uid::makeLockingRangeUid(rangeId).toUint64();
    return tableSetBool(session, rangeUid, uid::col::LOCK_ON_RESET, lockOnReset, result);
}

Result EvalApi::cryptoErase(Session& session, uint32_t rangeId, RawResult& result) {
    uint64_t rangeUid = uid::makeLockingRangeUid(rangeId).toUint64();
    return genKey(session, rangeUid, result);
}

// ════════════════════════════════════════════════════════
//  Enterprise SSC
// ════════════════════════════════════════════════════════

Result EvalApi::configureBand(Session& session, uint32_t bandId,
                               uint64_t bandStart, uint64_t bandLength,
                               bool readLockEnabled, bool writeLockEnabled,
                               RawResult& result) {
    return setRange(session, bandId, bandStart, bandLength,
                    readLockEnabled, writeLockEnabled, result);
}

Result EvalApi::lockBand(Session& session, uint32_t bandId, RawResult& result) {
    return setRangeLock(session, bandId, true, true, result);
}

Result EvalApi::unlockBand(Session& session, uint32_t bandId, RawResult& result) {
    return setRangeLock(session, bandId, false, false, result);
}

Result EvalApi::getBandInfo(Session& session, uint32_t bandId,
                             LockingInfo& info, RawResult& result) {
    return getLockingInfo(session, bandId, info, result);
}

Result EvalApi::setBandMasterPassword(Session& session, uint32_t bandId,
                                       const Bytes& newPin, RawResult& result) {
    uint64_t cpinUid = uid::makeCpinBandMasterUid(bandId).toUint64();
    return setCPin(session, cpinUid, newPin, result);
}

Result EvalApi::setEraseMasterPassword(Session& session, const Bytes& newPin,
                                        RawResult& result) {
    return setCPin(session, uid::CPIN_ERASEMASTER, newPin, result);
}

Result EvalApi::eraseBand(Session& session, uint32_t bandId, RawResult& result) {
    uint64_t rangeUid = uid::makeLockingRangeUid(bandId).toUint64();
    return erase(session, rangeUid, result);
}

// ════════════════════════════════════════════════════════
//  Raw Transport
// ════════════════════════════════════════════════════════

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

// ════════════════════════════════════════════════════════
//  Session State & Control
// ════════════════════════════════════════════════════════

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

// ════════════════════════════════════════════════════════
//  ComID Management
// ════════════════════════════════════════════════════════

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

// ════════════════════════════════════════════════════════
//  Password / Hash Utilities
// ════════════════════════════════════════════════════════

Bytes EvalApi::hashPassword(const std::string& password) {
    return HashPassword::passwordToBytes(password);
}

Bytes EvalApi::hashPasswordPbkdf2(const std::string& password,
                                   const Bytes& salt,
                                   uint32_t iterations) {
    return HashPassword::pbkdf2Sha256(password, salt, iterations);
}

Result EvalApi::getCPinTriesRemaining(Session& session, uint64_t cpinUid,
                                       uint32_t& remaining, RawResult& result) {
    Token val;
    auto r = tableGetColumn(session, cpinUid, uid::col::PIN_TRIES_REMAINING, val, result);
    if (r.ok()) {
        remaining = static_cast<uint32_t>(val.getUint());
    }
    return r;
}

// ════════════════════════════════════════════════════════
//  Table Row Management
// ════════════════════════════════════════════════════════

Result EvalApi::tableCreateRow(Session& session, uint64_t tableUid, RawResult& result) {
    Bytes tokens = buildMethodCall(tableUid, method::CREATE_ROW, {});
    return sendMethod(session, tokens, result);
}

Result EvalApi::tableDeleteRow(Session& session, uint64_t rowUid, RawResult& result) {
    Bytes tokens = buildMethodCall(rowUid, method::DELETE_ROW, {});
    return sendMethod(session, tokens, result);
}

// ════════════════════════════════════════════════════════
//  Access Control (GetACL / Assign / Remove)
// ════════════════════════════════════════════════════════

Result EvalApi::getAcl(Session& session, uint64_t invokingUid,
                        uint64_t methodUid, AclInfo& info) {
    TokenEncoder paramEnc;
    paramEnc.encodeUid(invokingUid);
    paramEnc.encodeUid(methodUid);

    Bytes tokens = buildMethodCall(invokingUid, method::GETACL, paramEnc.data());
    auto r = sendMethod(session, tokens, info.raw);
    if (r.ok() && info.raw.methodResult.isSuccess()) {
        auto stream = info.raw.methodResult.resultStream();
        while (stream.hasMore()) {
            const auto* tok = stream.peek();
            if (tok->isByteSequence && tok->getBytes().size() == 8) {
                info.aceList.push_back(Uid(stream.next()->getBytes()));
            } else {
                break;
            }
        }
    }
    return r;
}

Result EvalApi::tableAssign(Session& session, uint64_t tableUid,
                             uint64_t rowUid, uint64_t authorityUid,
                             RawResult& result) {
    TokenEncoder paramEnc;
    paramEnc.encodeUid(rowUid);
    paramEnc.encodeUid(authorityUid);

    Bytes tokens = buildMethodCall(tableUid, method::ASSIGN, paramEnc.data());
    return sendMethod(session, tokens, result);
}

Result EvalApi::tableRemove(Session& session, uint64_t tableUid,
                             uint64_t rowUid, uint64_t authorityUid,
                             RawResult& result) {
    TokenEncoder paramEnc;
    paramEnc.encodeUid(rowUid);
    paramEnc.encodeUid(authorityUid);

    Bytes tokens = buildMethodCall(tableUid, method::REMOVE, paramEnc.data());
    return sendMethod(session, tokens, result);
}

// ════════════════════════════════════════════════════════
//  Convenience Single-Type Column Reads
// ════════════════════════════════════════════════════════

Result EvalApi::tableGetUint(Session& session, uint64_t objectUid,
                              uint32_t column, uint64_t& value,
                              RawResult& result) {
    Token val;
    auto r = tableGetColumn(session, objectUid, column, val, result);
    if (r.ok()) value = val.getUint();
    return r;
}

Result EvalApi::tableGetBytes(Session& session, uint64_t objectUid,
                               uint32_t column, Bytes& value,
                               RawResult& result) {
    Token val;
    auto r = tableGetColumn(session, objectUid, column, val, result);
    if (r.ok()) value = val.getBytes();
    return r;
}

Result EvalApi::tableGetBool(Session& session, uint64_t objectUid,
                              uint32_t column, bool& value,
                              RawResult& result) {
    uint64_t v = 0;
    auto r = tableGetUint(session, objectUid, column, v, result);
    if (r.ok()) value = (v != 0);
    return r;
}

// ════════════════════════════════════════════════════════
//  Multi-Column Set
// ════════════════════════════════════════════════════════

Result EvalApi::tableSetMultiUint(Session& session, uint64_t objectUid,
                                   const std::vector<std::pair<uint32_t, uint64_t>>& columns,
                                   RawResult& result) {
    TokenList values;
    for (auto& [col, val] : columns) {
        values.addUint(col, val);
    }
    Bytes tokens = MethodCall::buildSet(Uid(objectUid), values);
    return sendMethod(session, tokens, result);
}

// ════════════════════════════════════════════════════════
//  Revert (object level)
// ════════════════════════════════════════════════════════

Result EvalApi::revert(Session& session, uint64_t objectUid, RawResult& result) {
    Bytes tokens = buildMethodCall(objectUid, method::REVERT, {});
    return sendMethod(session, tokens, result);
}

// ════════════════════════════════════════════════════════
//  Clock
// ════════════════════════════════════════════════════════

Result EvalApi::getClock(Session& session, uint64_t& clockValue, RawResult& result) {
    Bytes tokens = buildMethodCall(uid::THIS_SP, method::GET_CLOCK, {});
    auto r = sendMethod(session, tokens, result);
    if (r.ok() && result.methodResult.isSuccess()) {
        auto stream = result.methodResult.resultStream();
        if (stream.hasMore()) {
            clockValue = stream.next()->getUint();
        }
    }
    return r;
}

// ════════════════════════════════════════════════════════
//  Authority Verification
// ════════════════════════════════════════════════════════

Result EvalApi::verifyAuthority(std::shared_ptr<ITransport> transport,
                                 uint16_t comId, uint64_t spUid,
                                 uint64_t authorityUid, const Bytes& credential) {
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = startSessionWithAuth(session, spUid, false, authorityUid, credential, ssr);
    if (r.ok()) closeSession(session);
    return r;
}

Result EvalApi::verifyAuthority(std::shared_ptr<ITransport> transport,
                                 uint16_t comId, uint64_t spUid,
                                 uint64_t authorityUid, const std::string& password) {
    Bytes cred = HashPassword::passwordToBytes(password);
    return verifyAuthority(transport, comId, spUid, authorityUid, cred);
}

// ════════════════════════════════════════════════════════
//  DataStore with Table Number
// ════════════════════════════════════════════════════════

Result EvalApi::tcgWriteDataStoreN(Session& session, uint32_t tableNumber,
                                    uint32_t offset, const Bytes& data,
                                    RawResult& result) {
    uint64_t dsUid = uid::TABLE_DATASTORE + tableNumber + 1;
    return tcgWrite(session, dsUid, offset, data, result);
}

Result EvalApi::tcgReadDataStoreN(Session& session, uint32_t tableNumber,
                                   uint32_t offset, uint32_t length,
                                   DataOpResult& result) {
    uint64_t dsUid = uid::TABLE_DATASTORE + tableNumber + 1;
    return tcgRead(session, dsUid, offset, length, result);
}

// ════════════════════════════════════════════════════════
//  Enterprise Band Extended
// ════════════════════════════════════════════════════════

Result EvalApi::setBandLockOnReset(Session& session, uint32_t bandId,
                                    bool lockOnReset, RawResult& result) {
    uint64_t bandUid = uid::makeLockingRangeUid(bandId).toUint64();
    return tableSetBool(session, bandUid, uid::col::LOCK_ON_RESET, lockOnReset, result);
}

Result EvalApi::eraseAllBands(Session& session, uint32_t maxBands, RawResult& result) {
    Result r;
    for (uint32_t i = 0; i < maxBands; i++) {
        r = eraseBand(session, i, result);
        if (r.failed()) return r;
    }
    return r;
}

// ════════════════════════════════════════════════════════
//  Active Key
// ════════════════════════════════════════════════════════

Result EvalApi::getActiveKey(Session& session, uint32_t rangeId,
                              Uid& keyUid, RawResult& result) {
    uint64_t rangeUid = uid::makeLockingRangeUid(rangeId).toUint64();
    Token val;
    auto r = tableGetColumn(session, rangeUid, uid::col::ACTIVE_KEY, val, result);
    if (r.ok() && val.isByteSequence && val.getBytes().size() == 8) {
        keyUid = Uid(val.getBytes());
    }
    return r;
}

// ════════════════════════════════════════════════════════
//  Discovery Namespace (with raw)
// ════════════════════════════════════════════════════════

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


// ════════════════════════════════════════════════════════
//  NVMe Device Access
// ════════════════════════════════════════════════════════

INvmeDevice* EvalApi::getNvmeDevice(std::shared_ptr<ITransport> transport) {
    if (!transport || transport->type() != TransportType::NVMe) return nullptr;
    auto* nvmeTr = dynamic_cast<NvmeTransport*>(transport.get());
    return nvmeTr ? nvmeTr->nvmeDevice() : nullptr;
}

Result EvalApi::nvmeIdentify(std::shared_ptr<ITransport> transport,
                              uint8_t cns, uint32_t nsid, Bytes& data) {
    auto* dev = getNvmeDevice(transport);
    if (!dev) return ErrorCode::TransportNotAvailable;
    return dev->identify(cns, nsid, data);
}

Result EvalApi::nvmeGetLogPage(std::shared_ptr<ITransport> transport,
                                uint8_t logId, uint32_t nsid,
                                Bytes& data, uint32_t dataLen) {
    auto* dev = getNvmeDevice(transport);
    if (!dev) return ErrorCode::TransportNotAvailable;
    return dev->getLogPage(logId, nsid, data, dataLen);
}

Result EvalApi::nvmeGetFeature(std::shared_ptr<ITransport> transport,
                                uint8_t featureId, uint32_t nsid,
                                uint32_t& cdw0, Bytes& data) {
    auto* dev = getNvmeDevice(transport);
    if (!dev) return ErrorCode::TransportNotAvailable;
    return dev->getFeature(featureId, nsid, cdw0, data);
}

Result EvalApi::nvmeSetFeature(std::shared_ptr<ITransport> transport,
                                uint8_t featureId, uint32_t nsid,
                                uint32_t cdw11, const Bytes& data) {
    auto* dev = getNvmeDevice(transport);
    if (!dev) return ErrorCode::TransportNotAvailable;
    return dev->setFeature(featureId, nsid, cdw11, data);
}

Result EvalApi::nvmeFormat(std::shared_ptr<ITransport> transport,
                            uint32_t nsid, uint8_t lbaf,
                            uint8_t ses, uint8_t pi) {
    auto* dev = getNvmeDevice(transport);
    if (!dev) return ErrorCode::TransportNotAvailable;
    return dev->formatNvm(nsid, lbaf, ses, pi);
}

Result EvalApi::nvmeAdminCmd(std::shared_ptr<ITransport> transport,
                              NvmeAdminCmd& cmd, NvmeCompletion& cpl) {
    auto* dev = getNvmeDevice(transport);
    if (!dev) return ErrorCode::TransportNotAvailable;
    return dev->adminCommand(cmd, cpl);
}

Result EvalApi::nvmeIoCmd(std::shared_ptr<ITransport> transport,
                           NvmeIoCmd& cmd, NvmeCompletion& cpl) {
    auto* dev = getNvmeDevice(transport);
    if (!dev) return ErrorCode::TransportNotAvailable;
    return dev->ioCommand(cmd, cpl);
}

} // namespace eval
} // namespace libsed
