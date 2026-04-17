#include "libsed/eval/eval_api.h"
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

namespace libsed {
namespace eval {

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
//  Revert (object level)
// ════════════════════════════════════════════════════════

Result EvalApi::revert(Session& session, uint64_t objectUid, RawResult& result) {
    Bytes tokens = buildMethodCall(objectUid, method::REVERT, {});
    return sendMethod(session, tokens, result);
}

// ════════════════════════════════════════════════════════
//  Clock
// ════��═══════════════════════════════════════════════════

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
    auto r = startSessionWithAuth(session, spUid, true, authorityUid, credential, ssr);
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

// ══════════════════════════════════════════════════════════
//  Simplified overloads (RawResult omitted)
// ══════════════════════════════════════════════════════════

Result EvalApi::activate(Session& session, uint64_t spUid) {
    RawResult raw;
    return activate(session, spUid, raw);
}

Result EvalApi::revertSP(Session& session, uint64_t spUid) {
    RawResult raw;
    return revertSP(session, spUid, raw);
}

Result EvalApi::psidRevert(Session& session) {
    RawResult raw;
    return psidRevert(session, raw);
}

Result EvalApi::enableUser(Session& session, uint32_t userId) {
    RawResult raw;
    return enableUser(session, userId, raw);
}

Result EvalApi::setUserPassword(Session& session, uint32_t userId, const Bytes& newPin) {
    RawResult raw;
    return setUserPassword(session, userId, newPin, raw);
}

Result EvalApi::setUserPassword(Session& session, uint32_t userId, const std::string& newPassword) {
    RawResult raw;
    return setUserPassword(session, userId, newPassword, raw);
}

Result EvalApi::isUserEnabled(Session& session, uint32_t userId, bool& enabled) {
    RawResult raw;
    return isUserEnabled(session, userId, enabled, raw);
}

Result EvalApi::setAdmin1Password(Session& session, const Bytes& newPin) {
    RawResult raw;
    return setAdmin1Password(session, newPin, raw);
}

Result EvalApi::setAdmin1Password(Session& session, const std::string& newPassword) {
    RawResult raw;
    return setAdmin1Password(session, newPassword, raw);
}

Result EvalApi::assignUserToRange(Session& session, uint32_t userId, uint32_t rangeId) {
    RawResult raw;
    return assignUserToRange(session, userId, rangeId, raw);
}

Result EvalApi::setAuthorityEnabled(Session& session, uint64_t authorityUid, bool enabled) {
    RawResult raw;
    return setAuthorityEnabled(session, authorityUid, enabled, raw);
}

Result EvalApi::addAuthorityToAce(Session& session, uint64_t aceUid, uint64_t authorityUid) {
    RawResult raw;
    return addAuthorityToAce(session, aceUid, authorityUid, raw);
}

Result EvalApi::getSpLifecycle(Session& session, uint64_t spUid, uint8_t& lifecycle) {
    RawResult raw;
    return getSpLifecycle(session, spUid, lifecycle, raw);
}

Result EvalApi::getAceInfo(Session& session, uint64_t aceUid, AceInfo& info) {
    RawResult raw;
    return getAceInfo(session, aceUid, info, raw);
}

Result EvalApi::getClock(Session& session, uint64_t& clockValue) {
    RawResult raw;
    return getClock(session, clockValue, raw);
}

Result EvalApi::getCPinTriesRemaining(Session& session, uint64_t cpinUid, uint32_t& remaining) {
    RawResult raw;
    return getCPinTriesRemaining(session, cpinUid, remaining, raw);
}

} // namespace eval
} // namespace libsed
