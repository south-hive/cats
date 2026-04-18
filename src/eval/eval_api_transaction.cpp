#include "libsed/eval/eval_api.h"
#include "libsed/codec/token_encoder.h"
#include "libsed/session/session.h"
#include "eval_api_internal.h"

namespace libsed {
namespace eval {

// ════════════════════════════════════════════════════════
//  Transactions — explicit boundary API
// ════════════════════════════════════════════════════════
//
// The host drives the transaction lifecycle itself: startTransaction,
// then zero or more method calls (Set/Get/etc. called through the
// normal EvalApi), then commitTransaction OR rollbackTransaction.
//
// Each boundary is its own ComPacket / ifSend / ifRecv cycle so TC
// scenarios can inspect NVMe transport errors separately from TCG
// method status at every step. This file does NOT hide any step or
// auto-apply commit/rollback — that's a deliberate design choice so
// scenario code stays explicit.

static Result sendTokens(Session& session, const Bytes& tokens,
                          RawResult& result) {
    result.rawSendPayload = tokens;
    Bytes resp;
    auto r = session.sendTokenPayload(tokens, resp);
    result.rawRecvPayload = resp;
    result.transportError = r.code();

    // Best-effort method-result parse. Transaction boundary responses are
    // typically empty or a status list; if the parse finds a status, it
    // lands in result.methodResult and the caller can check
    // isSuccess() / status(). If the parse fails (empty / malformed),
    // methodResult stays default (success). transportError is authoritative
    // for the NVMe layer regardless.
    if (r.ok() && !resp.empty()) {
        result.methodResult.parse(resp);
    }
    return r;
}

Result EvalApi::startTransaction(Session& session, RawResult& result) {
    TokenEncoder enc;
    enc.startTransaction();
    return sendTokens(session, enc.data(), result);
}

Result EvalApi::endTransaction(Session& session, bool commit, RawResult& result) {
    TokenEncoder enc;
    enc.endTransaction(commit);
    return sendTokens(session, enc.data(), result);
}

Result EvalApi::commitTransaction(Session& session, RawResult& result) {
    return endTransaction(session, /*commit=*/true, result);
}

Result EvalApi::rollbackTransaction(Session& session, RawResult& result) {
    return endTransaction(session, /*commit=*/false, result);
}

} // namespace eval
} // namespace libsed
