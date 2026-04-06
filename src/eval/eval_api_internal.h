// eval_api_internal.h — Shared helper for split EvalApi implementation files
#pragma once

#include "libsed/eval/eval_api.h"
#include "libsed/method/method_result.h"

namespace libsed {
namespace eval {

// Internal helper: send method on session, capture raw payloads and status
static inline Result sendMethod(Session& session, const Bytes& methodTokens, RawResult& raw) {
    raw.rawSendPayload = methodTokens;

    auto r = session.sendMethod(methodTokens, raw.methodResult);
    raw.transportError = r.code();

    if (r.ok() && !raw.methodResult.isSuccess()) {
        raw.protocolError = raw.methodResult.toResult().code();
    }

    return r;
}

} // namespace eval
} // namespace libsed
