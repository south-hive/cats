#include "libsed/eval/eval_api.h"
#include "libsed/method/method_call.h"
#include "libsed/method/method_result.h"
#include "libsed/method/method_uids.h"
#include "libsed/method/param_encoder.h"
#include "libsed/method/param_decoder.h"
#include "libsed/codec/token_encoder.h"
#include "libsed/codec/token_decoder.h"
#include "libsed/packet/packet_builder.h"
#include "libsed/core/uid.h"
#include "libsed/core/endian.h"
#include "libsed/core/log.h"
#include "eval_api_internal.h"

namespace libsed {
namespace eval {

// ════════════════════════════════════════════════════════
//  Table Get / Set
// ════════════════════════════════════════════════════════

Result EvalApi::tableGet(Session& session, uint64_t objectUid,
                          uint32_t startCol, uint32_t endCol,
                          TableResult& result) {
    CellBlock cb;
    cb.startColumn = startCol;
    cb.endColumn = endCol;
    Bytes tokens = MethodCall::buildGet(Uid(objectUid), cb, method::getUidFor(session.sscType()));
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
    Bytes tokens = MethodCall::buildGet(Uid(objectUid), {}, method::getUidFor(session.sscType()));
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
    Bytes tokens = MethodCall::buildSet(Uid(objectUid), values, method::setUidFor(session.sscType()));
    return sendMethod(session, tokens, result);
}

Result EvalApi::tableSetUint(Session& session, uint64_t objectUid,
                              uint32_t column, uint64_t value,
                              RawResult& result) {
    TokenList values;
    values.addUint(column, value);
    Bytes tokens = MethodCall::buildSet(Uid(objectUid), values, method::setUidFor(session.sscType()));
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
    Bytes tokens = MethodCall::buildSet(Uid(objectUid), values, method::setUidFor(session.sscType()));
    return sendMethod(session, tokens, result);
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
    Bytes tokens = MethodCall::buildSet(Uid(objectUid), values, method::setUidFor(session.sscType()));
    return sendMethod(session, tokens, result);
}

// ══════════════════════════════════════════════════════════
//  Simplified overloads (RawResult omitted)
// ══════════════════════════════════════════════════════════

Result EvalApi::tableSetBool(Session& session, uint64_t objectUid, uint32_t column, bool value) {
    RawResult raw;
    return tableSetBool(session, objectUid, column, value, raw);
}

Result EvalApi::tableGetUint(Session& session, uint64_t objectUid, uint32_t column, uint64_t& value) {
    RawResult raw;
    return tableGetUint(session, objectUid, column, value, raw);
}

} // namespace eval
} // namespace libsed
