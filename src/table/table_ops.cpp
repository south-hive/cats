#include "libsed/table/table_ops.h"
#include "libsed/method/method_call.h"
#include "libsed/method/param_encoder.h"
#include "libsed/core/uid.h"
#include "libsed/core/log.h"

namespace libsed {

Result TableOps::sendAndParse(const Bytes& methodTokens, MethodResult& result) {
    auto r = session_.sendMethod(methodTokens, result);
    if (r.failed()) return r;
    return result.toResult();
}

Result TableOps::get(const Uid& objectUid, const CellBlock& cellBlock,
                      ParamDecoder::ColumnValues& values) {
    auto tokens = MethodCall::buildGet(objectUid, cellBlock, method::getUidFor(session_.sscType()));

    MethodResult result;
    auto r = sendAndParse(tokens, result);
    if (r.failed()) return r;

    auto stream = result.resultStream();
    return ParamDecoder::decodeGetResponse(stream, values);
}

Result TableOps::getAll(const Uid& objectUid, ParamDecoder::ColumnValues& values) {
    return get(objectUid, CellBlock{}, values);
}

Result TableOps::getColumn(const Uid& objectUid, uint32_t column, Token& value) {
    CellBlock cb;
    cb.startColumn = column;
    cb.endColumn = column;

    ParamDecoder::ColumnValues values;
    auto r = get(objectUid, cb, values);
    if (r.failed()) return r;

    auto it = values.find(column);
    if (it == values.end()) return ErrorCode::FeatureNotFound;
    value = it->second;

    return ErrorCode::Success;
}

Result TableOps::getUint(const Uid& objectUid, uint32_t column, uint64_t& value) {
    Token token;
    auto r = getColumn(objectUid, column, token);
    if (r.failed()) return r;
    if (token.isByteSequence) return ErrorCode::MalformedResponse;
    value = token.getUint();
    return ErrorCode::Success;
}

Result TableOps::getBytes(const Uid& objectUid, uint32_t column, Bytes& value) {
    Token token;
    auto r = getColumn(objectUid, column, token);
    if (r.failed()) return r;
    if (!token.isByteSequence) return ErrorCode::MalformedResponse;
    value = token.getBytes();
    return ErrorCode::Success;
}

Result TableOps::set(const Uid& objectUid, const ParamDecoder::ColumnValues& values) {
    TokenList list;
    for (const auto& [col, token] : values) {
        if (token.isByteSequence) {
            list.addBytes(col, token.getBytes());
        } else {
            list.addUint(col, token.getUint());
        }
    }

    auto tokens = MethodCall::buildSet(objectUid, list, method::setUidFor(session_.sscType()));

    MethodResult result;
    return sendAndParse(tokens, result);
}

Result TableOps::setUint(const Uid& objectUid, uint32_t column, uint64_t value) {
    TokenList list;
    list.addUint(column, value);
    auto tokens = MethodCall::buildSet(objectUid, list, method::setUidFor(session_.sscType()));

    MethodResult result;
    return sendAndParse(tokens, result);
}

Result TableOps::setBool(const Uid& objectUid, uint32_t column, bool value) {
    return setUint(objectUid, column, value ? 1 : 0);
}

Result TableOps::setBytes(const Uid& objectUid, uint32_t column, const Bytes& value) {
    TokenList list;
    list.addBytes(column, value);
    auto tokens = MethodCall::buildSet(objectUid, list, method::setUidFor(session_.sscType()));

    MethodResult result;
    return sendAndParse(tokens, result);
}

Result TableOps::setPin(const Uid& cpinUid, const Bytes& pin) {
    return setBytes(cpinUid, uid::col::PIN, pin);
}

Result TableOps::setPin(const Uid& cpinUid, const std::string& pin) {
    Bytes pinBytes(pin.begin(), pin.end());
    return setPin(cpinUid, pinBytes);
}

Result TableOps::authenticate(const Uid& authority, const Bytes& credential) {
    auto tokens = MethodCall::buildAuthenticate(authority, credential, method::authenticateUidFor(session_.sscType()));

    MethodResult result;
    auto r = session_.sendMethod(tokens, result);
    if (r.failed()) return r;

    if (!result.isSuccess()) {
        LIBSED_WARN("Authentication failed: %s", result.statusMessage().c_str());
        return ErrorCode::AuthFailed;
    }

    // Check the boolean result
    auto stream = result.resultStream();
    auto success = stream.readBool();
    if (!success || !*success) {
        return ErrorCode::AuthFailed;
    }

    return ErrorCode::Success;
}

Result TableOps::authenticate(const Uid& authority, const std::string& password) {
    Bytes credential(password.begin(), password.end());
    return authenticate(authority, credential);
}

Result TableOps::genKey(const Uid& objectUid) {
    auto tokens = MethodCall::buildGenKey(objectUid);
    MethodResult result;
    return sendAndParse(tokens, result);
}

Result TableOps::next(const Uid& tableUid, const Uid& startRow,
                       std::vector<Uid>& rows, uint32_t count) {
    TokenEncoder paramEnc;
    if (!startRow.isNull()) {
        paramEnc.startName();
        paramEnc.encodeUint(0); // Where
        paramEnc.encodeUid(startRow);
        paramEnc.endName();
    }
    if (count > 0) {
        paramEnc.startName();
        paramEnc.encodeUint(1); // Count
        paramEnc.encodeUint(count);
        paramEnc.endName();
    }

    MethodCall call(tableUid, Uid(method::NEXT));
    call.setParams(paramEnc.data());
    auto tokens = call.build();

    MethodResult result;
    auto r = sendAndParse(tokens, result);
    if (r.failed()) return r;

    auto stream = result.resultStream();
    while (stream.hasMore()) {
        auto uid = stream.readUid();
        if (uid) rows.push_back(*uid);
        else break;
    }

    return ErrorCode::Success;
}

Result TableOps::revertSP(const Uid& spUid) {
    auto tokens = MethodCall::buildRevertSP(spUid);
    MethodResult result;
    return sendAndParse(tokens, result);
}

Result TableOps::activate(const Uid& spUid) {
    auto tokens = MethodCall::buildActivate(spUid);
    MethodResult result;
    return sendAndParse(tokens, result);
}

Result TableOps::erase(const Uid& objectUid) {
    auto tokens = MethodCall::buildErase(objectUid);
    MethodResult result;
    return sendAndParse(tokens, result);
}

Result TableOps::getRandom(Bytes& randomData, uint32_t count) {
    TokenEncoder paramEnc;
    paramEnc.encodeUint(count);

    MethodCall call{Uid(uid::THIS_SP), Uid(method::RANDOM)};
    call.setParams(paramEnc.data());
    auto tokens = call.build();

    MethodResult result;
    auto r = sendAndParse(tokens, result);
    if (r.failed()) return r;

    auto stream = result.resultStream();
    auto data = stream.readBytes();
    if (data) randomData = *data;

    return ErrorCode::Success;
}

} // namespace libsed
