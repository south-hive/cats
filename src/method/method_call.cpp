#include "libsed/method/method_call.h"
#include "libsed/method/param_encoder.h"
#include "libsed/core/uid.h"

namespace libsed {

Bytes MethodCall::build() const {
    TokenEncoder enc;

    // CALL token
    enc.call();

    // InvokingID (UID of the object being invoked)
    enc.encodeUid(invokingId_);

    // MethodID (UID of the method)
    enc.encodeUid(methodId_);

    // Parameter list
    enc.startList();
    enc.appendRaw(paramEncoder_.data());
    enc.endList();

    // End of data
    enc.endOfData();

    // Status list placeholder (sent by host as empty)
    enc.startList();
    enc.encodeUint(0); // expected status
    enc.encodeUint(0); // reserved
    enc.encodeUint(0); // reserved
    enc.endList();

    return enc.data();
}

Bytes MethodCall::buildSmCall(uint64_t smMethodUid, const Bytes& paramTokens) {
    TokenEncoder enc;

    enc.call();
    enc.encodeUid(uid::SMUID);      // Session Manager UID
    enc.encodeUid(smMethodUid);     // SM method UID

    enc.startList();
    enc.appendRaw(paramTokens);
    enc.endList();

    enc.endOfData();

    enc.startList();
    enc.encodeUint(0);
    enc.encodeUint(0);
    enc.encodeUint(0);
    enc.endList();

    return enc.data();
}

Bytes MethodCall::buildGet(const Uid& objectUid, const CellBlock& cellBlock) {
    TokenEncoder paramEnc;

    // CellBlock parameter
    paramEnc.startList();
    ParamEncoder::encodeCellBlock(paramEnc, cellBlock);
    paramEnc.endList();

    MethodCall call(objectUid, Uid(method::GET));
    call.setParams(paramEnc.data());
    return call.build();
}

Bytes MethodCall::buildSet(const Uid& objectUid, const TokenList& values) {
    TokenEncoder paramEnc;

    // Where (empty) — sedutil always includes this even when empty
    paramEnc.startName();
    paramEnc.encodeUint(0); // "Where" keyword
    paramEnc.startList();
    paramEnc.endList();
    paramEnc.endName();

    // Values
    paramEnc.startName();
    paramEnc.encodeUint(1); // "Values" keyword
    paramEnc.startList();
    values.encode(paramEnc);
    paramEnc.endList();
    paramEnc.endName();

    MethodCall call(objectUid, Uid(method::SET));
    call.setParams(paramEnc.data());
    return call.build();
}

Bytes MethodCall::buildAuthenticate(const Uid& authorityUid, const Bytes& credential) {
    TokenEncoder paramEnc;

    paramEnc.encodeUid(authorityUid);
    if (!credential.empty()) {
        paramEnc.startName();
        paramEnc.encodeUint(0); // "Challenge" keyword
        paramEnc.encodeBytes(credential);
        paramEnc.endName();
    }

    MethodCall call{Uid(uid::THIS_SP), Uid(method::AUTHENTICATE)};
    call.setParams(paramEnc.data());
    return call.build();
}

Bytes MethodCall::buildGenKey(const Uid& objectUid) {
    MethodCall call(objectUid, Uid(method::GENKEY));
    return call.build();
}

Bytes MethodCall::buildRevertSP(const Uid& spUid) {
    MethodCall call(spUid, Uid(method::REVERTSP));
    return call.build();
}

Bytes MethodCall::buildActivate(const Uid& spUid) {
    MethodCall call(spUid, Uid(method::ACTIVATE));
    return call.build();
}

Bytes MethodCall::buildErase(const Uid& objectUid) {
    MethodCall call(objectUid, Uid(method::ERASE));
    return call.build();
}

} // namespace libsed
