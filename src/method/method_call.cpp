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

Bytes MethodCall::buildGet(const Uid& objectUid, const CellBlock& cellBlock,
                            uint64_t methodUid) {
    TokenEncoder paramEnc;

    // TCG Core Spec: Get [ Cellblock : cell_block ] — cell_block is a list
    // type, so it MUST be wrapped in its own STARTLIST/ENDLIST. Real sedutil
    // binary does this (verified by hex dump from a hardware run); a previous
    // assumption that sedutil emits cellblock named pairs flat was wrong and
    // produced 0x0F (TPER_MALFUNCTION) on strict drives.
    //
    // Outer list comes from MethodCall::build() (params wrapper).
    // Inner list is this cellblock object.
    paramEnc.startList();
    ParamEncoder::encodeCellBlock(paramEnc, cellBlock);
    paramEnc.endList();

    MethodCall call(objectUid, Uid(methodUid));
    call.setParams(paramEnc.data());
    return call.build();
}

Bytes MethodCall::buildSet(const Uid& objectUid, const TokenList& values,
                            uint64_t methodUid) {
    TokenEncoder paramEnc;

    // Object.Set per TCG Core Spec §5.3.3: `ObjectUID.Set [ Values : list ]`.
    // No Where — the object position is identified by the InvokingUID itself.
    //
    // History note: this was correctly removed in e41c77d (2026-04-17), then
    // wrongly re-added in deac2e6 (5 h later) based on the hand-rolled
    // DtaCommand reference in sed_compare. Real sedutil-cli on hardware does
    // NOT send Where for object sets — confirmed by user-captured hex dump
    // 2026-04-27 (cats=74B vs sedutil=69B subpacket, exactly 5B = empty Where
    // overhead).
    //
    // Byte-table writes (DataStore, raw MBR) do need Where with row offset,
    // but those paths bypass buildSet and encode tokens manually
    // (see EvalApi::writeMbrData / writeDataStore).
    //
    // See LAW 3 and LAW 17 in docs/internal/hammurabi_code.md.
    paramEnc.startName();
    paramEnc.encodeUint(1); // "Values" keyword
    paramEnc.startList();
    values.encode(paramEnc);
    paramEnc.endList();
    paramEnc.endName();

    MethodCall call(objectUid, Uid(methodUid));
    call.setParams(paramEnc.data());
    return call.build();
}

Bytes MethodCall::buildAuthenticate(const Uid& authorityUid, const Bytes& credential,
                                     uint64_t methodUid) {
    TokenEncoder paramEnc;

    paramEnc.encodeUid(authorityUid);
    if (!credential.empty()) {
        paramEnc.startName();
        paramEnc.encodeUint(0); // "Challenge" keyword
        paramEnc.encodeBytes(credential);
        paramEnc.endName();
    }

    MethodCall call{Uid(uid::THIS_SP), Uid(methodUid)};
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
