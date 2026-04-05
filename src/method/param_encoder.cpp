#include "libsed/method/param_encoder.h"
#include "libsed/core/uid.h"

namespace libsed {

Bytes ParamEncoder::encodeStartSession(uint32_t hostSessionId,
                                         const Uid& spUid,
                                         bool write,
                                         const Bytes& hostChallenge,
                                         const Uid& hostExchangeAuth,
                                         const Uid& hostSignAuth) {
    TokenEncoder enc;

    // Parameter 0: Host Session ID
    enc.encodeUint(hostSessionId);

    // Parameter 1: SP UID
    enc.encodeUid(spUid);

    // Parameter 2: Write (boolean)
    enc.encodeBool(write);

    // Optional: Host Challenge
    // Opal SSC names optional params starting from 0: HostChallenge=0
    // (NOT absolute Table 225 index). sedutil uses 0 and works with hardware.
    if (!hostChallenge.empty()) {
        enc.startName();
        enc.encodeUint(0); // HostChallenge
        enc.encodeBytes(hostChallenge);
        enc.endName();
    }

    // Optional: HostExchangeAuthority (TCG Core Spec Table 225, named param index 3)
    // Index 1=HostExchangeCert, 2=HostSigningCert are between 0 and 3
    if (!hostExchangeAuth.isNull()) {
        enc.startName();
        enc.encodeUint(3); // HostExchangeAuthority
        enc.encodeUid(hostExchangeAuth);
        enc.endName();
    }

    // Optional: HostSigningAuthority (TCG Core Spec Table 225, named param index 4)
    if (!hostSignAuth.isNull()) {
        enc.startName();
        enc.encodeUint(4); // HostSigningAuthority
        enc.encodeUid(hostSignAuth);
        enc.endName();
    }

    return enc.data();
}

Bytes ParamEncoder::encodeProperties(const HostProperties& props) {
    TokenEncoder enc;

    // TCG Core Spec: Properties method parameter is a named value pair
    //   STARTNAME "HostProperties" STARTLIST { pairs... } ENDLIST ENDNAME
    // Each property is a named value pair: STARTNAME string uint ENDNAME
    // sedutil reference: DtaDevOpal.cpp properties() uses this exact encoding.
    enc.startName();
    enc.encodeString("HostProperties");
    enc.startList();

    enc.startName(); enc.encodeString("MaxComPacketSize");
    enc.encodeUint(props.maxComPacketSize); enc.endName();

    enc.startName(); enc.encodeString("MaxPacketSize");
    enc.encodeUint(props.maxPacketSize); enc.endName();

    enc.startName(); enc.encodeString("MaxIndTokenSize");
    enc.encodeUint(props.maxIndTokenSize); enc.endName();

    enc.startName(); enc.encodeString("MaxPackets");
    enc.encodeUint(props.maxPackets); enc.endName();

    enc.startName(); enc.encodeString("MaxSubpackets");
    enc.encodeUint(props.maxSubPackets); enc.endName();

    enc.startName(); enc.encodeString("MaxMethods");
    enc.encodeUint(props.maxMethods); enc.endName();

    enc.endList();
    enc.endName();

    return enc.data();
}

void ParamEncoder::encodeCellBlock(TokenEncoder& enc, const CellBlock& cb) {
    if (cb.startColumn) {
        enc.startName();
        enc.encodeUint(0); // startColumn
        enc.encodeUint(*cb.startColumn);
        enc.endName();
    }
    if (cb.endColumn) {
        enc.startName();
        enc.encodeUint(1); // endColumn
        enc.encodeUint(*cb.endColumn);
        enc.endName();
    }
    if (cb.startRow) {
        enc.startName();
        enc.encodeUint(2); // startRow
        enc.encodeUint(*cb.startRow);
        enc.endName();
    }
    if (cb.endRow) {
        enc.startName();
        enc.encodeUint(3); // endRow
        enc.encodeUint(*cb.endRow);
        enc.endName();
    }
}

Bytes ParamEncoder::encodeAuthenticate(const Uid& authority, const Bytes& challenge) {
    TokenEncoder enc;
    enc.encodeUid(authority);

    if (!challenge.empty()) {
        enc.startName();
        enc.encodeUint(0); // Challenge
        enc.encodeBytes(challenge);
        enc.endName();
    }

    return enc.data();
}

} // namespace libsed
