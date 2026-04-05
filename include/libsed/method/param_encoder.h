#pragma once

#include "../core/types.h"
#include "../codec/token_encoder.h"
#include <vector>
#include <string>

namespace libsed {

/// Helper for encoding method-specific parameters
class ParamEncoder {
public:
    ParamEncoder() = default;

    // ── StartSession parameters ──────────────────────

    /// Encode StartSession parameters
    /// hostSessionId, spUid, write(bool), [hostChallenge], [hostExchangeAuth], [hostSignAuth]
    static Bytes encodeStartSession(
        uint32_t hostSessionId,
        const Uid& spUid,
        bool write,
        const Bytes& hostChallenge = {},
        const Uid& hostExchangeAuth = Uid(),
        const Uid& hostSignAuth = Uid()
    );

    // ── Properties parameters ────────────────────────

    struct HostProperties {
        uint32_t maxMethods = 1;
        uint32_t maxSubPackets = 1;
        uint32_t maxPackets = 1;
        uint32_t maxComPacketSize = 2048;
        uint32_t maxResponseComPacketSize = 2048;
        uint32_t maxPacketSize = 2028;
        uint32_t maxIndTokenSize = 1992;
        uint32_t maxAggTokenSize = 1992;
        uint32_t continuedTokens = 0;
        uint32_t sequenceNumbers = 0;
        uint32_t ackNak = 0;
        uint32_t async = 0;
    };

    static Bytes encodeProperties(const HostProperties& props);

    // ── Get/Set CellBlock encoding ───────────────────

    /// Encode CellBlock as named values inside a list
    static void encodeCellBlock(TokenEncoder& enc, const CellBlock& cb);

    // ── Authenticate parameters ──────────────────────

    /// Encode Authenticate method parameters
    static Bytes encodeAuthenticate(const Uid& authority, const Bytes& challenge);
};

} // namespace libsed
