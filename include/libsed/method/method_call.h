#pragma once

#include "../core/types.h"
#include "../core/error.h"
#include "../codec/token_encoder.h"
#include "../codec/token_list.h"
#include "method_uids.h"
#include <vector>
#include <optional>

namespace libsed {

/// Builds a TCG SED method call token stream
/// Structure: CALL InvokingID MethodID [ params... ] EndOfData [ status ]
class MethodCall {
public:
    MethodCall() = default;
    MethodCall(const Uid& invokingId, const Uid& methodId)
        : invokingId_(invokingId), methodId_(methodId) {}

    MethodCall(uint64_t invokingId, uint64_t methodId)
        : invokingId_(Uid(invokingId)), methodId_(Uid(methodId)) {}

    /// Set the invoking object UID
    void setInvokingId(const Uid& uid) { invokingId_ = uid; }
    void setInvokingId(uint64_t uid) { invokingId_ = Uid(uid); }

    /// Set the method UID
    void setMethodId(const Uid& uid) { methodId_ = uid; }
    void setMethodId(uint64_t uid) { methodId_ = Uid(uid); }

    /// Access to parameter encoder (add tokens between StartList/EndList)
    TokenEncoder& params() { return paramEncoder_; }
    const TokenEncoder& params() const { return paramEncoder_; }

    /// Set pre-built parameters (replaces current)
    void setParams(const Bytes& paramTokens) { paramEncoder_.clear(); paramEncoder_.appendRaw(paramTokens); }

    /// Build complete method call token stream
    /// Returns: CALL uid uid [ params ] EndOfData [ 0 0 0 ]
    Bytes build() const;

    /// Build method call for session manager (uses SMUID as invoking ID)
    static Bytes buildSmCall(uint64_t smMethodUid, const Bytes& paramTokens);

    // ── Convenience factory methods ──────────────────

    /// Build GET method call with CellBlock.
    /// @param methodUid  Defaults to Opal GET (0x16). Pass method::EGET (0x06)
    ///                   for Enterprise SSC sessions; use method::getUidFor(ssc)
    ///                   to pick automatically.
    static Bytes buildGet(const Uid& objectUid, const CellBlock& cellBlock = {},
                          uint64_t methodUid = method::GET);

    /// Build SET method call with values.
    /// @param methodUid  Defaults to Opal SET (0x17). Pass method::ESET (0x07)
    ///                   for Enterprise SSC sessions.
    static Bytes buildSet(const Uid& objectUid, const TokenList& values,
                          uint64_t methodUid = method::SET);

    /// Build Authenticate method call.
    /// @param methodUid  Defaults to Opal AUTHENTICATE (0x1C). Pass
    ///                   method::EAUTHENTICATE (0x0C) for Enterprise SSC.
    static Bytes buildAuthenticate(const Uid& authorityUid, const Bytes& credential,
                                   uint64_t methodUid = method::AUTHENTICATE);

    /// Build GenKey method call
    static Bytes buildGenKey(const Uid& objectUid);

    /// Build Revert method call on SP
    static Bytes buildRevertSP(const Uid& spUid);

    /// Build Activate method call
    static Bytes buildActivate(const Uid& spUid);

    /// Build Erase method call
    static Bytes buildErase(const Uid& objectUid);

private:
    Uid invokingId_;
    Uid methodId_;
    TokenEncoder paramEncoder_;
};

} // namespace libsed
