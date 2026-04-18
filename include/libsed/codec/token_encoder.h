#pragma once

#include "../core/types.h"
#include "../core/endian.h"
#include "token.h"
#include <vector>
#include <string>

namespace libsed {

/// Encodes C++ values into TCG SED token byte stream
class TokenEncoder {
public:
    TokenEncoder() = default;
    explicit TokenEncoder(size_t reserveBytes) { buffer_.reserve(reserveBytes); }

    // ── Atom encoding ──────────────────────────────────

    /// Encode unsigned integer (auto-selects tiny/short/medium atom)
    void encodeUint(uint64_t val);

    /// Encode signed integer
    void encodeInt(int64_t val);

    /// Encode byte sequence (binary data)
    void encodeBytes(const uint8_t* data, size_t len);
    void encodeBytes(const Bytes& data) { encodeBytes(data.data(), data.size()); }
    void encodeBytes(ByteSpan data) { encodeBytes(data.data(), data.size()); }

    /// Encode a string as byte sequence
    void encodeString(const std::string& str) {
        encodeBytes(reinterpret_cast<const uint8_t*>(str.data()), str.size());
    }

    /// Encode UID (8-byte)
    void encodeUid(const Uid& uid) { encodeBytes(uid.bytes.data(), 8); }
    void encodeUid(uint64_t uid) { encodeUid(Uid(uid)); }

    /// Encode half-UID (4-byte)
    void encodeHalfUid(const HalfUid& huid) { encodeBytes(huid.bytes.data(), 4); }

    /// Encode boolean as uint (0 or 1)
    void encodeBool(bool val) { encodeUint(val ? 1 : 0); }

    // ── Control token encoding ─────────────────────────

    void startList()        { buffer_.push_back(static_cast<uint8_t>(TokenType::StartList)); }
    void endList()          { buffer_.push_back(static_cast<uint8_t>(TokenType::EndList)); }
    void startName()        { buffer_.push_back(static_cast<uint8_t>(TokenType::StartName)); }
    void endName()          { buffer_.push_back(static_cast<uint8_t>(TokenType::EndName)); }
    void call()             { buffer_.push_back(static_cast<uint8_t>(TokenType::Call)); }
    void endOfData()        { buffer_.push_back(static_cast<uint8_t>(TokenType::EndOfData)); }
    void endOfSession()     { buffer_.push_back(static_cast<uint8_t>(TokenType::EndOfSession)); }
    void startTransaction() { buffer_.push_back(static_cast<uint8_t>(TokenType::StartTransaction)); }

    /// Emit EndTransaction (0xFC) followed by a 1-byte commit status.
    /// @param commit  true → commit (0x00). false → abort/rollback (0x01).
    ///
    /// Per TCG Core Spec §3.2.1.3, EndTransaction requires the status byte
    /// encoded as a tiny atom. `commit == true` asks the TPer to apply all
    /// operations accumulated since StartTransaction; `false` discards them.
    void endTransaction(bool commit = true) {
        buffer_.push_back(static_cast<uint8_t>(TokenType::EndTransaction));
        buffer_.push_back(commit ? uint8_t{0x00} : uint8_t{0x01});
    }

    // ── Named value helpers ────────────────────────────

    /// Encode { name = uintVal }
    void namedUint(uint32_t name, uint64_t val) {
        startName(); encodeUint(name); encodeUint(val); endName();
    }

    /// Encode { name = intVal }
    void namedInt(uint32_t name, int64_t val) {
        startName(); encodeUint(name); encodeInt(val); endName();
    }

    /// Encode { name = bytes }
    void namedBytes(uint32_t name, const Bytes& val) {
        startName(); encodeUint(name); encodeBytes(val); endName();
    }

    void namedString(uint32_t name, const std::string& val) {
        startName(); encodeUint(name); encodeString(val); endName();
    }

    void namedBool(uint32_t name, bool val) {
        startName(); encodeUint(name); encodeBool(val); endName();
    }

    void namedUid(uint32_t name, const Uid& val) {
        startName(); encodeUint(name); encodeUid(val); endName();
    }

    // ── Buffer access ──────────────────────────────────

    const Bytes& data() const { return buffer_; }
    Bytes&& release() { return std::move(buffer_); }
    size_t size() const { return buffer_.size(); }
    void clear() { buffer_.clear(); }
    void reset() { buffer_.clear(); }

    /// Append raw bytes
    void appendRaw(const uint8_t* data, size_t len) {
        buffer_.insert(buffer_.end(), data, data + len);
    }

    void appendRaw(const Bytes& data) {
        buffer_.insert(buffer_.end(), data.begin(), data.end());
    }

private:
    /// Encode tiny atom (unsigned): 0 to 63
    void encodeTinyAtomUnsigned(uint8_t val);

    /// Encode tiny atom (signed): -32 to 31
    void encodeTinyAtomSigned(int8_t val);

    /// Encode short atom: header byte + up to 15 data bytes
    void encodeShortAtom(bool isByte, bool isSigned, const uint8_t* data, size_t len);

    /// Encode medium atom: 2 header bytes + up to 2047 data bytes
    void encodeMediumAtom(bool isByte, bool isSigned, const uint8_t* data, size_t len);

    /// Encode long atom: 4 header bytes + up to 16MB data bytes
    void encodeLongAtom(bool isByte, bool isSigned, const uint8_t* data, size_t len);

    Bytes buffer_;
};

} // namespace libsed
