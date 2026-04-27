#pragma once

#include "../core/types.h"
#include <string>

namespace libsed {

/// Password hashing utilities for TCG SED
class HashPassword {
public:
    /// Hash a password using PBKDF2-HMAC-SHA256
    /// @param password  User password
    /// @param salt      Salt bytes (typically serial number + user name)
    /// @param iterations  PBKDF2 iterations (recommend >= 75000)
    /// @param keyLen    Output key length (typically 32)
    /// @return derived key bytes
    static Bytes pbkdf2Sha256(const std::string& password,
                               const Bytes& salt,
                               uint32_t iterations = 75000,
                               uint32_t keyLen = 32);

    /// Hash password with drive serial as salt (convenience)
    static Bytes hashForDrive(const std::string& password,
                               const std::string& serialNumber,
                               uint32_t iterations = 75000);

    /// Simple: convert string password to bytes (no hashing, for testing)
    static Bytes passwordToBytes(const std::string& password);

    /// SHA-256 hash
    static Bytes sha256(const uint8_t* data, size_t len);
    static Bytes sha256(const Bytes& data) { return sha256(data.data(), data.size()); }

    /// HMAC-SHA-256
    static Bytes hmacSha256(const Bytes& key, const Bytes& data);

    // ── sedutil-compatible primitives (PBKDF2-HMAC-SHA1) ─────────────
    // libsed 의 native default 와는 별도 경로. cross-tool 호환을 의도한
    // 사용자가 명시적으로 호출. LAW 21 (hammurabi_code.md) 참조.

    /// SHA-1 hash (RFC 3174 / FIPS 180-4). 20-byte output.
    /// Used only as a building block for sedutilHash. Not recommended for
    /// new cryptographic uses outside sedutil compatibility.
    static Bytes sha1(const uint8_t* data, size_t len);
    static Bytes sha1(const Bytes& data) { return sha1(data.data(), data.size()); }

    /// HMAC-SHA-1 (RFC 2104).
    static Bytes hmacSha1(const Bytes& key, const Bytes& data);

    /// PBKDF2 with HMAC-SHA-1 PRF (RFC 2898 / RFC 6070).
    /// @param password   user password (treated as raw byte input to HMAC)
    /// @param salt       salt bytes (sedutil uses drive serial)
    /// @param iterations PBKDF2 iteration count (sedutil = 75000)
    /// @param keyLen     desired output length in bytes (sedutil = 32)
    static Bytes pbkdf2Sha1(const std::string& password,
                              const Bytes& salt,
                              uint32_t iterations = 75000,
                              uint32_t keyLen = 32);

    /// sedutil-cli (DTA fork) 호환 password hash.
    /// = PBKDF2-HMAC-SHA1(password, drive_serial, iter=75000, keyLen=32).
    ///
    /// 사용처: cross-tool 시나리오에서 cats 가 sedutil 와 byte-identical
    /// wire 를 보내야 할 때. setCPin(Bytes) / startSessionWithAuth(Bytes)
    /// 의 Bytes overload 와 함께 사용.
    ///
    /// @param password     plain-text password (sedutil 도 NUL-terminated
    ///                     C-string 으로 동일 처리)
    /// @param driveSerial  NVMe Identify Controller 의 SN field — 보통
    ///                     20 ASCII 바이트 (trailing space padded). 그대로
    ///                     salt 로 사용.
    /// @return 32-byte derived key, sedutil 와 byte-identical
    static Bytes sedutilHash(const std::string& password,
                              const Bytes& driveSerial,
                              uint32_t iterations = 75000,
                              uint32_t keyLen = 32);
};

} // namespace libsed
