#include "libsed/security/hash_password.h"
#include "libsed/core/log.h"
#include <cstring>
#include <algorithm>
#include <array>

namespace libsed {

// Minimal standalone SHA-256 implementation
// (In production, use OpenSSL or mbedTLS)
namespace {

static constexpr uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
inline uint32_t sig0(uint32_t x) { return rotr(x,2) ^ rotr(x,13) ^ rotr(x,22); }
inline uint32_t sig1(uint32_t x) { return rotr(x,6) ^ rotr(x,11) ^ rotr(x,25); }
inline uint32_t gam0(uint32_t x) { return rotr(x,7) ^ rotr(x,18) ^ (x >> 3); }
inline uint32_t gam1(uint32_t x) { return rotr(x,17) ^ rotr(x,19) ^ (x >> 10); }

struct Sha256Ctx {
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    uint8_t buf[64] = {};
    uint64_t totalLen = 0;
    size_t bufLen = 0;

    void processBlock(const uint8_t* block) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++) {
            w[i] = (static_cast<uint32_t>(block[i*4]) << 24) |
                   (static_cast<uint32_t>(block[i*4+1]) << 16) |
                   (static_cast<uint32_t>(block[i*4+2]) << 8) |
                   static_cast<uint32_t>(block[i*4+3]);
        }
        for (int i = 16; i < 64; i++) {
            w[i] = gam1(w[i-2]) + w[i-7] + gam0(w[i-15]) + w[i-16];
        }

        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];

        for (int i = 0; i < 64; i++) {
            uint32_t t1 = hh + sig1(e) + ch(e,f,g) + K[i] + w[i];
            uint32_t t2 = sig0(a) + maj(a,b,c);
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }

        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
        h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }

    void update(const uint8_t* data, size_t len) {
        totalLen += len;
        while (len > 0) {
            size_t space = 64 - bufLen;
            size_t copy = std::min(len, space);
            std::memcpy(buf + bufLen, data, copy);
            bufLen += copy;
            data += copy;
            len -= copy;
            if (bufLen == 64) {
                processBlock(buf);
                bufLen = 0;
            }
        }
    }

    std::array<uint8_t, 32> finalize() {
        uint64_t bits = totalLen * 8;
        uint8_t pad = 0x80;
        update(&pad, 1);
        pad = 0;
        while (bufLen != 56) update(&pad, 1);

        uint8_t lenBuf[8];
        for (int i = 7; i >= 0; i--) { lenBuf[i] = static_cast<uint8_t>(bits & 0xFF); bits >>= 8; }
        update(lenBuf, 8);

        std::array<uint8_t, 32> result;
        for (int i = 0; i < 8; i++) {
            result[i*4]   = static_cast<uint8_t>((h[i] >> 24) & 0xFF);
            result[i*4+1] = static_cast<uint8_t>((h[i] >> 16) & 0xFF);
            result[i*4+2] = static_cast<uint8_t>((h[i] >> 8) & 0xFF);
            result[i*4+3] = static_cast<uint8_t>(h[i] & 0xFF);
        }
        return result;
    }
};

// ── SHA-1 (RFC 3174 / FIPS 180-4) ──────────────────────────────────
// 64-byte block, 20-byte output, 80 rounds with 4 round constants.
// Style mirrors the SHA-256 ctx above for consistency.

inline uint32_t rotl(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

struct Sha1Ctx {
    uint32_t h[5] = {
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    };
    uint8_t buf[64] = {};
    uint64_t totalLen = 0;
    size_t bufLen = 0;

    void processBlock(const uint8_t* block) {
        uint32_t w[80];
        for (int i = 0; i < 16; i++) {
            w[i] = (static_cast<uint32_t>(block[i*4]) << 24) |
                   (static_cast<uint32_t>(block[i*4+1]) << 16) |
                   (static_cast<uint32_t>(block[i*4+2]) << 8) |
                   static_cast<uint32_t>(block[i*4+3]);
        }
        for (int i = 16; i < 80; i++) {
            w[i] = rotl(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        }

        uint32_t a=h[0], b=h[1], c=h[2], d=h[3], e=h[4];

        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            uint32_t t = rotl(a, 5) + f + e + k + w[i];
            e = d; d = c; c = rotl(b, 30); b = a; a = t;
        }

        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e;
    }

    void update(const uint8_t* data, size_t len) {
        totalLen += len;
        while (len > 0) {
            size_t space = 64 - bufLen;
            size_t copy = std::min(len, space);
            std::memcpy(buf + bufLen, data, copy);
            bufLen += copy;
            data += copy;
            len -= copy;
            if (bufLen == 64) {
                processBlock(buf);
                bufLen = 0;
            }
        }
    }

    std::array<uint8_t, 20> finalize() {
        uint64_t bits = totalLen * 8;
        uint8_t pad = 0x80;
        update(&pad, 1);
        pad = 0;
        while (bufLen != 56) update(&pad, 1);

        uint8_t lenBuf[8];
        for (int i = 7; i >= 0; i--) { lenBuf[i] = static_cast<uint8_t>(bits & 0xFF); bits >>= 8; }
        update(lenBuf, 8);

        std::array<uint8_t, 20> result;
        for (int i = 0; i < 5; i++) {
            result[i*4]   = static_cast<uint8_t>((h[i] >> 24) & 0xFF);
            result[i*4+1] = static_cast<uint8_t>((h[i] >> 16) & 0xFF);
            result[i*4+2] = static_cast<uint8_t>((h[i] >> 8) & 0xFF);
            result[i*4+3] = static_cast<uint8_t>(h[i] & 0xFF);
        }
        return result;
    }
};

} // anonymous namespace

Bytes HashPassword::sha256(const uint8_t* data, size_t len) {
    Sha256Ctx ctx;
    ctx.update(data, len);
    auto hash = ctx.finalize();
    return Bytes(hash.begin(), hash.end());
}

Bytes HashPassword::hmacSha256(const Bytes& key, const Bytes& data) {
    constexpr size_t BLOCK_SIZE = 64;

    Bytes k = key;
    if (k.size() > BLOCK_SIZE) {
        k = sha256(k);
    }
    k.resize(BLOCK_SIZE, 0);

    Bytes ipad(BLOCK_SIZE), opad(BLOCK_SIZE);
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5C;
    }

    // inner hash: SHA256(ipad || data)
    Sha256Ctx inner;
    inner.update(ipad.data(), ipad.size());
    inner.update(data.data(), data.size());
    auto innerHash = inner.finalize();

    // outer hash: SHA256(opad || inner_hash)
    Sha256Ctx outer;
    outer.update(opad.data(), opad.size());
    outer.update(innerHash.data(), innerHash.size());
    auto result = outer.finalize();

    return Bytes(result.begin(), result.end());
}

Bytes HashPassword::pbkdf2Sha256(const std::string& password,
                                   const Bytes& salt,
                                   uint32_t iterations,
                                   uint32_t keyLen) {
    Bytes derivedKey;
    derivedKey.reserve(keyLen);

    Bytes passwordBytes(password.begin(), password.end());

    uint32_t blockNum = 1;
    while (derivedKey.size() < keyLen) {
        // U1 = HMAC(password, salt || INT32_BE(blockNum))
        Bytes saltBlock = salt;
        saltBlock.push_back(static_cast<uint8_t>((blockNum >> 24) & 0xFF));
        saltBlock.push_back(static_cast<uint8_t>((blockNum >> 16) & 0xFF));
        saltBlock.push_back(static_cast<uint8_t>((blockNum >> 8) & 0xFF));
        saltBlock.push_back(static_cast<uint8_t>(blockNum & 0xFF));

        Bytes u = hmacSha256(passwordBytes, saltBlock);
        Bytes t = u;

        for (uint32_t i = 1; i < iterations; i++) {
            u = hmacSha256(passwordBytes, u);
            for (size_t j = 0; j < t.size(); j++) {
                t[j] ^= u[j];
            }
        }

        size_t needed = std::min(static_cast<size_t>(keyLen) - derivedKey.size(), t.size());
        derivedKey.insert(derivedKey.end(), t.begin(), t.begin() + needed);
        blockNum++;
    }

    return derivedKey;
}

Bytes HashPassword::hashForDrive(const std::string& password,
                                   const std::string& serialNumber,
                                   uint32_t iterations) {
    Bytes salt(serialNumber.begin(), serialNumber.end());
    return pbkdf2Sha256(password, salt, iterations, 32);
}

Bytes HashPassword::passwordToBytes(const std::string& password) {
    // SHA-256 hash to produce a 32-byte PIN that satisfies Opal's minimum
    // PIN-length requirement (≥ 20 bytes); raw ASCII is too short for
    // drives that expect MSID-length credentials.
    //
    // ⚠ NOT cross-compatible with sedutil-cli.
    //   sedutil hashes passwords with PBKDF2-HMAC-SHA1 (drive serial /
    //   MSID as salt, 75000 iterations). A drive whose C_PIN was Set via
    //   libsed will reject sedutil's same-password authentication, and
    //   vice versa. After enough auth failures the drive locks SID,
    //   recoverable only via PSID Revert (destroys data).
    //
    //   This divergence is by design and pinned by tests/unit/test_hash.cpp::
    //   `SedutilDivergence_Sha256VsPbkdf2Sha256`.
    //
    //   Use libsed throughout the drive's lifecycle for consistency, OR
    //   compute a sedutil-compatible PIN externally and pass it via the
    //   `Bytes` overloads of setCPin / startSessionWithAuth.
    //
    // See LAW 21 in docs/internal/hammurabi_code.md and §10 in
    // docs/rosetta_stone.md for the full risk model.
    return sha256(reinterpret_cast<const uint8_t*>(password.data()),
                  password.size());
}

// ── sedutil-compatible primitives ──────────────────────────────────

Bytes HashPassword::sha1(const uint8_t* data, size_t len) {
    Sha1Ctx ctx;
    ctx.update(data, len);
    auto hash = ctx.finalize();
    return Bytes(hash.begin(), hash.end());
}

Bytes HashPassword::hmacSha1(const Bytes& key, const Bytes& data) {
    constexpr size_t BLOCK_SIZE = 64;

    Bytes k = key;
    if (k.size() > BLOCK_SIZE) {
        k = sha1(k);
    }
    k.resize(BLOCK_SIZE, 0);

    Bytes ipad(BLOCK_SIZE), opad(BLOCK_SIZE);
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5C;
    }

    // inner = SHA-1(ipad || data)
    Sha1Ctx inner;
    inner.update(ipad.data(), ipad.size());
    inner.update(data.data(), data.size());
    auto innerHash = inner.finalize();

    // outer = SHA-1(opad || inner)
    Sha1Ctx outer;
    outer.update(opad.data(), opad.size());
    outer.update(innerHash.data(), innerHash.size());
    auto result = outer.finalize();

    return Bytes(result.begin(), result.end());
}

Bytes HashPassword::pbkdf2Sha1(const std::string& password,
                                 const Bytes& salt,
                                 uint32_t iterations,
                                 uint32_t keyLen) {
    Bytes derivedKey;
    derivedKey.reserve(keyLen);

    Bytes passwordBytes(password.begin(), password.end());

    uint32_t blockNum = 1;
    while (derivedKey.size() < keyLen) {
        // U1 = HMAC-SHA1(password, salt || INT32_BE(blockNum))
        Bytes saltBlock = salt;
        saltBlock.push_back(static_cast<uint8_t>((blockNum >> 24) & 0xFF));
        saltBlock.push_back(static_cast<uint8_t>((blockNum >> 16) & 0xFF));
        saltBlock.push_back(static_cast<uint8_t>((blockNum >> 8) & 0xFF));
        saltBlock.push_back(static_cast<uint8_t>(blockNum & 0xFF));

        Bytes u = hmacSha1(passwordBytes, saltBlock);
        Bytes t = u;

        for (uint32_t i = 1; i < iterations; i++) {
            u = hmacSha1(passwordBytes, u);
            for (size_t j = 0; j < t.size(); j++) {
                t[j] ^= u[j];
            }
        }

        size_t needed = std::min(static_cast<size_t>(keyLen) - derivedKey.size(), t.size());
        derivedKey.insert(derivedKey.end(), t.begin(), t.begin() + needed);
        blockNum++;
    }

    return derivedKey;
}

Bytes HashPassword::sedutilHash(const std::string& password,
                                  const Bytes& driveSerial,
                                  uint32_t iterations,
                                  uint32_t keyLen) {
    // sedutil-cli (DTA fork) DtaHashPwd:
    //   gPBKDF2-HMAC-SHA1(password, drive_serial, 75000, derivedkey_len=32)
    // Wire form: D0 20 [32 bytes].
    return pbkdf2Sha1(password, driveSerial, iterations, keyLen);
}

} // namespace libsed
