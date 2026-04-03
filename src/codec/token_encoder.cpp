#include "libsed/codec/token_encoder.h"
#include "libsed/core/log.h"
#include <cassert>

namespace libsed {

// ══════════════════════════════════════════════════════
//  Unsigned integer encoding
// ══════════════════════════════════════════════════════
void TokenEncoder::encodeUint(uint64_t val) {
    // Tiny atom unsigned: 0-63 (single byte, bit 7 = 0, bit 6 = 0)
    if (val <= 63) {
        encodeTinyAtomUnsigned(static_cast<uint8_t>(val));
        return;
    }

    // Short/medium/long atom: encode as unsigned integer bytes
    size_t nBytes = Endian::minBytesUnsigned(val);

    if (nBytes <= 15) {
        uint8_t buf[8];
        size_t idx = 0;
        for (int i = static_cast<int>(nBytes) - 1; i >= 0; --i) {
            buf[idx++] = static_cast<uint8_t>((val >> (i * 8)) & 0xFF);
        }
        encodeShortAtom(false, false, buf, nBytes);
    } else {
        // Should not happen for uint64_t (max 8 bytes)
        uint8_t buf[8];
        size_t idx = 0;
        for (int i = static_cast<int>(nBytes) - 1; i >= 0; --i) {
            buf[idx++] = static_cast<uint8_t>((val >> (i * 8)) & 0xFF);
        }
        encodeMediumAtom(false, false, buf, nBytes);
    }
}

// ══════════════════════════════════════════════════════
//  Signed integer encoding
// ══════════════════════════════════════════════════════
void TokenEncoder::encodeInt(int64_t val) {
    // Tiny atom signed: -32 to 31 (single byte, bit 7 = 0, bit 6 = 1)
    if (val >= -32 && val <= 31) {
        encodeTinyAtomSigned(static_cast<int8_t>(val));
        return;
    }

    size_t nBytes = Endian::minBytesSigned(val);

    if (nBytes <= 15) {
        uint8_t buf[8];
        uint64_t uval = static_cast<uint64_t>(val);
        size_t idx = 0;
        for (int i = static_cast<int>(nBytes) - 1; i >= 0; --i) {
            buf[idx++] = static_cast<uint8_t>((uval >> (i * 8)) & 0xFF);
        }
        encodeShortAtom(false, true, buf, nBytes);
    } else {
        uint8_t buf[8];
        uint64_t uval = static_cast<uint64_t>(val);
        size_t idx = 0;
        for (int i = static_cast<int>(nBytes) - 1; i >= 0; --i) {
            buf[idx++] = static_cast<uint8_t>((uval >> (i * 8)) & 0xFF);
        }
        encodeMediumAtom(false, true, buf, nBytes);
    }
}

// ══════════════════════════════════════════════════════
//  Byte sequence encoding
// ══════════════════════════════════════════════════════
void TokenEncoder::encodeBytes(const uint8_t* data, size_t len) {
    if (len == 0) {
        // Empty byte sequence: short atom with bytestring=1, signed=0, length=0
        encodeShortAtom(true, false, nullptr, 0);
    } else if (len <= 15) {
        encodeShortAtom(true, false, data, len);
    } else if (len <= 2047) {
        encodeMediumAtom(true, false, data, len);
    } else {
        encodeLongAtom(true, false, data, len);
    }
}

// ══════════════════════════════════════════════════════
//  Tiny atom (single byte)
// ══════════════════════════════════════════════════════
void TokenEncoder::encodeTinyAtomUnsigned(uint8_t val) {
    // Format: 0b00xxxxxx (top bit = 0, sign bit = 0, value in bits 0-5)
    assert(val <= 63);
    buffer_.push_back(val & 0x3F);
}

void TokenEncoder::encodeTinyAtomSigned(int8_t val) {
    // Format: 0b01xxxxxx (top bit = 0, sign bit = 1, value in bits 0-5)
    assert(val >= -32 && val <= 31);
    uint8_t byte = 0x40 | (static_cast<uint8_t>(val) & 0x3F);
    buffer_.push_back(byte);
}

// ══════════════════════════════════════════════════════
//  Short atom: 1 header byte + up to 15 data bytes
//  Format: 1b|s|l|llll
//    b = byte/integer, s = signed, llll = length (0-15)
// ══════════════════════════════════════════════════════
void TokenEncoder::encodeShortAtom(bool isByte, bool isSigned,
                                     const uint8_t* data, size_t len) {
    assert(len <= 15);
    uint8_t header = 0x80;  // top bit = 1, next bit = 0 → short atom
    if (isByte)   header |= 0x20;  // bit 5
    if (isSigned) header |= 0x10;  // bit 4
    header |= static_cast<uint8_t>(len & 0x0F);  // bits 0-3

    buffer_.push_back(header);
    if (data && len > 0) {
        buffer_.insert(buffer_.end(), data, data + len);
    }
}

// ══════════════════════════════════════════════════════
//  Medium atom: 2 header bytes + up to 2047 data bytes
//  Format: 110b|s|lll llllllll
// ══════════════════════════════════════════════════════
void TokenEncoder::encodeMediumAtom(bool isByte, bool isSigned,
                                      const uint8_t* data, size_t len) {
    assert(len <= 2047);
    uint8_t header0 = 0xC0;  // top 3 bits = 110
    if (isByte)   header0 |= 0x10;  // bit 4
    if (isSigned) header0 |= 0x08;  // bit 3
    header0 |= static_cast<uint8_t>((len >> 8) & 0x07);  // bits 0-2 = len high

    uint8_t header1 = static_cast<uint8_t>(len & 0xFF);

    buffer_.push_back(header0);
    buffer_.push_back(header1);
    if (data && len > 0) {
        buffer_.insert(buffer_.end(), data, data + len);
    }
}

// ══════════════════════════════════════════════════════
//  Long atom: 4 header bytes + up to 16M data bytes
//  Format: 11100b|s|0 length[3]
// ══════════════════════════════════════════════════════
void TokenEncoder::encodeLongAtom(bool isByte, bool isSigned,
                                    const uint8_t* data, size_t len) {
    assert(len <= 0x00FFFFFF); // 16MB max
    uint8_t header0 = 0xE0;  // top 5 bits = 11100
    if (isByte)   header0 |= 0x04;  // bit 2 (B flag)
    if (isSigned) header0 |= 0x02;  // bit 1 (S flag)
    // bit 0 is reserved (0)

    buffer_.push_back(header0);
    buffer_.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
    buffer_.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
    buffer_.push_back(static_cast<uint8_t>(len & 0xFF));

    if (data && len > 0) {
        buffer_.insert(buffer_.end(), data, data + len);
    }
}

} // namespace libsed
