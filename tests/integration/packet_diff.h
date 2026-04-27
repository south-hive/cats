#pragma once

/// @file packet_diff.h
/// @brief Shared packet comparison and diagnostic utilities for TCG SED validators.
///
/// Extracted from ioctl_validator.cpp for reuse by golden_validator.
/// Provides: hex dump, TCG header field names, byte-by-byte diff, token stream decoder.

#include <libsed/core/endian.h>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <vector>
#include <algorithm>

namespace libsed {
namespace test {

using Packet = std::vector<uint8_t>;

// ═══════════════════════════════════════════════════════
//  Hex dump
// ═══════════════════════════════════════════════════════

inline void hexDump(const char* label, const uint8_t* data, size_t len, size_t maxBytes = 0) {
    printf("=== %s (%zu bytes) ===\n", label, len);
    size_t limit = (maxBytes > 0) ? std::min(len, maxBytes) : len;
    for (size_t i = 0; i < limit; i += 16) {
        printf("  %04zX: ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < limit) printf("%02X ", data[i + j]);
            else printf("   ");
            if (j == 7) printf(" ");
        }
        printf(" |");
        for (size_t j = 0; j < 16 && (i + j) < limit; j++) {
            uint8_t c = data[i + j];
            printf("%c", (c >= 0x20 && c <= 0x7E) ? static_cast<char>(c) : '.');
        }
        printf("|\n");
    }
    if (limit < len) printf("  ... (%zu more bytes)\n", len - limit);
    printf("\n");
}

// ═══════════════════════════════════════════════════════
//  TCG-aware header field name
// ═══════════════════════════════════════════════════════

inline const char* headerFieldName(size_t offset) {
    if (offset < 4)  return "ComPacket.reserved";
    if (offset < 6)  return "ComPacket.comId";
    if (offset < 8)  return "ComPacket.comIdExtension";
    if (offset < 12) return "ComPacket.outstandingData";
    if (offset < 16) return "ComPacket.minTransfer";
    if (offset < 20) return "ComPacket.length";
    if (offset < 24) return "Packet.TSN";
    if (offset < 28) return "Packet.HSN";
    if (offset < 32) return "Packet.seqNumber";
    if (offset < 34) return "Packet.reserved";
    if (offset < 36) return "Packet.ackType";
    if (offset < 40) return "Packet.acknowledgement";
    if (offset < 44) return "Packet.length";
    if (offset < 50) return "SubPacket.reserved";
    if (offset < 52) return "SubPacket.kind";
    if (offset < 56) return "SubPacket.length";
    return "payload";
}

// ═══════════════════════════════════════════════════════
//  Byte-by-byte diff with TCG field labels
// ═══════════════════════════════════════════════════════

inline int diffPackets(const char* name, const Packet& a, const Packet& b) {
    size_t maxLen = std::max(a.size(), b.size());
    int diffs = 0;
    for (size_t i = 0; i < maxLen; i++) {
        uint8_t av = (i < a.size()) ? a[i] : 0;
        uint8_t bv = (i < b.size()) ? b[i] : 0;
        if (av != bv) {
            printf("    offset 0x%04zX [%s]: %s=0x%02X  ref=0x%02X",
                   i, headerFieldName(i), name, av, bv);
            if (av >= 0x20 && av <= 0x7E && bv >= 0x20 && bv <= 0x7E)
                printf("  ('%c' vs '%c')", av, bv);
            printf("\n");
            diffs++;
            if (diffs >= 50) { printf("    ... (too many diffs)\n"); break; }
        }
    }
    if (a.size() != b.size())
        printf("    Size: %s=%zu  ref=%zu\n", name, a.size(), b.size());
    return diffs;
}

// Overload for backward compatibility (ioctl_validator uses 2-arg form)
inline int diffPackets(const Packet& a, const Packet& b) {
    return diffPackets("libsed", a, b);
}

// ═══════════════════════════════════════════════════════
//  Token-payload-only diff
// ═══════════════════════════════════════════════════════
//
// Compare ONLY the token payload (offset 56 onwards, length from
// SubPacket.length). 헤더(TSN/HSN/SeqNumber/길이 필드)는 무시.
//
// 용도: 다세션 시퀀스(initialSetup 등) 의 fixture 와 cats 출력을 비교할 때
// TSN 이 달라도 인코딩 로직 자체는 동일하면 PASS 가 되도록.
// 정확한 wire-level 검증이 필요한 경우(ComID/HSN/seqNumber 등) 는 여전히
// diffPackets() 사용.

inline int diffTokenPayload(const char* name, const Packet& a, const Packet& b) {
    if (a.size() < 56 || b.size() < 56) {
        printf("    Both packets must be ≥56 bytes (got %zu, %zu)\n",
               a.size(), b.size());
        return 1;
    }
    uint32_t aLen = Endian::readBe32(a.data() + 52);
    uint32_t bLen = Endian::readBe32(b.data() + 52);
    if (aLen != bLen) {
        printf("    SubPacket.length differs: %s=%u  ref=%u\n", name, aLen, bLen);
        return 1;
    }
    if (56u + aLen > a.size() || 56u + bLen > b.size()) {
        printf("    Token payload out-of-bounds (truncated packet)\n");
        return 1;
    }
    int diffs = 0;
    for (uint32_t i = 0; i < aLen; ++i) {
        uint8_t av = a[56 + i];
        uint8_t bv = b[56 + i];
        if (av != bv) {
            printf("    payload[0x%04X]: %s=0x%02X  ref=0x%02X\n",
                   i, name, av, bv);
            ++diffs;
            if (diffs >= 50) { printf("    ... (too many diffs)\n"); break; }
        }
    }
    return diffs;
}

inline int diffTokenPayload(const Packet& a, const Packet& b) {
    return diffTokenPayload("libsed", a, b);
}

// ═══════════════════════════════════════════════════════
//  Token stream decoder
// ═══════════════════════════════════════════════════════

inline void tokenDump(const char* label, const uint8_t* data, size_t len) {
    printf("  %s tokens:\n", label);
    size_t i = 0;
    while (i < len) {
        uint8_t b = data[i];
        if (b >= 0xF0 && b <= 0xFF) {
            const char* names[] = {
                "STARTLIST","ENDLIST","STARTNAME","ENDNAME",
                "??F4","??F5","??F6","??F7",
                "CALL","ENDOFDATA","ENDOFSESSION","STARTTXN",
                "ENDTXN","??FD","??FE","EMPTY"
            };
            printf("    [%04zX] %s\n", i, names[b - 0xF0]);
            i++;
        } else if ((b & 0xC0) == 0x00) {
            printf("    [%04zX] uint: %u\n", i, b & 0x3F);
            i++;
        } else if ((b & 0xC0) == 0x40) {
            printf("    [%04zX] int: %d\n", i,
                   static_cast<int>(static_cast<int8_t>((b & 0x3F) | ((b & 0x20) ? 0xC0 : 0))));
            i++;
        } else if ((b & 0xC0) == 0x80) {
            bool isB = b & 0x20;
            size_t al = b & 0x0F;
            i++;
            if (isB) {
                bool printable = true;
                for (size_t j = 0; j < al && (i + j) < len; j++)
                    if (data[i + j] < 0x20 || data[i + j] > 0x7E) { printable = false; break; }
                if (printable && al > 0) {
                    printf("    [%04zX] \"", i - 1);
                    for (size_t j = 0; j < al; j++) printf("%c", data[i + j]);
                    printf("\"\n");
                } else {
                    printf("    [%04zX] bytes[%zu]: ", i - 1, al);
                    for (size_t j = 0; j < al; j++) printf("%02X", data[i + j]);
                    printf("\n");
                }
            } else {
                uint64_t v = 0;
                for (size_t j = 0; j < al; j++) v = (v << 8) | data[i + j];
                printf("    [%04zX] uint: %llu\n", i - 1, static_cast<unsigned long long>(v));
            }
            i += al;
        } else if ((b & 0xE0) == 0xC0) {
            bool isB = b & 0x10;
            size_t al = (static_cast<size_t>(b & 0x07) << 8) | data[i + 1];
            i += 2;
            if (isB) {
                bool printable = true;
                for (size_t j = 0; j < al && (i + j) < len; j++)
                    if (data[i + j] < 0x20 || data[i + j] > 0x7E) { printable = false; break; }
                if (printable && al > 0) {
                    printf("    [%04zX] \"", i - 2);
                    for (size_t j = 0; j < al; j++) printf("%c", data[i + j]);
                    printf("\"\n");
                } else {
                    printf("    [%04zX] bytes[%zu]: ", i - 2, al);
                    for (size_t j = 0; j < al; j++) printf("%02X", data[i + j]);
                    printf("\n");
                }
            } else {
                uint64_t v = 0;
                for (size_t j = 0; j < al; j++) v = (v << 8) | data[i + j];
                printf("    [%04zX] uint: %llu\n", i - 2, static_cast<unsigned long long>(v));
            }
            i += al;
        } else {
            printf("    [%04zX] ?? 0x%02X\n", i, b);
            i++;
        }
    }
}

// ═══════════════════════════════════════════════════════
//  Diagnostic: dump tokens + hex on failure
// ═══════════════════════════════════════════════════════

inline void dumpFailDiagnostics(const char* testLabel, const char* refLabel,
                                const Packet& test, const Packet& ref) {
    uint32_t testTokenLen = 0, refTokenLen = 0;
    if (test.size() >= 56)
        testTokenLen = Endian::readBe32(test.data() + 52);
    if (ref.size() >= 56)
        refTokenLen = Endian::readBe32(ref.data() + 52);

    if (testTokenLen > 0)
        tokenDump(testLabel, test.data() + 56, testTokenLen);
    if (refTokenLen > 0)
        tokenDump(refLabel, ref.data() + 56, refTokenLen);

    hexDump(testLabel, test.data(), test.size(), 128);
    hexDump(refLabel, ref.data(), ref.size(), 128);
}

} // namespace test
} // namespace libsed
