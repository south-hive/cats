/// @file props_diff.cpp
/// @brief libsed vs sedutil Properties 패킷 비교 도구
///
/// 두 방식으로 Properties ComPacket을 만들어 hex dump + diff를 출력한다.
/// Usage: ./props_diff [comid]
///   comid: ComID (기본값: 0x1004)

#include <libsed/codec/token_encoder.h>
#include <libsed/method/method_call.h>
#include <libsed/method/method_uids.h>
#include <libsed/method/param_encoder.h>
#include <libsed/packet/packet_builder.h>
#include <libsed/core/uid.h>
#include <libsed/core/endian.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <algorithm>

using namespace libsed;

// ═══════════════════════════════════════════════════════
//  sedutil 방식으로 Properties 패킷을 수동 구성
//  (DtaDevOpal.cpp properties() + DtaCommand.cpp 재현)
// ═══════════════════════════════════════════════════════

static std::vector<uint8_t> buildSedutilProperties(uint16_t comId) {
    // sedutil: IO_BUFFER_LENGTH = 2048, 헤더 56바이트 후 토큰 시작
    std::vector<uint8_t> buf(2048, 0);
    size_t pos = 56;  // OPALHeader 크기 (ComPacket 20 + Packet 24 + SubPacket 12)

    // ── Token payload (DtaDevOpal.cpp::properties() 재현) ──

    // CALL
    buf[pos++] = 0xF8;

    // InvokingUID: SMUID = 00 00 00 00 00 00 00 FF
    buf[pos++] = 0xA8;  // short atom, byte-seq, len=8
    buf[pos++] = 0x00; buf[pos++] = 0x00; buf[pos++] = 0x00; buf[pos++] = 0x00;
    buf[pos++] = 0x00; buf[pos++] = 0x00; buf[pos++] = 0x00; buf[pos++] = 0xFF;

    // MethodUID: SM_PROPERTIES = 00 00 00 00 00 00 FF 01
    buf[pos++] = 0xA8;
    buf[pos++] = 0x00; buf[pos++] = 0x00; buf[pos++] = 0x00; buf[pos++] = 0x00;
    buf[pos++] = 0x00; buf[pos++] = 0x00; buf[pos++] = 0xFF; buf[pos++] = 0x01;

    // STARTLIST (method params)
    buf[pos++] = 0xF0;

    // STARTNAME
    buf[pos++] = 0xF2;

    // "HostProperties" (14 bytes) → short atom 0xAE
    {
        const char* s = "HostProperties";
        size_t len = strlen(s);
        buf[pos++] = 0xA0 | (uint8_t)(len & 0x0F);
        memcpy(&buf[pos], s, len);
        pos += len;
    }

    // STARTLIST (host props list)
    buf[pos++] = 0xF0;

    // Helper: add named property (string key, uint value)
    auto addProp = [&](const char* name, uint32_t value) {
        buf[pos++] = 0xF2;  // STARTNAME

        // String key
        size_t slen = strlen(name);
        if (slen <= 15) {
            buf[pos++] = 0xA0 | (uint8_t)(slen & 0x0F);
        } else {
            // medium atom for strings > 15 bytes
            buf[pos++] = 0xD0 | (uint8_t)((slen >> 8) & 0x07);
            buf[pos++] = (uint8_t)(slen & 0xFF);
        }
        memcpy(&buf[pos], name, slen);
        pos += slen;

        // Uint value
        if (value < 64) {
            buf[pos++] = (uint8_t)(value & 0x3F);
        } else if (value < 0x100) {
            buf[pos++] = 0x81;
            buf[pos++] = (uint8_t)value;
        } else if (value < 0x10000) {
            buf[pos++] = 0x82;
            buf[pos++] = (uint8_t)(value >> 8);
            buf[pos++] = (uint8_t)(value & 0xFF);
        } else {
            buf[pos++] = 0x84;
            buf[pos++] = (uint8_t)(value >> 24);
            buf[pos++] = (uint8_t)(value >> 16);
            buf[pos++] = (uint8_t)(value >> 8);
            buf[pos++] = (uint8_t)(value & 0xFF);
        }

        buf[pos++] = 0xF3;  // ENDNAME
    };

    // sedutil 순서 (DtaDevOpal.cpp)
    addProp("MaxComPacketSize", 2048);
    addProp("MaxPacketSize",    2028);
    addProp("MaxIndTokenSize",  1992);
    addProp("MaxPackets",       1);
    addProp("MaxSubpackets",    1);   // ← sedutil: lowercase 'p'
    addProp("MaxMethods",       1);

    // ENDLIST (host props)
    buf[pos++] = 0xF1;

    // ENDNAME
    buf[pos++] = 0xF3;

    // ENDLIST (method params)
    buf[pos++] = 0xF1;

    // ENDOFDATA
    buf[pos++] = 0xF9;

    // Status list: [ 0, 0, 0 ]
    buf[pos++] = 0xF0;
    buf[pos++] = 0x00;
    buf[pos++] = 0x00;
    buf[pos++] = 0x00;
    buf[pos++] = 0xF1;

    size_t tokenLen = pos - 56;

    // ── Fill headers (sedutil DtaCommand::complete() 재현) ──

    // SubPacket header (offset 44-55)
    // 6 bytes reserved (already 0)
    // kind = 0 (already 0)
    // length = tokenLen
    Endian::writeBe32(&buf[52], static_cast<uint32_t>(tokenLen));

    // Pad token payload to 4-byte boundary
    while (pos % 4 != 0) pos++;

    size_t afterSubpkt = pos - 44;  // bytes from SubPacket header start

    // Packet header (offset 20-43)
    // TSN=0, HSN=0, seqNumber=0, reserved=0, ackType=0, ack=0
    // length = everything after Packet header = pos - 44
    Endian::writeBe32(&buf[40], static_cast<uint32_t>(afterSubpkt));

    // ComPacket header (offset 0-19)
    // reserved=0, ComID, ExtComID=0, outstandingData=0, minTransfer=0
    // length = everything after ComPacket header = pos - 20
    Endian::writeBe16(&buf[4], comId);
    Endian::writeBe32(&buf[16], static_cast<uint32_t>(pos - 20));

    return buf;
}

// ═══════════════════════════════════════════════════════
//  libsed 방식으로 Properties 패킷 구성
// ═══════════════════════════════════════════════════════

static std::vector<uint8_t> buildLibsedProperties(uint16_t comId) {
    ParamEncoder::HostProperties hp;
    hp.maxComPacketSize = 2048;
    hp.maxPacketSize = 2028;
    hp.maxIndTokenSize = 1992;
    hp.maxPackets = 1;
    hp.maxSubPackets = 1;
    hp.maxMethods = 1;

    Bytes params = ParamEncoder::encodeProperties(hp);
    Bytes methodTokens = MethodCall::buildSmCall(method::SM_PROPERTIES, params);

    PacketBuilder pb;
    pb.setComId(comId);
    Bytes pkt = pb.buildSessionManagerPacket(methodTokens);

    return pkt;
}

// ═══════════════════════════════════════════════════════
//  출력 유틸리티
// ═══════════════════════════════════════════════════════

static void hexDump(const char* label, const uint8_t* data, size_t len, size_t maxLines = 0) {
    printf("=== %s (%zu bytes) ===\n", label, len);
    size_t lines = 0;
    for (size_t i = 0; i < len; i += 16) {
        if (maxLines > 0 && lines >= maxLines) {
            printf("  ... (%zu more bytes)\n", len - i);
            break;
        }
        printf("  %04zX: ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len)
                printf("%02X ", data[i + j]);
            else
                printf("   ");
            if (j == 7) printf(" ");
        }
        printf(" |");
        for (size_t j = 0; j < 16 && (i + j) < len; j++) {
            uint8_t c = data[i + j];
            printf("%c", (c >= 0x20 && c <= 0x7E) ? c : '.');
        }
        printf("|\n");
        lines++;
    }
    printf("\n");
}

static void tokenDump(const char* label, const uint8_t* data, size_t len) {
    printf("=== %s Token Stream ===\n", label);
    size_t i = 0;
    while (i < len) {
        uint8_t b = data[i];
        if (b == 0xF8) { printf("  [%04zX] CALL\n", i); i++; }
        else if (b == 0xF0) { printf("  [%04zX] STARTLIST\n", i); i++; }
        else if (b == 0xF1) { printf("  [%04zX] ENDLIST\n", i); i++; }
        else if (b == 0xF2) { printf("  [%04zX] STARTNAME\n", i); i++; }
        else if (b == 0xF3) { printf("  [%04zX] ENDNAME\n", i); i++; }
        else if (b == 0xF9) { printf("  [%04zX] ENDOFDATA\n", i); i++; }
        else if (b == 0xFA) { printf("  [%04zX] ENDOFSESSION\n", i); i++; }
        else if ((b & 0xC0) == 0x00) {
            // Tiny atom unsigned
            printf("  [%04zX] tiny_uint: %u\n", i, b & 0x3F);
            i++;
        }
        else if ((b & 0xC0) == 0x40) {
            // Tiny atom signed
            int8_t val = (int8_t)((b & 0x3F) | ((b & 0x20) ? 0xC0 : 0));
            printf("  [%04zX] tiny_int: %d\n", i, val);
            i++;
        }
        else if ((b & 0xC0) == 0x80) {
            // Short atom
            bool isByte = (b & 0x20) != 0;
            bool isSigned = (b & 0x10) != 0;
            size_t alen = b & 0x0F;
            i++;
            if (isByte) {
                // Check if printable ASCII
                bool printable = true;
                for (size_t j = 0; j < alen && (i+j) < len; j++) {
                    if (data[i+j] < 0x20 || data[i+j] > 0x7E) { printable = false; break; }
                }
                if (printable && alen > 0) {
                    printf("  [%04zX] bytes[%zu]: \"", i-1, alen);
                    for (size_t j = 0; j < alen && (i+j) < len; j++) printf("%c", data[i+j]);
                    printf("\"\n");
                } else {
                    printf("  [%04zX] bytes[%zu]: ", i-1, alen);
                    for (size_t j = 0; j < alen && (i+j) < len; j++) printf("%02X", data[i+j]);
                    printf("\n");
                }
            } else {
                uint64_t val = 0;
                for (size_t j = 0; j < alen && (i+j) < len; j++)
                    val = (val << 8) | data[i+j];
                if (isSigned)
                    printf("  [%04zX] int[%zu]: %lld\n", i-1, alen, (long long)(int64_t)val);
                else
                    printf("  [%04zX] uint[%zu]: %llu\n", i-1, alen, (unsigned long long)val);
            }
            i += alen;
        }
        else if ((b & 0xE0) == 0xC0) {
            // Medium atom
            bool isByte = (b & 0x10) != 0;
            size_t alen = ((size_t)(b & 0x07) << 8) | data[i+1];
            i += 2;
            if (isByte) {
                bool printable = true;
                for (size_t j = 0; j < alen && (i+j) < len; j++) {
                    if (data[i+j] < 0x20 || data[i+j] > 0x7E) { printable = false; break; }
                }
                if (printable && alen > 0) {
                    printf("  [%04zX] bytes[%zu]: \"", i-2, alen);
                    for (size_t j = 0; j < alen && (i+j) < len; j++) printf("%c", data[i+j]);
                    printf("\"\n");
                } else {
                    printf("  [%04zX] bytes[%zu]: ", i-2, alen);
                    for (size_t j = 0; j < alen && (i+j) < len; j++) printf("%02X", data[i+j]);
                    printf("\n");
                }
            } else {
                uint64_t val = 0;
                for (size_t j = 0; j < alen && (i+j) < len; j++)
                    val = (val << 8) | data[i+j];
                printf("  [%04zX] uint[%zu]: %llu\n", i-2, alen, (unsigned long long)val);
            }
            i += alen;
        }
        else {
            printf("  [%04zX] ?? 0x%02X\n", i, b);
            i++;
        }
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
    uint16_t comId = 0x1004;
    if (argc >= 2) comId = (uint16_t)strtol(argv[1], nullptr, 0);

    auto sedutil = buildSedutilProperties(comId);
    auto libsed  = buildLibsedProperties(comId);

    // ── Headers ──
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║  Properties Packet Comparison: libsed vs sedutil    ║\n");
    printf("║  ComID: 0x%04X                                      ║\n", comId);
    printf("╚══════════════════════════════════════════════════════╝\n\n");

    // ── Header comparison ──
    printf("── ComPacket Header (offset 0-19) ──\n");
    printf("  %-20s  %-24s  %-24s\n", "Field", "libsed", "sedutil");
    printf("  %-20s  %-24s  %-24s\n", "────────────────────", "────────────────────────", "────────────────────────");

    auto cmpField32 = [&](const char* name, size_t off) {
        uint32_t lv = Endian::readBe32(libsed.data() + off);
        uint32_t sv = Endian::readBe32(sedutil.data() + off);
        const char* mark = (lv == sv) ? "" : " ← DIFF";
        printf("  %-20s  0x%08X (%u)%*s  0x%08X (%u)%s\n",
               name, lv, lv, (int)(10 - snprintf(nullptr, 0, "%u", lv)), "",
               sv, sv, mark);
    };
    auto cmpField16 = [&](const char* name, size_t off) {
        uint16_t lv = Endian::readBe16(libsed.data() + off);
        uint16_t sv = Endian::readBe16(sedutil.data() + off);
        const char* mark = (lv == sv) ? "" : " ← DIFF";
        printf("  %-20s  0x%04X%*s  0x%04X%s\n",
               name, lv, 18, "", sv, mark);
    };

    cmpField32("Reserved", 0);
    cmpField16("ComID", 4);
    cmpField16("ExtComID", 6);
    cmpField32("OutstandingData", 8);
    cmpField32("MinTransfer", 12);
    cmpField32("Length", 16);

    printf("\n── Packet Header (offset 20-43) ──\n");
    cmpField32("TSN", 20);
    cmpField32("HSN", 24);
    cmpField32("SeqNumber", 28);
    cmpField16("Reserved", 32);
    cmpField16("AckType", 34);
    cmpField32("Acknowledgement", 36);
    cmpField32("Length", 40);

    printf("\n── SubPacket Header (offset 44-55) ──\n");
    cmpField16("Reserved[0-1]", 44);
    cmpField16("Reserved[2-3]", 46);
    cmpField16("Reserved[4-5]", 48);
    cmpField16("Kind", 50);
    cmpField32("Length", 52);

    // ── Token payloads ──
    uint32_t libTokenLen  = Endian::readBe32(libsed.data() + 52);
    uint32_t sedTokenLen  = Endian::readBe32(sedutil.data() + 52);

    printf("\n");
    tokenDump("libsed", libsed.data() + 56, libTokenLen);
    tokenDump("sedutil", sedutil.data() + 56, sedTokenLen);

    // ── Byte-by-byte diff (token payload only) ──
    printf("── Token Payload Diff ──\n");
    size_t maxLen = std::max(libTokenLen, sedTokenLen);
    int diffCount = 0;
    for (size_t i = 0; i < maxLen; i++) {
        uint8_t lb = (i < libTokenLen) ? libsed[56 + i] : 0;
        uint8_t sb = (i < sedTokenLen) ? sedutil[56 + i] : 0;
        if (lb != sb) {
            printf("  offset %3zu (0x%04zX): libsed=0x%02X  sedutil=0x%02X\n",
                   i, 56 + i, lb, sb);
            diffCount++;
        }
    }
    if (libTokenLen != sedTokenLen) {
        printf("  Token length: libsed=%u  sedutil=%u\n", libTokenLen, sedTokenLen);
    }
    if (diffCount == 0 && libTokenLen == sedTokenLen) {
        printf("  *** Token payloads are IDENTICAL ***\n");
    } else {
        printf("  Total diffs: %d\n", diffCount);
    }

    // ── Full hex dump (up to data portion) ──
    printf("\n");
    size_t dumpLen = std::max((size_t)56 + maxLen + 4, (size_t)128);
    dumpLen = std::min(dumpLen, (size_t)256);
    hexDump("libsed  (full)", libsed.data(), dumpLen);
    hexDump("sedutil (full)", sedutil.data(), dumpLen);

    return (diffCount > 0 || libTokenLen != sedTokenLen) ? 1 : 0;
}
