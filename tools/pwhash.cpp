/// @file pwhash.cpp
/// @brief Password hash 출력 도구 — 진단/wire-dump 검증용.
///
/// 사용 예:
///   pwhash "TestSIDPassword123"           → SHA-256 (cats native)
///   pwhash --sedutil --serial XXX pw     → PBKDF2-HMAC-SHA1 (sedutil-compat)
///
/// 출력된 32-byte hex 를 wire dump 와 대조하면 setCPin 과 startSession-
/// WithAuth 가 정말 같은 PIN bytes 를 보내는지 단정 가능.
///   - 둘 다 같은 hex 를 포함 → cats 내부 일관, 드라이브가 거부 시 다른 원인
///   - 둘이 다른 hex → cats 내부 wire bug

#include <libsed/security/hash_password.h>
#include <cstdio>
#include <cstring>
#include <string>

using namespace libsed;

static void printHex(const Bytes& b) {
    for (auto x : b) std::printf("%02x", x);
    std::printf("\n");
}

static void printSpacedHex(const Bytes& b) {
    // wire dump 의 hexdump (4-char 그룹) 형식과 매칭하기 쉽게.
    for (size_t i = 0; i < b.size(); ++i) {
        std::printf("%02x", b[i]);
        if (i % 2 == 1 && i + 1 < b.size()) std::printf(" ");
    }
    std::printf("\n");
}

int main(int argc, char* argv[]) {
    bool sedutilMode = false;
    std::string serialHex;
    std::string password;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--sedutil") sedutilMode = true;
        else if (a == "--serial" && i + 1 < argc) serialHex = argv[++i];
        else if (a == "-h" || a == "--help") {
            std::printf("Usage:\n"
                        "  %s <password>                          # SHA-256 (cats native)\n"
                        "  %s --sedutil --serial <20-hex> <password>\n"
                        "                                          # PBKDF2-HMAC-SHA1 (sedutil-compat)\n"
                        "  --serial: 20 ASCII byte serial as hex (40 chars).\n"
                        "            tip: get from `nvme id-ctrl /dev/nvmeX | grep -i sn`\n",
                        argv[0], argv[0]);
            return 0;
        }
        else password = a;
    }

    if (password.empty()) {
        std::fprintf(stderr, "error: password required (-h for help)\n");
        return 1;
    }

    if (sedutilMode) {
        if (serialHex.size() != 40) {
            std::fprintf(stderr,
                "error: --serial must be 40 hex chars (20 bytes). got %zu\n",
                serialHex.size());
            return 1;
        }
        Bytes serial;
        for (size_t i = 0; i + 1 < serialHex.size(); i += 2) {
            unsigned v;
            if (std::sscanf(serialHex.c_str() + i, "%2x", &v) != 1) {
                std::fprintf(stderr, "error: bad hex in --serial at byte %zu\n", i/2);
                return 1;
            }
            serial.push_back(static_cast<uint8_t>(v));
        }
        auto pin = HashPassword::sedutilHash(password, serial);
        std::printf("# password = \"%s\"\n", password.c_str());
        std::printf("# salt (drive serial, 20 B): ");
        for (auto b : serial) {
            if (b >= 0x20 && b < 0x7F) std::printf("%c", b);
            else std::printf(".");
        }
        std::printf("\n");
        std::printf("# algorithm = PBKDF2-HMAC-SHA1, iter=75000, keyLen=32\n");
        std::printf("PIN bytes (32 B):\n  ");
        printSpacedHex(pin);
        std::printf("PIN bytes (no spaces):\n  ");
        printHex(pin);
    } else {
        auto pin = HashPassword::passwordToBytes(password);
        std::printf("# password = \"%s\"\n", password.c_str());
        std::printf("# algorithm = SHA-256 (cats native, libsed default)\n");
        std::printf("PIN bytes (32 B):\n  ");
        printSpacedHex(pin);
        std::printf("PIN bytes (no spaces):\n  ");
        printHex(pin);
    }

    return 0;
}
