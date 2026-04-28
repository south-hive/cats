/// @file pwhash.cpp
/// @brief Password hash 출력 도구 — 진단/wire-dump 검증용.
///
/// 사용 예:
///   pwhash "TestSIDPassword123"
///       → SHA-256 (cats native)
///
///   pwhash --sedutil --salt-hex   <hex> "pw"
///   pwhash --sedutil --salt-ascii "salt"  "pw"
///       → PBKDF2-HMAC-SHA1 (sedutil-compat) — salt 직접 지정
///
///   pwhash --sedutil --serial <hex> "pw"
///       → 위 --salt-hex 의 별칭 (기존 호출 호환)
///
/// SEDUTIL SALT SOURCE 가 무엇인지 (drive serial vs MSID) 는 sedutil 포크에
/// 따라 다르고 코드베이스 안에서도 의견이 갈림. 사용자의 실제 sedutil
/// 바이너리 wire dump 와 두 후보를 직접 비교해 결정하는 것이 정답.
///
/// 비교 방법:
///   1) sedutil 측 #23 (StartSession w/ MSID) wire dump 의 credential 32 B 추출
///   2) 동일 password=MSID, salt=serial 로 pwhash --sedutil 실행, 32 B 비교
///   3) 동일 password=MSID, salt=MSID 로 pwhash --sedutil 실행, 32 B 비교
///   4) 일치하는 쪽이 그 sedutil 포크의 진짜 salt 정책

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

static Bytes hexToBytes(const std::string& hex) {
    Bytes out;
    if (hex.size() % 2 != 0) return out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        unsigned v;
        if (std::sscanf(hex.c_str() + i, "%2x", &v) != 1) return {};
        out.push_back(static_cast<uint8_t>(v));
    }
    return out;
}

int main(int argc, char* argv[]) {
    bool sedutilMode = false;
    std::string saltHex;
    std::string saltAscii;
    bool saltHexSet = false, saltAsciiSet = false;
    std::string password;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--sedutil") sedutilMode = true;
        else if ((a == "--serial" || a == "--salt-hex") && i + 1 < argc) {
            saltHex = argv[++i]; saltHexSet = true;
        }
        else if (a == "--salt-ascii" && i + 1 < argc) {
            saltAscii = argv[++i]; saltAsciiSet = true;
        }
        else if (a == "-h" || a == "--help") {
            std::printf("Usage:\n"
                        "  %s <password>\n"
                        "      SHA-256 (cats native default)\n"
                        "\n"
                        "  %s --sedutil --salt-hex   <hex>     <password>\n"
                        "  %s --sedutil --salt-ascii <string>  <password>\n"
                        "  %s --sedutil --serial     <hex>     <password>   (alias of --salt-hex)\n"
                        "      PBKDF2-HMAC-SHA1, 75000 iter, 32 B output (sedutil-compat).\n"
                        "\n"
                        "Salt source 결정:\n"
                        "  sedutil 포크에 따라 drive serial 또는 MSID 를 salt 로 사용함.\n"
                        "  실제 sedutil wire dump 와 비교해서 어느 쪽이 일치하는지 검증할 것.\n"
                        "  serial: `sudo nvme id-ctrl /dev/nvmeX -b | xxd -p -s 4 -l 20`\n"
                        "  MSID:   `04_read_msid` 출력 또는 dump 의 CPIN_MSID Get 응답\n",
                        argv[0], argv[0], argv[0], argv[0]);
            return 0;
        }
        else password = a;
    }

    if (password.empty()) {
        std::fprintf(stderr, "error: password required (-h for help)\n");
        return 1;
    }

    if (sedutilMode) {
        if (saltHexSet == saltAsciiSet) {
            std::fprintf(stderr,
                "error: must specify exactly one of --salt-hex/--serial or --salt-ascii\n");
            return 1;
        }
        Bytes salt;
        if (saltHexSet) {
            salt = hexToBytes(saltHex);
            if (salt.empty() && !saltHex.empty()) {
                std::fprintf(stderr, "error: bad hex in salt: %s\n", saltHex.c_str());
                return 1;
            }
        } else {
            salt.assign(saltAscii.begin(), saltAscii.end());
        }

        auto pin = HashPassword::sedutilHash(password, salt);
        std::printf("# password = \"%s\"\n", password.c_str());
        std::printf("# salt (%zu B): ", salt.size());
        for (auto b : salt) {
            if (b >= 0x20 && b < 0x7F) std::printf("%c", b);
            else std::printf(".");
        }
        std::printf("\n");
        std::printf("# salt hex: ");
        for (auto b : salt) std::printf("%02x", b);
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
