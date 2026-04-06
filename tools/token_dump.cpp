/// @file token_dump.cpp
/// CLI tool: Parse and display TCG token streams from hex input or files

#include <cats.h>
#include <libsed/codec/token_encoder.h>
#include <libsed/codec/token_decoder.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>

using namespace libsed;

static Bytes hexToBytes(const std::string& hex) {
    Bytes result;
    for (size_t i = 0; i < hex.size(); i += 2) {
        while (i < hex.size() && (hex[i] == ' ' || hex[i] == ':' || hex[i] == '\n')) ++i;
        if (i + 1 >= hex.size()) break;
        auto b = static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16));
        result.push_back(b);
    }
    return result;
}

static void printHex(const Bytes& data, size_t indent = 0) {
    std::string pad(indent, ' ');
    for (size_t i = 0; i < data.size(); ++i) {
        if (i > 0 && i % 16 == 0) std::cout << "\n" << pad;
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]) << " ";
    }
    std::cout << std::dec << "\n";
}

static void dumpToken(const Token& tok, int depth = 0) {
    std::string indent(depth * 2, ' ');

    switch (tok.type) {
        case TokenType::StartList:
            std::cout << indent << "[\n";
            break;
        case TokenType::EndList:
            std::cout << indent << "]\n";
            break;
        case TokenType::StartName:
            std::cout << indent << "{\n";
            break;
        case TokenType::EndName:
            std::cout << indent << "}\n";
            break;
        case TokenType::Call:
            std::cout << indent << "CALL\n";
            break;
        case TokenType::EndOfData:
            std::cout << indent << "END_OF_DATA\n";
            break;
        case TokenType::EndOfSession:
            std::cout << indent << "END_OF_SESSION\n";
            break;
        case TokenType::StartTransaction:
            std::cout << indent << "START_TRANSACTION\n";
            break;
        case TokenType::EndTransaction:
            std::cout << indent << "END_TRANSACTION\n";
            break;
        case TokenType::EmptyAtom:
            std::cout << indent << "EMPTY\n";
            break;
        default:
            if (tok.isByteSequence) {
                auto bytes = tok.getBytes();
                if (bytes.size() == 8) {
                    // Likely a UID
                    uint64_t uid = 0;
                    for (auto b : bytes) uid = (uid << 8) | b;
                    std::cout << indent << "UID: 0x" << std::hex << std::setw(16)
                              << std::setfill('0') << uid << std::dec;

                    // Known UIDs
                    if (uid == 0x0000000000000001ULL) std::cout << " (SMUID)";
                    else if (uid == 0x0000000000000005ULL) std::cout << " (THIS_SP)";
                    else if (uid == 0x0000000900000000ULL) std::cout << " (AUTH_SID)";
                    else if (uid == 0x0000020500000001ULL) std::cout << " (SP_ADMIN)";
                    else if (uid == 0x0000020500000002ULL) std::cout << " (SP_LOCKING)";
                    else if ((uid >> 32) == 0x0000000B) std::cout << " (C_PIN)";

                    std::cout << "\n";
                } else {
                    std::cout << indent << "BYTES[" << bytes.size() << "]: ";
                    printHex(bytes, indent.size() + 12);
                }
            } else if (tok.isSigned) {
                std::cout << indent << "INT: " << tok.getInt() << "\n";
            } else {
                std::cout << indent << "UINT: " << tok.getUint() << "\n";
            }
            break;
    }
}

static void dumpTokens(const std::vector<Token>& tokens) {
    int depth = 0;
    for (const auto& tok : tokens) {
        if (tok.type == TokenType::EndList || tok.type == TokenType::EndName) {
            --depth;
        }
        dumpToken(tok, depth);
        if (tok.type == TokenType::StartList || tok.type == TokenType::StartName) {
            ++depth;
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage:\n"
                  << "  " << argv[0] << " <hex_string>\n"
                  << "  " << argv[0] << " -f <binary_file>\n"
                  << "  echo 'F0 A8 00 ... ' | " << argv[0] << " -\n\n"
                  << "Parses TCG token streams and displays decoded tokens.\n";
        return 1;
    }

    Bytes data;

    if (std::string(argv[1]) == "-f" && argc > 2) {
        // Read from binary file
        std::ifstream file(argv[2], std::ios::binary);
        if (!file) { std::cerr << "Cannot open: " << argv[2] << "\n"; return 1; }
        data = Bytes(std::istreambuf_iterator<char>(file), {});
    } else if (std::string(argv[1]) == "-") {
        // Read hex from stdin
        std::string input((std::istreambuf_iterator<char>(std::cin)), {});
        data = hexToBytes(input);
    } else {
        // Parse hex argument
        std::string hexInput;
        for (int i = 1; i < argc; ++i) {
            hexInput += argv[i];
        }
        data = hexToBytes(hexInput);
    }

    if (data.empty()) {
        std::cerr << "No data to parse\n";
        return 1;
    }

    std::cout << "Input (" << data.size() << " bytes):\n  ";
    printHex(data, 2);
    std::cout << "\nDecoded tokens:\n";

    TokenDecoder decoder;
    auto r = decoder.decode(data);
    if (r.failed()) {
        std::cerr << "Decode error: " << r.message() << "\n";
        return 1;
    }

    std::cout << "(" << decoder.count() << " tokens)\n\n";
    dumpTokens(decoder.tokens());

    return 0;
}
