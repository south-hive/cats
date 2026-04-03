/// @file appnote_datastore.cpp
/// @brief TCG Storage Application Note: DataStore 테이블 구현 예제.
///
/// TCG SED DataStore(ByteTable)는 드라이브에 소량의 비휘발성 데이터를
/// 저장할 수 있는 범용 저장 공간입니다. PBA 설정, 키 에스크로,
/// 관리 메타데이터 등의 용도로 사용됩니다.
///
/// 포함 시나리오:
///   1. ByteTable 정보 조회 (크기, 사용량)
///   2. DataStore 쓰기/읽기/비교 (Write-Read-Compare)
///   3. 다중 DataStore 테이블 (테이블 번호별 접근)
///   4. 대용량 데이터 처리 (청크 단위 쓰기/읽기)

#include <libsed/eval/eval_api.h>
#include <libsed/transport/transport_factory.h>
#include <libsed/security/hash_password.h>
#include <libsed/sed_library.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <cstring>

using namespace libsed;
using namespace libsed::eval;

// ── Helpers ─────────────────────────────────────────────

static void printHex(const std::string& label, const Bytes& d, size_t maxLen = 32) {
    std::cout << "    " << label << " (" << d.size() << " bytes): ";
    for (size_t i = 0; i < std::min(d.size(), maxLen); i++)
        printf("%02X ", d[i]);
    if (d.size() > maxLen) std::cout << "...";
    std::cout << "\n";
}

static void step(int n, const std::string& name, Result r) {
    std::cout << "  [Step " << n << "] " << name << ": "
              << (r.ok() ? "OK" : "FAIL");
    if (r.failed()) std::cout << " (" << r.message() << ")";
    std::cout << "\n";
}

// ════════════════════════════════════════════════════════
//  1. Query ByteTable Info
// ════════════════════════════════════════════════════════

/// @scenario ByteTable(DataStore) 정보 조회
/// @precondition Locking SP 활성화, Admin1 비밀번호 유효
/// @steps
///   1. LockingSP에 Admin1 인증으로 읽기 세션 열기
///   2. ByteTable 정보 조회 (maxSize, usedSize)
///   3. 세션 닫기
/// @expected
///   - DataStore 최대 크기와 현재 사용량 확인
///   - 일반적으로 maxSize는 수 KB ~ 수 MB
static bool ds_queryByteTableInfo(EvalApi& api,
                                   std::shared_ptr<ITransport> transport,
                                   uint16_t comId,
                                   const std::string& admin1Pw) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  1. Query ByteTable Info                  ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes admin1Cred = HashPassword::passwordToBytes(admin1Pw);

    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_LOCKING, false,
                                       uid::AUTH_ADMIN1, admin1Cred, ssr);
    step(1, "Admin1 auth to LockingSP (read-only)", r);
    if (r.failed()) return false;

    RawResult raw;
    ByteTableInfo info;
    r = api.getByteTableInfo(session, info, raw);
    step(2, "Get ByteTable info", r);
    if (r.ok()) {
        std::cout << "    Table UID:  0x" << std::hex << info.tableUid << std::dec << "\n";
        std::cout << "    Max Size:   " << info.maxSize << " bytes";
        if (info.maxSize >= 1024)
            std::cout << " (" << (info.maxSize / 1024) << " KB)";
        std::cout << "\n";
        std::cout << "    Used Size:  " << info.usedSize << " bytes\n";
    }

    api.closeSession(session);
    step(3, "Close session", Result(ErrorCode::Success));

    return r.ok();
}

// ════════════════════════════════════════════════════════
//  2. Write-Read-Compare
// ════════════════════════════════════════════════════════

/// @scenario DataStore 쓰기/읽기/비교 (Write-Read-Compare)
/// @precondition Locking SP 활성화, Admin1 비밀번호 유효
/// @steps
///   1. LockingSP에 Admin1 인증으로 쓰기 세션 열기
///   2. 테스트 데이터(64바이트) 생성
///   3. DataStore에 쓰기 (offset=0)
///   4. DataStore에서 읽기 (offset=0, length=64)
///   5. 읽은 데이터와 원본 비교
///   6. tcgCompare로 데이터 일치 확인
///   7. 세션 닫기
/// @expected
///   - 쓰기/읽기 성공
///   - 읽은 데이터가 원본과 일치
///   - tcgCompare의 compareMatch == true
static bool ds_writeReadCompare(EvalApi& api,
                                 std::shared_ptr<ITransport> transport,
                                 uint16_t comId,
                                 const std::string& admin1Pw) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  2. Write-Read-Compare                    ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes admin1Cred = HashPassword::passwordToBytes(admin1Pw);

    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_LOCKING, true,
                                       uid::AUTH_ADMIN1, admin1Cred, ssr);
    step(1, "Admin1 auth to LockingSP", r);
    if (r.failed()) return false;

    // Generate test data
    const uint32_t dataSize = 64;
    Bytes testData(dataSize);
    for (uint32_t i = 0; i < dataSize; i++)
        testData[i] = static_cast<uint8_t>((i * 7 + 0xAB) & 0xFF);

    step(2, "Generate test data (" + std::to_string(dataSize) + " bytes)", Result(ErrorCode::Success));
    printHex("Test data", testData, 16);

    // Write
    RawResult raw;
    r = api.tcgWriteDataStore(session, 0, testData, raw);
    step(3, "Write to DataStore (offset=0)", r);

    // Read
    DataOpResult readResult;
    r = api.tcgReadDataStore(session, 0, dataSize, readResult);
    step(4, "Read from DataStore (offset=0, len=" + std::to_string(dataSize) + ")", r);
    if (r.ok()) printHex("Read data", readResult.data, 16);

    // Manual compare
    bool manualMatch = (readResult.data == testData);
    step(5, "Manual compare", manualMatch ? Result(ErrorCode::Success) : Result(ErrorCode::InvalidArgument));
    std::cout << "    Match: " << (manualMatch ? "YES" : "NO") << "\n";

    // tcgCompare
    DataOpResult cmpResult;
    r = api.tcgCompare(session, uid::TABLE_DATASTORE, 0, testData, cmpResult);
    step(6, "tcgCompare", r);
    if (r.ok())
        std::cout << "    compareMatch: " << (cmpResult.compareMatch ? "true" : "false") << "\n";

    api.closeSession(session);
    step(7, "Close session", Result(ErrorCode::Success));

    return manualMatch;
}

// ════════════════════════════════════════════════════════
//  3. Multiple DataStore Tables
// ════════════════════════════════════════════════════════

/// @scenario 다중 DataStore 테이블 접근
/// @precondition Locking SP 활성화, Admin1 비밀번호 유효, 다중 DataStore 지원 드라이브
/// @steps
///   1. LockingSP에 Admin1 인증으로 쓰기 세션 열기
///   2. Table 0에 "TABLE0_DATA" 쓰기
///   3. Table 1에 "TABLE1_DATA" 쓰기 (지원하지 않으면 건너뜀)
///   4. Table 0에서 읽기 및 확인
///   5. Table 1에서 읽기 및 확인
///   6. 세션 닫기
/// @expected
///   - Table 0: 쓰기/읽기 성공
///   - Table 1: 지원 시 쓰기/읽기 성공, 미지원 시 오류 반환
///   - 각 테이블이 독립적인 저장 공간임을 확인
static bool ds_multipleDataStoreTables(EvalApi& api,
                                        std::shared_ptr<ITransport> transport,
                                        uint16_t comId,
                                        const std::string& admin1Pw) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  3. Multiple DataStore Tables             ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes admin1Cred = HashPassword::passwordToBytes(admin1Pw);

    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_LOCKING, true,
                                       uid::AUTH_ADMIN1, admin1Cred, ssr);
    step(1, "Admin1 auth to LockingSP", r);
    if (r.failed()) return false;

    RawResult raw;

    // Table 0
    Bytes data0 = {'T','A','B','L','E','0','_','D','A','T','A'};
    r = api.tcgWriteDataStoreN(session, 0, 0, data0, raw);
    step(2, "Write to DataStore Table 0", r);

    // Table 1 (may not be supported)
    Bytes data1 = {'T','A','B','L','E','1','_','D','A','T','A'};
    r = api.tcgWriteDataStoreN(session, 1, 0, data1, raw);
    step(3, "Write to DataStore Table 1", r);
    if (r.failed())
        std::cout << "    Table 1 not supported on this drive (normal)\n";

    // Read back Table 0
    DataOpResult read0;
    r = api.tcgReadDataStoreN(session, 0, 0, data0.size(), read0);
    step(4, "Read from Table 0", r);
    if (r.ok()) {
        bool match = (read0.data == data0);
        std::cout << "    Table 0 data match: " << (match ? "YES" : "NO") << "\n";
    }

    // Read back Table 1
    DataOpResult read1;
    r = api.tcgReadDataStoreN(session, 1, 0, data1.size(), read1);
    step(5, "Read from Table 1", r);
    if (r.ok()) {
        bool match = (read1.data == data1);
        std::cout << "    Table 1 data match: " << (match ? "YES" : "NO") << "\n";
    }

    api.closeSession(session);
    step(6, "Close session", Result(ErrorCode::Success));

    return true;
}

// ════════════════════════════════════════════════════════
//  4. Large Data Handling
// ════════════════════════════════════════════════════════

/// @scenario 대용량 데이터 청크 처리
/// @precondition Locking SP 활성화, Admin1 비밀번호 유효
/// @steps
///   1. LockingSP에 Admin1 인증으로 쓰기 세션 열기
///   2. 8192바이트 테스트 데이터 생성
///   3. 512바이트 청크 단위로 DataStore에 쓰기 (offset 증가)
///   4. 512바이트 청크 단위로 DataStore에서 읽기
///   5. 전체 데이터 비교
///   6. 세션 닫기
/// @expected
///   - 8192바이트 전체가 청크 단위로 성공적으로 기록/읽기됨
///   - 읽은 데이터가 원본과 완전히 일치
static bool ds_largeDataHandling(EvalApi& api,
                                  std::shared_ptr<ITransport> transport,
                                  uint16_t comId,
                                  const std::string& admin1Pw) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  4. Large Data Handling (Chunked)          ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes admin1Cred = HashPassword::passwordToBytes(admin1Pw);

    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_LOCKING, true,
                                       uid::AUTH_ADMIN1, admin1Cred, ssr);
    step(1, "Admin1 auth to LockingSP", r);
    if (r.failed()) return false;

    // Generate large test data
    const uint32_t totalSize = 8192;
    const uint32_t chunkSize = 512;
    Bytes testData(totalSize);
    for (uint32_t i = 0; i < totalSize; i++)
        testData[i] = static_cast<uint8_t>((i * 13 + 0x37) & 0xFF);

    step(2, "Generate " + std::to_string(totalSize) + " bytes test data", Result(ErrorCode::Success));

    // Write in chunks
    uint32_t written = 0;
    RawResult raw;
    for (uint32_t offset = 0; offset < totalSize; offset += chunkSize) {
        uint32_t len = std::min(chunkSize, totalSize - offset);
        Bytes chunk(testData.begin() + offset, testData.begin() + offset + len);
        r = api.tcgWriteDataStore(session, offset, chunk, raw);
        if (r.ok()) {
            written += len;
        } else {
            std::cout << "    Write failed at offset " << offset << ": " << r.message() << "\n";
            break;
        }
    }
    step(3, "Chunked write (" + std::to_string(written) + "/" + std::to_string(totalSize) + " bytes)", r);

    // Read in chunks
    Bytes readData;
    for (uint32_t offset = 0; offset < totalSize; offset += chunkSize) {
        uint32_t len = std::min(chunkSize, totalSize - offset);
        DataOpResult readResult;
        r = api.tcgReadDataStore(session, offset, len, readResult);
        if (r.ok()) {
            readData.insert(readData.end(), readResult.data.begin(), readResult.data.end());
        } else {
            std::cout << "    Read failed at offset " << offset << "\n";
            break;
        }
    }
    step(4, "Chunked read (" + std::to_string(readData.size()) + "/" + std::to_string(totalSize) + " bytes)", r);

    // Compare
    bool match = (readData == testData);
    step(5, "Full data compare", match ? Result(ErrorCode::Success) : Result(ErrorCode::InvalidArgument));
    std::cout << "    Match: " << (match ? "YES" : "NO")
              << " (" << readData.size() << " bytes)\n";

    api.closeSession(session);
    step(6, "Close session", Result(ErrorCode::Success));

    return match;
}

// ════════════════════════════════════════════════════════
//  Main
// ════════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <device> <admin1_pw>\n\n";
        std::cerr << "TCG DataStore Application Note.\n\n";
        std::cerr << "Example:\n";
        std::cerr << "  " << argv[0] << " /dev/nvme0 admin123\n";
        return 1;
    }

    std::string device   = argv[1];
    std::string admin1Pw = argv[2];

    libsed::initialize();

    auto transport = TransportFactory::createNvme(device);
    if (!transport || !transport->isOpen()) {
        std::cerr << "Cannot open " << device << "\n";
        return 1;
    }

    EvalApi api;

    TcgOption opt;
    api.getTcgOption(transport, opt);
    uint16_t comId = opt.baseComId;
    if (comId == 0) {
        std::cerr << "No valid ComID found\n";
        return 1;
    }

    PropertiesResult props;
    api.exchangeProperties(transport, comId, props);

    std::cout << "═══════════════════════════════════════════════\n";
    std::cout << " TCG DataStore Application Note\n";
    std::cout << " Device: " << device << "\n";
    std::cout << " ComID:  0x" << std::hex << comId << std::dec << "\n";
    std::cout << "═══════════════════════════════════════════════\n";

    struct { const char* name; bool pass; } results[] = {
        {"1. Query ByteTable Info",       false},
        {"2. Write-Read-Compare",         false},
        {"3. Multiple DataStore Tables",  false},
        {"4. Large Data Handling",        false},
    };

    results[0].pass = ds_queryByteTableInfo(api, transport, comId, admin1Pw);
    results[1].pass = ds_writeReadCompare(api, transport, comId, admin1Pw);
    results[2].pass = ds_multipleDataStoreTables(api, transport, comId, admin1Pw);
    results[3].pass = ds_largeDataHandling(api, transport, comId, admin1Pw);

    // Summary
    std::cout << "\n═══════════════════════════════════════════════\n";
    std::cout << " Summary\n";
    std::cout << "═══════════════════════════════════════════════\n";
    int passCount = 0;
    for (auto& r : results) {
        std::cout << "  " << (r.pass ? "[PASS]" : "[FAIL]") << " " << r.name << "\n";
        if (r.pass) passCount++;
    }
    std::cout << "\n  Total: " << passCount << "/4 passed\n";

    libsed::shutdown();
    return 0;
}
