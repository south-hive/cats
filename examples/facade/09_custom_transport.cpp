/// @file 09_custom_transport.cpp
/// @brief Custom Transport 주입 예제 — 자체 libnvme 등 외부 transport 사용
///
/// SedDrive는 ITransport를 주입받을 수 있습니다.
/// 자체 libnvme 라이브러리 등으로 NVMe 디바이스를 열고,
/// ITransport를 구현하여 SedDrive에 주입하면 됩니다.
///
/// 이 예제는 BDF(Bus:Device:Function) 기반 NVMe transport의
/// 구현 스켈레톤과 SedDrive 주입 패턴을 보여줍니다.
///
/// 사용법: ./facade_custom_transport <bdf> [--dump]
///   예) ./facade_custom_transport 0000:03:00.0 --dump

#include <cats.h>
#include <cstdio>
#include <cstring>
#include <memory>

using namespace libsed;

// ═══════════════════════════════════════════════════════
//  BDF 기반 NVMe Transport 스켈레톤
//  실제 구현에서는 libnvme의 ioctl을 사용합니다.
// ═══════════════════════════════════════════════════════

class BdfNvmeTransport : public ITransport {
public:
    /// BDF 문자열로 디바이스 열기 (예: "0000:03:00.0")
    explicit BdfNvmeTransport(const std::string& bdf)
        : bdf_(bdf), open_(false)
    {
        // 실제 구현:
        //   fd_ = open_nvme_by_bdf(bdf);  // libnvme로 BDF 기반 열기
        //   open_ = (fd_ >= 0);
        //
        // 또는 sysfs에서 /dev/nvmeN 경로를 찾아서 열기:
        //   auto path = bdf_to_devpath(bdf);  // "/dev/nvme0"
        //   fd_ = open(path.c_str(), O_RDWR);

        // 스켈레톤: 항상 실패 (실제 구현 시 교체)
        printf("  [BdfNvmeTransport] BDF=%s (스켈레톤 — 실제 ioctl 미구현)\n", bdf.c_str());
        open_ = false;
    }

    ~BdfNvmeTransport() override {
        close();
    }

    Result ifSend(uint8_t protocolId, uint16_t comId, ByteSpan payload) override {
        if (!open_) return Result(ErrorCode::TransportOpenFailed);

        // 실제 구현:
        //   struct nvme_security_send cmd = {};
        //   cmd.secp = protocolId;
        //   cmd.spsp = comId;
        //   cmd.tl = payload.size();
        //   cmd.data = payload.data();
        //   return ioctl(fd_, NVME_IOCTL_SECURITY_SEND, &cmd) == 0
        //          ? Result::success() : Result(ErrorCode::TransportSendFailed);

        (void)protocolId; (void)comId; (void)payload;
        return Result(ErrorCode::TransportSendFailed);
    }

    Result ifRecv(uint8_t protocolId, uint16_t comId,
                  MutableByteSpan buffer, size_t& bytesReceived) override {
        if (!open_) return Result(ErrorCode::TransportOpenFailed);

        // 실제 구현:
        //   struct nvme_security_recv cmd = {};
        //   cmd.secp = protocolId;
        //   cmd.spsp = comId;
        //   cmd.al = buffer.size();
        //   cmd.data = buffer.data();
        //   int ret = ioctl(fd_, NVME_IOCTL_SECURITY_RECV, &cmd);
        //   bytesReceived = cmd.al;
        //   return ret == 0 ? Result::success() : Result(ErrorCode::TransportRecvFailed);

        (void)protocolId; (void)comId; (void)buffer;
        bytesReceived = 0;
        return Result(ErrorCode::TransportRecvFailed);
    }

    TransportType type() const override { return TransportType::NVMe; }
    std::string devicePath() const override { return bdf_; }
    bool isOpen() const override { return open_; }
    void close() override { open_ = false; }

private:
    std::string bdf_;
    bool open_;
    // int fd_ = -1;  // 실제 구현 시 파일 디스크립터
};

// ═══════════════════════════════════════════════════════
//  Main
// ═══════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("사용법: %s <bdf> [--dump]\n", argv[0]);
        printf("  예) %s 0000:03:00.0 --dump\n\n", argv[0]);
        printf("이 예제는 스켈레톤입니다.\n");
        printf("실제 libnvme transport를 구현한 후 사용하세요.\n");
        printf("\n");
        printf("패턴:\n");
        printf("  1. ITransport를 구현하는 클래스 작성\n");
        printf("  2. shared_ptr<ITransport>로 SedDrive에 주입\n");
        printf("  3. drive.query() → drive.login() 등 정상 사용\n");
        return 1;
    }

    const char* bdf = argv[1];

    // ── 1. Custom transport 생성 ──
    auto transport = std::make_shared<BdfNvmeTransport>(bdf);

    // ── 2. SedDrive에 주입 ──
    SedDrive drive(transport);

    // --dump 옵션 (transport 주입 후에도 동작)
    for (int i = 2; i < argc; i++)
        if (std::strcmp(argv[i], "--dump") == 0) drive.enableDump();

    // ── 3. 정상 사용 ──
    printf("Custom transport로 드라이브 조회 중...\n");
    auto r = drive.query();
    if (r.failed()) {
        printf("조회 실패: %s\n", r.message().c_str());
        printf("\n이 스켈레톤에서는 정상입니다.\n");
        printf("BdfNvmeTransport의 ifSend/ifRecv를 구현하면 동작합니다.\n");
        return 1;
    }

    printf("SSC: %s\n", drive.sscName());
    printf("ComID: 0x%04X\n", drive.comId());

    // ComID 지정 생성자:
    // SedDrive drive(transport, 0x0001);

    return 0;
}
