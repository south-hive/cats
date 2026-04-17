// Shared helpers for the sed_compare tool — byte-for-byte packet comparison
// between libsed (cats) and sedutil-cli (DtaCommand-based).
//
// Each tier file (t1_*.cpp / t2_*.cpp) builds one sedutil-cli command's packet
// sequence on both sides and calls Section::compare() for each packet.
//
// The passwords used below are passed RAW to both sides, bypassing hashing on
// libsed (SHA-256) and sedutil (PBKDF2 w/MSID salt). The wire format carries
// whatever PIN bytes the host supplies, so this validates the token encoding
// and packet framing independent of the host-side hashing convention.

#pragma once

#include <libsed/codec/token_encoder.h>
#include <libsed/codec/token_list.h>
#include <libsed/method/method_call.h>
#include <libsed/method/method_uids.h>
#include <libsed/method/param_encoder.h>
#include <libsed/packet/packet_builder.h>
#include <libsed/core/uid.h>

// sedutil third_party
#include "os.h"
#include "DtaStructures.h"
#include "DtaEndianFixup.h"
#include "DtaCommand.h"

#include "integration/packet_diff.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <cstdio>

namespace sed_compare {

using namespace libsed;
using namespace libsed::test;

constexpr uint16_t COMID = 0x0001;
constexpr uint32_t HSN   = 105;

// ── Counters (populated by Section) ──────────────────────────────────
struct Totals { int pass = 0; int fail = 0; };
Totals& totals();

// ── Section: one sedutil-cli command's banner + PASS/FAIL per packet ─
class Section {
public:
    explicit Section(const std::string& commandLine);
    ~Section();

    // Compare one packet. stepName shows the logical step within the cmd.
    void compare(const std::string& stepName,
                 const Packet& cats, const Packet& ref);

private:
    std::string cmd_;
    int step_ = 0;
    int pass_ = 0;
    int fail_ = 0;
};

// ── Sedutil DtaCommand → Packet extractor ────────────────────────────
// DtaCommand stores TSN/HSN in host byte order; swap to BE for wire-level
// comparison against libsed's PacketBuilder output.
Packet extractSedutilPacket(DtaCommand& cmd, uint32_t tsn, uint32_t hsn);

// ── Shared builders: StartSession / CloseSession / RevertSP ──────────
// These appear in nearly every sedutil-cli command; factor them out so
// each tier file can call one line per StartSession/CloseSession pair.

// StartSession: AdminSP anonymous (no credentials, no authority)
void compareStartSessionAnon(Section& sec, const std::string& stepName,
                             uint64_t spUid, bool write);

// StartSession: AdminSP or LockingSP with Challenge + HostSigningAuthority
void compareStartSessionAuth(Section& sec, const std::string& stepName,
                             uint64_t spUid, bool write,
                             const Bytes& challenge, uint64_t authUid);

// CloseSession (single END_OF_SESSION token, 0xFA)
void compareCloseSession(Section& sec, const std::string& stepName,
                         uint32_t tsn);

// RevertSP on a given SP
void compareRevertSP(Section& sec, const std::string& stepName,
                     uint32_t tsn, uint64_t spUid);

// ── Properties exchange ──────────────────────────────────────────────
void compareProperties(Section& sec, const std::string& stepName);

} // namespace sed_compare
