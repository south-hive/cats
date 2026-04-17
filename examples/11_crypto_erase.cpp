/// @file 11_crypto_erase.cpp
/// @brief Crypto Erase — Instant Data Destruction via Key Rotation
///
/// TCG SPEC CONTEXT:
/// Each locking range has an associated AES encryption key (K_AES).
/// ALL data written to the range is encrypted with this key. When you
/// call GenKey on the range, the drive generates a NEW random key —
/// instantly making all previously written data unrecoverable.
///
/// This is "crypto erase" — the physical data remains on the platters/
/// NAND, but without the old key it's indistinguishable from random noise.
/// It completes in milliseconds regardless of drive size.
///
/// GenKey(K_AES_RangeN):
///   - Generates a new random AES key for Range N
///   - The old key is destroyed — data encrypted with it is gone forever
///   - The range configuration (start, length, lock settings) is preserved
///   - The range is automatically unlocked after GenKey
///
/// This is different from "Erase" (secure erase of the physical media)
/// which may take hours. Crypto erase is the standard way to sanitize
/// SED-encrypted data.
///
/// API LAYER: EvalApi + SedDrive
/// PREREQUISITES: 01-07 (need configured locking range)
///
/// Usage: ./11_crypto_erase /dev/nvmeX [--dump]

#include "example_common.h"

static std::string SID_PW;
static std::string ADMIN1_PW;

static bool setupDrive(EvalApi& api, std::shared_ptr<ITransport> transport,
                       uint16_t comId) {
    auto cr = composite::takeOwnership(api, transport, comId, SID_PW);
    if (cr.failed()) return false;

    Bytes sidPw = pwBytes(SID_PW);
    auto r = composite::withSession(api, transport, comId,
        uid::SP_ADMIN, true, uid::AUTH_SID, sidPw,
        [&](Session& s) { return api.activate(s, uid::SP_LOCKING); });
    if (r.failed()) return false;

    return composite::withSession(api, transport, comId,
        uid::SP_LOCKING, true, uid::AUTH_ADMIN1, Bytes{},
        [&](Session& s) -> Result {
            auto r2 = api.setAdmin1Password(s, ADMIN1_PW);
            if (r2.failed()) return r2;
            // Configure Range 1 with locking enabled
            return api.setRange(s, 1, 0, 1024, true, true);
        }).ok();
}

// ── Scenario 1: Crypto Erase via GenKey ──
//
// Read the active key UID before and after GenKey to confirm rotation.

static bool scenario1_genKey(std::shared_ptr<ITransport> transport,
                              uint16_t comId) {
    scenario(1, "Crypto Erase via GenKey");

    EvalApi api;
    Bytes admin1Pw = pwBytes(ADMIN1_PW);

    auto r = composite::withSession(api, transport, comId,
        uid::SP_LOCKING, true, uid::AUTH_ADMIN1, admin1Pw,
        [&](Session& session) -> Result {
            // Read current active key for Range 1
            Uid keyBefore;
            auto r2 = api.getActiveKey(session, 1, keyBefore);
            step(1, "Get active key (before)", r2);
            if (r2.ok()) {
                printf("    Active Key UID: 0x%016lx\n", keyBefore.toUint64());
            }

            // Crypto Erase!
            // This calls GenKey on the K_AES object for Range 1.
            // Internally: GenKey(K_AES_Range1)
            r2 = api.cryptoErase(session, 1);
            step(2, "cryptoErase(Range 1) — GenKey", r2);
            if (r2.failed()) return r2;

            // Read active key after — it should be the same UID but
            // the actual key material inside has been regenerated.
            // (The UID identifies the key object, not the key value.)
            Uid keyAfter;
            r2 = api.getActiveKey(session, 1, keyAfter);
            step(3, "Get active key (after)", r2);
            if (r2.ok()) {
                printf("    Active Key UID: 0x%016lx\n", keyAfter.toUint64());
                printf("    (Same UID, but internal key material is new)\n");
            }

            // Verify range is still configured
            LockingRangeInfo info;
            r2 = api.getRangeInfo(session, 1, info);
            step(4, "Range 1 still configured after erase", r2);
            if (r2.ok()) {
                printf("    Start=%lu, Length=%lu, RLE=%s, WLE=%s\n",
                       info.rangeStart, info.rangeLength,
                       info.readLockEnabled ? "yes" : "no",
                       info.writeLockEnabled ? "yes" : "no");
            }

            return ErrorCode::Success;
        });

    return r.ok();
}

// ── Scenario 2: Multiple Crypto Erases ──
//
// GenKey can be called repeatedly — each call generates a fresh key.

static bool scenario2_multipleErases(std::shared_ptr<ITransport> transport,
                                      uint16_t comId) {
    scenario(2, "Multiple Crypto Erases");

    EvalApi api;
    Bytes admin1Pw = pwBytes(ADMIN1_PW);

    auto r = composite::withSession(api, transport, comId,
        uid::SP_LOCKING, true, uid::AUTH_ADMIN1, admin1Pw,
        [&](Session& session) -> Result {
            for (int i = 0; i < 3; i++) {
                auto r2 = api.cryptoErase(session, 1);
                char label[64];
                snprintf(label, sizeof(label), "Crypto erase #%d", i + 1);
                step(i + 1, label, r2);
                if (r2.failed()) return r2;
            }
            printf("    All 3 erases completed — key rotated 3 times\n");
            return ErrorCode::Success;
        });

    return r.ok();
}

// ── Scenario 3: SedDrive one-liner ──

static bool scenario3_facade(const char* device, cli::CliOptions& opts) {
    scenario(3, "SedDrive::cryptoErase()");

    SedDrive drive(device);
    if (opts.dump) drive.enableDump(std::cerr, opts.dumpLevel);
    drive.query();

    auto r = drive.cryptoErase(1, ADMIN1_PW);
    step(1, "SedDrive::cryptoErase(range=1)", r);

    return r.ok();
}

static bool cleanup(std::shared_ptr<ITransport> transport, uint16_t comId) {
    scenario(0, "Cleanup");
    EvalApi api;
    auto cr = composite::revertToFactory(api, transport, comId, SID_PW);
    step(1, "RevertToFactory", cr.overall);
    return cr.ok();
}

int main(int argc, char* argv[]) {
    cli::CliOptions opts;
    auto transport = initTransport(argc, argv, opts,
        "Crypto Erase — instant data destruction via key rotation");
    if (!transport) return 1;

    SID_PW = getPassword(opts);
    ADMIN1_PW = SID_PW + "_Admin1";

    banner("11: Crypto Erase");

    if (!confirmDestructive(opts, "crypto-erase locking range keys")) return 0;

    EvalApi api;
    DiscoveryInfo info;
    auto r = api.discovery0(transport, info);
    if (r.failed()) { printf("Discovery failed\n"); return 1; }

    if (!setupDrive(api, transport, info.baseComId)) {
        printf("  Setup failed.\n"); return 1;
    }

    bool ok = true;
    ok &= scenario1_genKey(transport, info.baseComId);
    ok &= scenario2_multipleErases(transport, info.baseComId);
    ok &= scenario3_facade(opts.device.c_str(), opts);
    cleanup(transport, info.baseComId);

    printf("\n%s\n", ok ? "All scenarios passed." : "Some scenarios failed.");
    return ok ? 0 : 1;
}
