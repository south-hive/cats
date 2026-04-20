/// @file sed_drive.cpp
/// @brief SedDrive facade 구현

#include <libsed/facade/sed_drive.h>
#include <libsed/debug/logging_transport.h>
#include <libsed/debug/command_logger.h>
#include <libsed/eval/eval_composite.h>
#include <libsed/eval/test_helpers.h>
#include <libsed/method/method_uids.h>

namespace libsed {

using eval::EvalApi;
using eval::StartSessionResult;
using eval::PropertiesResult;
using eval::TableResult;

// ═══════════════════════════════════════════════════════
//  SedDrive::Impl
// ═══════════════════════════════════════════════════════

struct SedDrive::Impl {
    std::shared_ptr<ITransport> transport;
    std::shared_ptr<ITransport> rawTransport;
    EvalApi api;
    Discovery disc;
    DiscoveryInfo dinfo{};
    PropertiesResult props{};
    Bytes msidCache;
    uint16_t comId = 0;
    bool comIdExplicit = false;
    bool queried = false;
    uint32_t maxCPS = 2048;

    std::unique_ptr<Session> createSession() {
        auto s = std::make_unique<Session>(transport, comId);
        s->setMaxComPacketSize(maxCPS);
        return s;
    }
};

// ── Constructors ──

SedDrive::SedDrive(const std::string& devicePath)
    : impl_(std::make_unique<Impl>())
{
    impl_->rawTransport = TransportFactory::create(devicePath);
    impl_->transport = impl_->rawTransport;
}

SedDrive::SedDrive(const std::string& devicePath, uint16_t comId)
    : impl_(std::make_unique<Impl>())
{
    impl_->rawTransport = TransportFactory::create(devicePath);
    impl_->transport = impl_->rawTransport;
    impl_->comId = comId;
    impl_->comIdExplicit = true;
}

SedDrive::SedDrive(std::shared_ptr<ITransport> transport)
    : impl_(std::make_unique<Impl>())
{
    impl_->rawTransport = transport;
    impl_->transport = transport;
}

SedDrive::SedDrive(std::shared_ptr<ITransport> transport, uint16_t comId)
    : impl_(std::make_unique<Impl>())
{
    impl_->rawTransport = transport;
    impl_->transport = transport;
    impl_->comId = comId;
    impl_->comIdExplicit = true;
}

SedDrive::~SedDrive() = default;
SedDrive::SedDrive(SedDrive&&) noexcept = default;
SedDrive& SedDrive::operator=(SedDrive&&) noexcept = default;

// ── Query ──

Result SedDrive::query() {
    if (!impl_->transport || !impl_->transport->isOpen())
        return Result(ErrorCode::TransportOpenFailed);

    auto r = impl_->disc.discover(impl_->transport);
    if (r.failed()) return r;

    impl_->dinfo = impl_->disc.buildInfo();
    if (!impl_->comIdExplicit)
        impl_->comId = impl_->dinfo.baseComId;

    if (impl_->comId == 0)
        return Result(ErrorCode::DiscoveryFailed);

    impl_->api.stackReset(impl_->transport, impl_->comId);

    r = impl_->api.exchangeProperties(impl_->transport, impl_->comId, impl_->props);
    if (r.ok() && impl_->props.tperMaxComPacketSize > 0)
        impl_->maxCPS = impl_->props.tperMaxComPacketSize;

    readMsid(impl_->msidCache);

    impl_->queried = true;
    return Result::success();
}

SscType SedDrive::sscType() const { return impl_->dinfo.primarySsc; }

const char* SedDrive::sscName() const {
    return libsed::eval::sscName(impl_->dinfo.primarySsc);
}

const DiscoveryInfo& SedDrive::info() const { return impl_->dinfo; }
const Bytes& SedDrive::msid() const { return impl_->msidCache; }

std::string SedDrive::msidString() const {
    return std::string(impl_->msidCache.begin(), impl_->msidCache.end());
}

uint16_t SedDrive::comId() const { return impl_->comId; }

void SedDrive::setComId(uint16_t comId) {
    impl_->comId = comId;
    impl_->comIdExplicit = true;
}

uint16_t SedDrive::numComIds() const { return impl_->dinfo.numComIds; }
uint32_t SedDrive::maxComPacketSize() const { return impl_->maxCPS; }

// ── Debug ──

void SedDrive::enableDump(std::ostream& os, int verbosity) {
    impl_->transport = debug::LoggingTransport::wrapDump(impl_->rawTransport, os, verbosity);
}

void SedDrive::enableLog(const std::string& logDir) {
    impl_->transport = debug::LoggingTransport::wrap(impl_->rawTransport, logDir);
}

void SedDrive::enableLogFile(const std::string& filePath) {
    impl_->transport = debug::LoggingTransport::wrapToFile(impl_->rawTransport, filePath);
}

void SedDrive::enableDumpAndLog(const std::string& logDir, std::ostream& os, int verbosity) {
    debug::LoggerConfig config;
    config.toFile = true;
    config.toStream = true;
    config.stream = &os;
    config.verbosity = verbosity;
    config.logDir = logDir;
    auto logger = std::make_shared<debug::CommandLogger>(config);
    impl_->transport = std::make_shared<debug::LoggingTransport>(
        impl_->rawTransport, logger);
}

void SedDrive::enableDumpAndLogFile(const std::string& filePath,
                                     std::ostream& os, int verbosity) {
    debug::LoggerConfig config;
    config.toFile = true;
    config.toStream = true;
    config.stream = &os;
    config.verbosity = verbosity;
    config.filePath = filePath;        // 명시적 경로 — logDir 무시됨
    auto logger = std::make_shared<debug::CommandLogger>(config);
    impl_->transport = std::make_shared<debug::LoggingTransport>(
        impl_->rawTransport, logger);
}

// ── Login ──

SedSession SedDrive::login(Uid spUid, const std::string& password, Uid authUid,
                           bool write) {
    Bytes cred;
    if (!password.empty()) {
        cred = eval::EvalApi::hashPassword(password);
    }
    return login(spUid, cred, authUid, write);
}

SedSession SedDrive::login(Uid spUid, const Bytes& credential, Uid authUid,
                           bool write) {
    auto session = impl_->createSession();
    StartSessionResult ssr;
    Result r;
    if (credential.empty()) {
        r = impl_->api.startSession(*session, spUid.toUint64(), write, ssr);
    } else {
        r = impl_->api.startSessionWithAuth(*session, spUid.toUint64(), write,
                                             authUid.toUint64(), credential, ssr);
    }
    return SedSession(std::move(session), impl_->api, r);
}

SedSession SedDrive::loginAnonymous(Uid spUid) {
    auto session = impl_->createSession();
    StartSessionResult ssr;
    auto r = impl_->api.startSession(*session, spUid.toUint64(), false, ssr);
    return SedSession(std::move(session), impl_->api, r);
}

// ── Convenience methods ──

Result SedDrive::readMsid(Bytes& outMsid) {
    auto session = impl_->createSession();
    StartSessionResult ssr;
    auto r = impl_->api.startSession(*session, uid::SP_ADMIN, false, ssr);
    if (r.failed()) return r;

    r = impl_->api.getCPin(*session, uid::CPIN_MSID, outMsid);
    impl_->api.closeSession(*session);
    return r;
}

Result SedDrive::takeOwnership(const std::string& newSidPassword) {
    Bytes msidVal;
    auto r = readMsid(msidVal);
    if (r.failed()) return r;

    // Login with raw MSID bytes — MSID is a raw credential, NOT a human password.
    // The Bytes overload of login() passes credentials directly without hashing.
    auto s = login(Uid(uid::SP_ADMIN), msidVal, Uid(uid::AUTH_SID), true);
    if (s.failed()) return s.openResult();
    // setCPin(string) hashes newSidPassword via SHA-256 before storing
    r = impl_->api.setCPin(s.raw(), uid::CPIN_SID, newSidPassword);
    s.close();
    return r;
}

Result SedDrive::activateLocking(const std::string& sidPassword) {
    return withSession(Uid(uid::SP_ADMIN), sidPassword, Uid(uid::AUTH_SID),
        [&](Session& s) -> Result {
            return impl_->api.activate(s, uid::SP_LOCKING);
        });
}

Result SedDrive::configureRange(uint32_t rangeId,
                                uint64_t rangeStart, uint64_t rangeLength,
                                const std::string& admin1Password) {
    return withSession(Uid(uid::SP_LOCKING), admin1Password, Uid(uid::AUTH_ADMIN1),
        [&](Session& s) -> Result {
            return impl_->api.setRange(s, rangeId, rangeStart, rangeLength, true, true);
        });
}

Result SedDrive::lockRange(uint32_t rangeId, const std::string& password,
                           uint32_t authId) {
    Uid auth = (authId <= 4) ? uid::makeAdminUid(authId) : uid::makeUserUid(authId);
    return withSession(Uid(uid::SP_LOCKING), password, auth,
        [&](Session& s) -> Result {
            return impl_->api.setRangeLock(s, rangeId, true, true);
        });
}

Result SedDrive::unlockRange(uint32_t rangeId, const std::string& password,
                             uint32_t authId) {
    Uid auth = (authId <= 4) ? uid::makeAdminUid(authId) : uid::makeUserUid(authId);
    return withSession(Uid(uid::SP_LOCKING), password, auth,
        [&](Session& s) -> Result {
            return impl_->api.setRangeLock(s, rangeId, false, false);
        });
}

Result SedDrive::revert(const std::string& sidPassword) {
    return withSession(Uid(uid::SP_ADMIN), sidPassword, Uid(uid::AUTH_SID),
        [&](Session& s) -> Result {
            return impl_->api.revertSP(s, uid::SP_ADMIN);
        });
}

Result SedDrive::psidRevert(const std::string& psid) {
    return withSession(Uid(uid::SP_ADMIN), psid, Uid(uid::AUTH_PSID),
        [&](Session& s) -> Result {
            return impl_->api.revertSP(s, uid::SP_ADMIN);
        });
}

Result SedDrive::cryptoErase(uint32_t rangeId, const std::string& admin1Password) {
    return withSession(Uid(uid::SP_LOCKING), admin1Password, Uid(uid::AUTH_ADMIN1),
        [&](Session& s) -> Result {
            return impl_->api.cryptoErase(s, rangeId);
        });
}

Result SedDrive::enumerateRanges(const std::string& admin1Password,
                                 std::vector<eval::LockingInfo>& ranges) {
    return withSession(Uid(uid::SP_LOCKING), admin1Password, Uid(uid::AUTH_ADMIN1),
        [&](Session& s) -> Result {
            return impl_->api.getAllLockingInfo(s, ranges, 16); // 16개까지 시도
        });
}

Result SedDrive::enumerateAuthorities(const std::string& admin1Password,
                                      std::vector<AuthorityInfo>& authorities) {
    return withSession(Uid(uid::SP_LOCKING), admin1Password, Uid(uid::AUTH_ADMIN1),
        [&](Session& s) -> Result {
            // Admin1 ~ Admin4 — Authority 테이블의 AUTH_ENABLED(col=5) 조회
            for (uint32_t i = 1; i <= 4; ++i) {
                Uid authUid = uid::makeAdminUid(i);
                Token v;
                eval::RawResult raw;
                auto r = impl_->api.tableGetColumn(
                    s, authUid.toUint64(), uid::col::AUTH_ENABLED, v, raw);
                bool enabled = r.ok() && raw.methodResult.isSuccess()
                             && !v.isByteSequence && v.getUint() != 0;
                authorities.push_back({AuthorityKind::Admin, i, authUid, enabled});
            }
            // User1 ~ User8
            for (uint32_t i = 1; i <= 8; ++i) {
                bool enabled = false;
                auto r = impl_->api.isUserEnabled(s, i, enabled);
                if (r.ok()) {
                    authorities.push_back({AuthorityKind::User, i, uid::makeUserUid(i), enabled});
                }
            }
            return ErrorCode::Success;
        });
}

Result SedDrive::enumerateBands(const std::string& bandMasterPassword,
                                std::vector<eval::LockingInfo>& bands) {
    return withSession(Uid(uid::SP_ENTERPRISE), bandMasterPassword, Uid(uid::AUTH_BANDMASTER0),
        [&](Session& s) -> Result {
            return impl_->api.getAllLockingInfo(s, bands, 16); 
        });
}

Result SedDrive::getMbrStatus(MbrStatus& status) {
    status.supported = impl_->dinfo.mbrSupported;
    return withAnonymousSession(Uid(uid::SP_ADMIN),
        [&](Session& s) -> Result {
            return impl_->api.getMbrStatus(s, status.enabled, status.done);
        });
}

Result SedDrive::revertLockingSP(const std::string& admin1Password) {
    return withSession(Uid(uid::SP_LOCKING), admin1Password, Uid(uid::AUTH_ADMIN1),
        [&](Session& s) -> Result {
            return impl_->api.revertSP(s, uid::SP_LOCKING);
        });
}

Result SedDrive::setupUser(uint32_t userId, const std::string& userPassword,
                           uint32_t rangeId, const std::string& admin1Password) {
    return withSession(Uid(uid::SP_LOCKING), admin1Password, Uid(uid::AUTH_ADMIN1),
        [&](Session& s) -> Result {
            auto r = impl_->api.enableUser(s, userId);
            if (r.failed()) return r;
            r = impl_->api.setUserPassword(s, userId, userPassword);
            if (r.failed()) return r;
            return impl_->api.assignUserToRange(s, userId, rangeId);
        });
}

Result SedDrive::setMbrEnable(bool enable, const std::string& admin1Password) {
    return withSession(Uid(uid::SP_LOCKING), admin1Password, Uid(uid::AUTH_ADMIN1),
        [&](Session& s) -> Result {
            return impl_->api.setMbrEnable(s, enable);
        });
}

Result SedDrive::setMbrDone(bool done, const std::string& admin1Password) {
    return withSession(Uid(uid::SP_LOCKING), admin1Password, Uid(uid::AUTH_ADMIN1),
        [&](Session& s) -> Result {
            return impl_->api.setMbrDone(s, done);
        });
}

// ── Enterprise Band ──
//
// Band operations live in the Enterprise SSC's own Locking SP (uid::
// SP_ENTERPRISE = 0x0000020500010001 — "Enterprise Locking SP"), NOT in
// the Opal LockingSP (0x0000020500000002). A real Enterprise drive
// rejects Opal's SP_LOCKING; SimTransport is permissive so the
// difference only bites at the first-real-drive moment of truth.
// Keep all band-* methods aligned with enumerateBands which already
// uses SP_ENTERPRISE.

Result SedDrive::configureBand(uint32_t bandId,
                               uint64_t bandStart, uint64_t bandLength,
                               const std::string& bandMasterPassword) {
    Uid auth = uid::makeBandMasterUid(bandId);
    return withSession(Uid(uid::SP_ENTERPRISE), bandMasterPassword, auth,
        [&](Session& s) -> Result {
            return impl_->api.configureBand(s, bandId, bandStart, bandLength, true, true);
        });
}

Result SedDrive::lockBand(uint32_t bandId, const std::string& bandMasterPassword) {
    Uid auth = uid::makeBandMasterUid(bandId);
    return withSession(Uid(uid::SP_ENTERPRISE), bandMasterPassword, auth,
        [&](Session& s) -> Result {
            return impl_->api.lockBand(s, bandId);
        });
}

Result SedDrive::unlockBand(uint32_t bandId, const std::string& bandMasterPassword) {
    Uid auth = uid::makeBandMasterUid(bandId);
    return withSession(Uid(uid::SP_ENTERPRISE), bandMasterPassword, auth,
        [&](Session& s) -> Result {
            return impl_->api.unlockBand(s, bandId);
        });
}

Result SedDrive::eraseBand(uint32_t bandId, const std::string& eraseMasterPassword) {
    // Per Enterprise SSC: Band erase is authorized by EraseMaster (not
    // the band's BandMaster), because EraseMaster is the single Authority
    // that holds Erase ACL across all bands.
    return withSession(Uid(uid::SP_ENTERPRISE), eraseMasterPassword,
                        Uid(uid::AUTH_ERASEMASTER),
        [&](Session& s) -> Result {
            return impl_->api.eraseBand(s, bandId);
        });
}

// ── Power user ──

EvalApi& SedDrive::api() { return impl_->api; }
std::shared_ptr<ITransport> SedDrive::transport() { return impl_->transport; }
const Discovery& SedDrive::discovery() const { return impl_->disc; }

Result SedDrive::withSession(Uid spUid, const std::string& password, Uid authUid,
                             std::function<Result(Session&)> fn) {
    auto s = login(spUid, password, authUid);
    if (s.failed()) return s.openResult();
    auto r = fn(s.raw());
    s.close();
    return r;
}

Result SedDrive::withAnonymousSession(Uid spUid,
                                      std::function<Result(Session&)> fn) {
    auto s = loginAnonymous(spUid);
    if (s.failed()) return s.openResult();
    auto r = fn(s.raw());
    s.close();
    return r;
}

Result SedDrive::runRawMethod(Uid spUid, Uid authUid, const std::string& password,
                               const Bytes& tokens, eval::RawResult& raw) {
    auto s = login(spUid, password, authUid);
    if (s.failed()) return s.openResult();
    auto r = impl_->api.sendRawMethod(s.raw(), tokens, raw);
    s.close();
    return r;
}

Result SedDrive::getTableColumn(Uid spUid, Uid authUid, const std::string& password,
                                 uint64_t tableUid, uint32_t col, Token& out, eval::RawResult& raw) {
    auto s = login(spUid, password, authUid);
    if (s.failed()) return s.openResult();
    auto r = impl_->api.tableGetColumn(s.raw(), tableUid, col, out, raw);
    s.close();
    return r;
}

// ═══════════════════════════════════════════════════════
//  SedSession::Impl
// ═══════════════════════════════════════════════════════

struct SedSession::Impl {
    std::unique_ptr<Session> session;
    EvalApi* api = nullptr;
    Result openResult;
    bool closed = false;
};

SedSession::SedSession()
    : impl_(std::make_unique<Impl>())
{
    impl_->openResult = Result(ErrorCode::SessionNotStarted);
    impl_->closed = true;
}

SedSession::SedSession(std::unique_ptr<Session> session, EvalApi& api,
                       Result openResult)
    : impl_(std::make_unique<Impl>())
{
    impl_->session = std::move(session);
    impl_->api = &api;
    impl_->openResult = openResult;
    impl_->closed = openResult.failed();
}

SedSession::~SedSession() {
    close();
}

SedSession::SedSession(SedSession&&) noexcept = default;
SedSession& SedSession::operator=(SedSession&&) noexcept = default;

bool SedSession::ok() const { return impl_ && impl_->openResult.ok(); }
bool SedSession::failed() const { return !impl_ || impl_->openResult.failed(); }
Result SedSession::openResult() const { return impl_ ? impl_->openResult : Result(ErrorCode::SessionNotStarted); }

bool SedSession::isActive() const {
    return impl_ && impl_->session && impl_->session->isActive() && !impl_->closed;
}

void SedSession::close() {
    if (impl_ && impl_->session && !impl_->closed && impl_->api) {
        impl_->api->closeSession(*impl_->session);
        impl_->closed = true;
    }
}

// ── PIN ──

Result SedSession::getPin(Uid cpinUid, Bytes& pin) {
    if (!isActive()) return Result(ErrorCode::SessionNotStarted);
    return impl_->api->getCPin(*impl_->session, cpinUid.toUint64(), pin);
}

Result SedSession::setPin(Uid cpinUid, const std::string& newPin) {
    if (!isActive()) return Result(ErrorCode::SessionNotStarted);
    return impl_->api->setCPin(*impl_->session, cpinUid.toUint64(), newPin);
}

Result SedSession::setPin(Uid cpinUid, const Bytes& newPin) {
    if (!isActive()) return Result(ErrorCode::SessionNotStarted);
    return impl_->api->setCPin(*impl_->session, cpinUid.toUint64(), newPin);
}

// ── Locking Range ──

Result SedSession::setRange(uint32_t rangeId,
                         uint64_t rangeStart, uint64_t rangeLength,
                         bool readLockEnabled, bool writeLockEnabled) {
    if (!isActive()) return Result(ErrorCode::SessionNotStarted);
    return impl_->api->setRange(*impl_->session, rangeId, rangeStart, rangeLength,
                                readLockEnabled, writeLockEnabled);
}

Result SedSession::setRangeLockState(uint32_t rangeId, bool readLocked, bool writeLocked) {
    if (!isActive()) return Result(ErrorCode::SessionNotStarted);
    return impl_->api->setRangeLock(*impl_->session, rangeId, readLocked, writeLocked);
}

Result SedSession::lockRange(uint32_t rangeId) {
    return setRangeLockState(rangeId, true, true);
}

Result SedSession::unlockRange(uint32_t rangeId) {
    return setRangeLockState(rangeId, false, false);
}


Result SedSession::getRangeInfo(uint32_t rangeId, LockingRangeInfo& info) {
    if (!isActive()) return Result(ErrorCode::SessionNotStarted);
    return impl_->api->getRangeInfo(*impl_->session, rangeId, info);
}

// ── SP 관리 ──

Result SedSession::activate(Uid spUid) {
    if (!isActive()) return Result(ErrorCode::SessionNotStarted);
    return impl_->api->activate(*impl_->session, spUid.toUint64());
}

Result SedSession::revertSP(Uid spUid) {
    if (!isActive()) return Result(ErrorCode::SessionNotStarted);
    return impl_->api->revertSP(*impl_->session, spUid.toUint64());
}

// ── User 관리 ──

Result SedSession::enableUser(uint32_t userId) {
    if (!isActive()) return Result(ErrorCode::SessionNotStarted);
    return impl_->api->enableUser(*impl_->session, userId);
}

Result SedSession::setUserPassword(uint32_t userId, const std::string& password) {
    if (!isActive()) return Result(ErrorCode::SessionNotStarted);
    return impl_->api->setUserPassword(*impl_->session, userId, password);
}

Result SedSession::assignUserToRange(uint32_t userId, uint32_t rangeId) {
    if (!isActive()) return Result(ErrorCode::SessionNotStarted);
    return impl_->api->assignUserToRange(*impl_->session, userId, rangeId);
}

// ── MBR ──

Result SedSession::setMbrEnable(bool enable) {
    if (!isActive()) return Result(ErrorCode::SessionNotStarted);
    return impl_->api->setMbrEnable(*impl_->session, enable);
}

Result SedSession::setMbrDone(bool done) {
    if (!isActive()) return Result(ErrorCode::SessionNotStarted);
    return impl_->api->setMbrDone(*impl_->session, done);
}

Result SedSession::writeMbr(uint64_t offset, const Bytes& data) {
    if (!isActive()) return Result(ErrorCode::SessionNotStarted);
    return impl_->api->writeMbrData(*impl_->session, static_cast<uint32_t>(offset), data);
}

Result SedSession::readMbr(uint64_t offset, uint32_t length, Bytes& data) {
    if (!isActive()) return Result(ErrorCode::SessionNotStarted);
    return impl_->api->readMbrData(*impl_->session, static_cast<uint32_t>(offset), length, data);
}

// ── Key / Erase ──

Result SedSession::genKey(Uid objectUid) {
    if (!isActive()) return Result(ErrorCode::SessionNotStarted);
    return impl_->api->genKey(*impl_->session, objectUid.toUint64());
}

Result SedSession::cryptoErase(uint32_t rangeId) {
    if (!isActive()) return Result(ErrorCode::SessionNotStarted);
    return impl_->api->cryptoErase(*impl_->session, rangeId);
}

// ── Enterprise Band ──

Result SedSession::configureBand(uint32_t bandId,
                                 uint64_t bandStart, uint64_t bandLength,
                                 bool readLockEnabled, bool writeLockEnabled) {
    if (!isActive()) return Result(ErrorCode::SessionNotStarted);
    return impl_->api->configureBand(*impl_->session, bandId,
                                      bandStart, bandLength,
                                      readLockEnabled, writeLockEnabled);
}

Result SedSession::lockBand(uint32_t bandId) {
    if (!isActive()) return Result(ErrorCode::SessionNotStarted);
    return impl_->api->lockBand(*impl_->session, bandId);
}

Result SedSession::unlockBand(uint32_t bandId) {
    if (!isActive()) return Result(ErrorCode::SessionNotStarted);
    return impl_->api->unlockBand(*impl_->session, bandId);
}

// ── DataStore ──

Result SedSession::writeDataStore(uint64_t offset, const Bytes& data) {
    if (!isActive()) return Result(ErrorCode::SessionNotStarted);
    return impl_->api->tcgWriteDataStore(*impl_->session, static_cast<uint32_t>(offset), data);
}

Result SedSession::readDataStore(uint64_t offset, uint32_t length, Bytes& data) {
    if (!isActive()) return Result(ErrorCode::SessionNotStarted);
    eval::DataOpResult dor;
    auto r = impl_->api->tcgReadDataStore(*impl_->session, static_cast<uint32_t>(offset), length, dor);
    if (r.ok()) data = std::move(dor.data);
    return r;
}

// ── Generic Table ──

Result SedSession::tableGet(Uid objectUid, uint32_t startCol, uint32_t endCol,
                            TableResult& result) {
    if (!isActive()) return Result(ErrorCode::SessionNotStarted);
    return impl_->api->tableGet(*impl_->session, objectUid.toUint64(), startCol, endCol, result);
}

Result SedSession::tableSet(Uid objectUid, const TokenList& /* values */) {
    if (!isActive()) return Result(ErrorCode::SessionNotStarted);
    // For generic table set, use raw() session + api() directly.
    // TokenList entries are not directly compatible with tableSet's
    // vector<pair<uint32_t,Token>> — use specific methods instead
    // (setPin, setRange, etc.) or drop down to api().tableSet().
    (void)objectUid;
    return Result(ErrorCode::NotImplemented);
}

// ── Raw access ──

Session& SedSession::raw() { return *impl_->session; }
const Session& SedSession::raw() const { return *impl_->session; }
EvalApi& SedSession::api() { return *impl_->api; }

} // namespace libsed
