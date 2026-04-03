#include "libsed/session/session.h"
#include "libsed/method/method_call.h"
#include "libsed/method/param_encoder.h"
#include "libsed/method/param_decoder.h"
#include "libsed/method/method_uids.h"
#include "libsed/codec/token_decoder.h"
#include "libsed/core/uid.h"
#include "libsed/core/log.h"
#include "libsed/debug/test_context.h"
#include <chrono>
#include <thread>

namespace libsed {

static constexpr uint8_t PROTOCOL_ID = 0x01;

Session::Session(std::shared_ptr<ITransport> transport, uint16_t comId)
    : transport_(std::move(transport))
    , comId_(comId) {
    packetBuilder_.setComId(comId_);
}

Session::~Session() {
    if (state_ == State::Active) {
        closeSession();
    }
}

Session::Session(Session&& other) noexcept
    : transport_(std::move(other.transport_))
    , packetBuilder_(std::move(other.packetBuilder_))
    , state_(other.state_)
    , comId_(other.comId_)
    , tsn_(other.tsn_)
    , hsn_(other.hsn_)
    , seqNumber_(other.seqNumber_)
    , maxComPacketSize_(other.maxComPacketSize_)
    , timeoutMs_(other.timeoutMs_) {
    other.state_ = State::Closed;
}

Session& Session::operator=(Session&& other) noexcept {
    if (this != &other) {
        if (state_ == State::Active) closeSession();
        transport_ = std::move(other.transport_);
        packetBuilder_ = std::move(other.packetBuilder_);
        state_ = other.state_;
        comId_ = other.comId_;
        tsn_ = other.tsn_;
        hsn_ = other.hsn_;
        seqNumber_ = other.seqNumber_;
        maxComPacketSize_ = other.maxComPacketSize_;
        timeoutMs_ = other.timeoutMs_;
        other.state_ = State::Closed;
    }
    return *this;
}

uint32_t Session::nextHostSessionNumber() {
    return sessionCounter_++;
}

Result Session::startSession(const Uid& spUid, bool write,
                               const Uid& hostAuthority,
                               const Bytes& hostChallenge) {
    if (state_ != State::Idle) {
        return ErrorCode::SessionAlreadyActive;
    }

    hsn_ = nextHostSessionNumber();
    state_ = State::Starting;

    // ── Debug layer: check fault before session start ──
    LIBSED_CHECK_FAULT_NP(debug::FaultPoint::BeforeStartSession);

    LIBSED_DEBUG("Starting session HSN=%u to SP 0x%016llX",
                  hsn_, static_cast<unsigned long long>(spUid.toUint64()));

    // Build StartSession parameters
    Bytes params = ParamEncoder::encodeStartSession(
        hsn_, spUid, write, hostChallenge, hostAuthority);

    // Build SM method call
    Bytes methodTokens = MethodCall::buildSmCall(method::SM_START_SESSION, params);

    // Send as session manager packet (TSN=0, HSN=0)
    Bytes sendData = packetBuilder_.buildSessionManagerPacket(methodTokens);

    // Send and receive
    Bytes recvTokens;
    auto r = sendRecv(sendData, recvTokens);
    if (r.failed()) {
        state_ = State::Idle;
        return r;
    }

    // Parse SyncSession response
    MethodResult result;
    r = result.parse(recvTokens);
    if (r.failed()) {
        state_ = State::Idle;
        return r;
    }

    if (!result.isSuccess()) {
        LIBSED_ERROR("StartSession failed: %s", result.statusMessage().c_str());
        state_ = State::Idle;
        return result.toResult();
    }

    // Decode session parameters from result
    ParamDecoder::SessionParams sessionParams;
    auto stream = result.resultStream();
    r = ParamDecoder::decodeSyncSession(stream, sessionParams);
    if (r.failed()) {
        state_ = State::Idle;
        return r;
    }

    tsn_ = sessionParams.tperSessionNumber;
    hsn_ = sessionParams.hostSessionNumber;

    // Update packet builder with session numbers
    packetBuilder_.setSessionNumbers(tsn_, hsn_);

    state_ = State::Active;
    LIBSED_INFO("Session started: TSN=%u HSN=%u", tsn_, hsn_);

    // ── Debug layer: post-session-start hook ──
    LIBSED_CHECK_FAULT_NP(debug::FaultPoint::AfterStartSession);
    LIBSED_TRACE_EVENT(debug::FaultPoint::AfterStartSession, "SESSION_START",
                       "TSN=" + std::to_string(tsn_) + " HSN=" + std::to_string(hsn_),
                       {}, ErrorCode::Success);
    LIBSED_BUMP("session.started");

    return ErrorCode::Success;
}

Result Session::closeSession() {
    if (state_ != State::Active) {
        return ErrorCode::SessionNotStarted;
    }

    state_ = State::Closing;

    // ── Debug layer: pre-close hook ──
    LIBSED_CHECK_FAULT_NP(debug::FaultPoint::BeforeCloseSession);

    LIBSED_DEBUG("Closing session TSN=%u HSN=%u", tsn_, hsn_);

    // Build CloseSession: just EndOfSession token
    TokenEncoder enc;
    enc.endOfSession();

    Bytes sendData = packetBuilder_.buildComPacket(enc.data());

    // Send, but don't fail hard if close doesn't work
    Bytes recvTokens;
    (void)sendRecv(sendData, recvTokens);

    state_ = State::Closed;
    tsn_ = 0;
    hsn_ = 0;
    packetBuilder_.setSessionNumbers(0, 0);

    LIBSED_INFO("Session closed");
    return ErrorCode::Success;
}

Result Session::sendMethod(const Bytes& methodTokens, MethodResult& result) {
    if (state_ != State::Active) {
        return ErrorCode::SessionNotStarted;
    }

    // ── Debug layer: pre-send hook ──
    {
        Bytes mutableTokens = methodTokens;
        LIBSED_CHECK_FAULT(debug::FaultPoint::BeforeSendMethod, mutableTokens);
    }
    LIBSED_BUMP("method.sent");

    // Extract method name from send tokens for logging
    {
        TokenDecoder dec;
        if (dec.decode(methodTokens).ok()) {
            const auto& toks = dec.tokens();
            // CALL(0) InvokingUID(1) MethodUID(2)
            if (toks.size() >= 3 && toks[0].type == TokenType::Call
                && toks[2].isAtom() && toks[2].isByteSequence) {
                auto bytes = toks[2].getBytes();
                if (bytes.size() == 8) {
                    uint64_t muid = 0;
                    for (int j = 0; j < 8; j++) muid = (muid << 8) | bytes[j];
                    result.setSendMethodUid(muid);
                }
            }
        }
    }

    Bytes sendData = packetBuilder_.buildComPacket(methodTokens);

    Bytes recvTokens;
    auto r = sendRecv(sendData, recvTokens);
    if (r.failed()) return r;

    r = result.parse(recvTokens);
    if (r.failed()) return r;

    // Check for EndOfSession in response (session terminated by TPer)
    for (const auto& token : result.resultTokens()) {
        if (token.type == TokenType::EndOfSession) {
            // ── Debug layer: workaround to ignore unexpected EndOfSession ──
            if (LIBSED_WA_ACTIVE(debug::workaround::kIgnoreEndOfSession)) {
                LIBSED_WARN("Ignoring unexpected EndOfSession (workaround active)");
                break;
            }
            LIBSED_WARN("TPer closed session unexpectedly");
            state_ = State::Closed;
            break;
        }
    }

    // ── Debug layer: post-recv-method hook ──
    {
        Bytes dummy;
        LIBSED_CHECK_FAULT(debug::FaultPoint::AfterRecvMethod, dummy);
    }

    return ErrorCode::Success;
}

Result Session::sendRaw(const Bytes& comPacketData) {
    return transport_->ifSend(PROTOCOL_ID, comId_,
                               ByteSpan(comPacketData.data(), comPacketData.size()));
}

Result Session::recvRaw(Bytes& comPacketData, uint32_t /*timeoutMs*/) {
    return transport_->ifRecv(PROTOCOL_ID, comId_, comPacketData, maxComPacketSize_);
}

Result Session::sendRecv(const Bytes& sendData, Bytes& recvTokens) {
    // ── Debug layer: pre-send transport hook ──
    {
        Bytes mutableSend = sendData;
        LIBSED_CHECK_FAULT(debug::FaultPoint::BeforeIfSend, mutableSend);
    }

    // Send
    auto r = transport_->ifSend(PROTOCOL_ID, comId_,
                                 ByteSpan(sendData.data(), sendData.size()));

    // ── Debug layer: post-send hook ──
    LIBSED_TRACE_EVENT(debug::FaultPoint::AfterIfSend, "IF-SEND",
                       "comId=0x" + std::to_string(comId_) + " size=" + std::to_string(sendData.size()),
                       {}, r.code());
    LIBSED_BUMP("transport.send");

    if (r.failed()) {
        LIBSED_ERROR("IF-SEND failed: %s", r.message().c_str());
        return r;
    }

    // ── Debug layer: check workaround for timeout extension ──
    uint32_t effectiveTimeout = timeoutMs_;
    if (LIBSED_WA_ACTIVE(debug::workaround::kExtendTimeout)) {
        auto ext = debug::TestContext::instance().configUint("timeout_extend_ms", "", 60000);
        effectiveTimeout = static_cast<uint32_t>(ext);
    }

    // Receive with polling
    auto startTime = std::chrono::steady_clock::now();
    uint32_t pollIntervalMs = 10;

    while (true) {
        Bytes recvBuffer(maxComPacketSize_, 0);
        size_t bytesReceived = 0;

        // ── Debug layer: pre-recv hook ──
        LIBSED_CHECK_FAULT(debug::FaultPoint::BeforeIfRecv, recvBuffer);

        r = transport_->ifRecv(PROTOCOL_ID, comId_,
                                MutableByteSpan(recvBuffer.data(), recvBuffer.size()),
                                bytesReceived);

        LIBSED_BUMP("transport.recv");

        if (r.failed()) {
            LIBSED_ERROR("IF-RECV failed: %s", r.message().c_str());
            return r;
        }

        // ── Debug layer: post-recv hook (may corrupt received data) ──
        if (bytesReceived > 0) {
            recvBuffer.resize(bytesReceived);
            LIBSED_CHECK_FAULT(debug::FaultPoint::AfterIfRecv, recvBuffer);
            LIBSED_TRACE_EVENT(debug::FaultPoint::AfterIfRecv, "IF-RECV",
                               "size=" + std::to_string(bytesReceived), {}, ErrorCode::Success);
        }

        if (bytesReceived == 0) {
            // Timeout check
            auto elapsed = std::chrono::steady_clock::now() - startTime;
            auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
            if (static_cast<uint32_t>(elapsedMs) > effectiveTimeout) {
                LIBSED_ERROR("Receive timeout after %u ms", effectiveTimeout);
                return ErrorCode::TransportTimeout;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(pollIntervalMs));
            pollIntervalMs = std::min(pollIntervalMs * 2, 500u);
            continue;
        }

        // Parse response
        PacketBuilder::ParsedResponse parsed;
        r = packetBuilder_.parseResponse(recvBuffer.data(), recvBuffer.size(), parsed);
        if (r.failed()) return r;

        // Check for empty response (outstanding data)
        if (parsed.tokenPayload.empty() && packetBuilder_.hasMoreData()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(pollIntervalMs));
            continue;
        }

        recvTokens = std::move(parsed.tokenPayload);
        return ErrorCode::Success;
    }
}

} // namespace libsed
