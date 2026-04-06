#pragma once

#include "../core/types.h"

namespace libsed {
namespace method {

// ══════════════════════════════════════════════════════
//  Session Manager Methods (invoked on SMUID)
// ══════════════════════════════════════════════════════
inline constexpr uint64_t SM_PROPERTIES            = 0x000000000000FF01;
inline constexpr uint64_t SM_START_SESSION         = 0x000000000000FF02;
inline constexpr uint64_t SM_SYNC_SESSION          = 0x000000000000FF03;
inline constexpr uint64_t SM_START_TRUSTED_SESSION = 0x000000000000FF04;
inline constexpr uint64_t SM_SYNC_TRUSTED_SESSION  = 0x000000000000FF05;
inline constexpr uint64_t SM_CLOSE_SESSION         = 0x000000000000FF06;

// ══════════════════════════════════════════════════════
//  Standard Object Methods
// ══════════════════════════════════════════════════════
// Opal SSC method UIDs (TCG Core Spec Table 241)
// Note: Enterprise SSC uses different UIDs: Get=0x06, Set=0x07, Authenticate=0x0C
inline constexpr uint64_t GET                  = 0x0000000600000016;
inline constexpr uint64_t SET                  = 0x0000000600000017;
inline constexpr uint64_t NEXT                 = 0x0000000600000008;
inline constexpr uint64_t GETACL               = 0x000000060000000D;
inline constexpr uint64_t GENKEY               = 0x0000000600000010;
inline constexpr uint64_t REVERTSP             = 0x0000000600000011;
// Note: GetFreeSpace/GetFreeRows are not separate method UIDs in TCG Core Spec.
// They are performed via GET on Table objects with specific columns.
inline constexpr uint64_t AUTHENTICATE         = 0x000000060000000C;

// Enterprise SSC method UIDs (different from Opal)
inline constexpr uint64_t EGET                 = 0x0000000600000006;
inline constexpr uint64_t ESET                 = 0x0000000600000007;
inline constexpr uint64_t EAUTHENTICATE        = 0x000000060000001C;
inline constexpr uint64_t REVERT               = 0x0000000600000202;
inline constexpr uint64_t ACTIVATE             = 0x0000000600000203;
inline constexpr uint64_t ERASE                = 0x0000000600000803;
inline constexpr uint64_t RANDOM               = 0x0000000600000601;

// ══════════════════════════════════════════════════════
//  Table-specific methods
// ══════════════════════════════════════════════════════
inline constexpr uint64_t ASSIGN               = 0x0000000600000009;
inline constexpr uint64_t REMOVE               = 0x000000060000000A;
inline constexpr uint64_t CREATE_ROW           = 0x000000060000000B;
inline constexpr uint64_t DELETE_ROW           = 0x000000060000000C;

// ══════════════════════════════════════════════════════
//  Clock / Logging
// ══════════════════════════════════════════════════════
inline constexpr uint64_t GET_CLOCK            = 0x0000000600000401;

} // namespace method
} // namespace libsed
