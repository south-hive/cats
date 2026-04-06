/// @file os.h
/// @brief Stub for sedutil's os.h — disables logging for standalone use.
/// sedutil source files include "os.h" for LOG() macros.
/// This stub provides a no-op implementation.
#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <iostream>
#include "DtaConstants.h"

// No-op log sink
struct NullLogSink {
    template<typename T>
    NullLogSink& operator<<(const T&) { return *this; }
};

// sedutil uses LOG(D1), LOG(E), etc.
#define D  0
#define D1 1
#define D2 2
#define D3 3
#define D4 4
#define E  5
#define LOG(level) NullLogSink()
