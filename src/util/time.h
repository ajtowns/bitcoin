// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_TIME_H
#define BITCOIN_UTIL_TIME_H

#include <compat.h>

#include <chrono>
#include <stdint.h>
#include <string>

using namespace std::chrono_literals;

void UninterruptibleSleep(const std::chrono::microseconds& n);

/**
 * Helper to count the seconds of a duration.
 *
 * All durations should be using std::chrono and calling this should generally
 * be avoided in code. Though, it is still preferred to an inline t.count() to
 * protect against a reliance on the exact type of t.
 *
 * This helper is used to convert durations before passing them over an
 * interface that doesn't support std::chrono (e.g. RPC, debug log, or the GUI)
 */
constexpr int64_t count_seconds(std::chrono::seconds t) { return t.count(); }
constexpr int64_t count_milliseconds(std::chrono::milliseconds t) { return t.count(); }
constexpr int64_t count_microseconds(std::chrono::microseconds t) { return t.count(); }

using SecondsDouble = std::chrono::duration<double, std::chrono::seconds::period>;

/**
 * Helper to count the seconds in any std::chrono::duration type
 */
inline double CountSecondsDouble(SecondsDouble t) { return t.count(); }

/** Returns the system time (not mockable) */
int64_t GetTimeMillis();
/** Returns the system time (not mockable) */
int64_t GetTimeMicros();
/** Returns the system time (not mockable) */
int64_t GetSystemTimeInSeconds(); // Like GetTime(), but not mockable

/** System clock */
using steady_clock = std::chrono::steady_clock;
using steady_time = std::chrono::steady_clock::time_point;

/** Mockable clock
 *
 * Example usage:
 *    mockable_time t1 = mockable_clock::now();
 *    mockable_time t2 = mockable_clock::now();
 *    if (t2 - t1 > 20m) return; // took too long
 */
struct mockable_clock
{
    using duration = std::chrono::microseconds;
    using rep = duration::rep;
    using period = duration::period;
    using time_point = std::chrono::time_point<mockable_clock>;
    static const bool is_steady = false;
    static constexpr time_point epoch{duration{0}};
    static time_point now() noexcept;

    static time_point real_time() noexcept;
    static std::chrono::seconds mock_time() noexcept;
    static void set_mock_time(std::chrono::seconds since_epoch) noexcept;
};
using mockable_time = mockable_clock::time_point;

/** For testing. Set e.g. with the setmocktime rpc, or -mocktime argument (DEPRECATED) */
static inline void SetMockTime(int64_t nMockTimeIn) { mockable_clock::set_mock_time(std::chrono::seconds{nMockTimeIn}); }

/** For testing (DEPRECATED) */
static inline int64_t GetMockTime() { return count_seconds(mockable_clock::mock_time()); }

/** Return system time (or mocked time, if set) (DEPRECATED) */
template <typename T>
static inline T GetTime() { return std::chrono::duration_cast<T>(mockable_clock::now().time_since_epoch()); }

/**
 * DEPRECATED
 * Use either GetSystemTimeInSeconds (not mockable) or GetTime<T> (mockable)
 */
static inline int64_t GetTime() { return GetTime<std::chrono::seconds>().count(); }

/**
 * ISO 8601 formatting is preferred. Use the FormatISO8601{DateTime,Date}
 * helper functions if possible.
 */
std::string FormatISO8601DateTime(mockable_time nTime);
std::string FormatISO8601Date(mockable_time nTime);
int64_t ParseISO8601DateTime(const std::string& str);

std::string FormatISO8601DateTime(int64_t nTime);
std::string FormatISO8601Date(int64_t nTime);
int64_t ParseISO8601DateTime(const std::string& str);

/**
 * Convert milliseconds to a struct timeval for e.g. select.
 */
struct timeval MillisToTimeval(int64_t nTimeout);

/**
 * Convert milliseconds to a struct timeval for e.g. select.
 */
struct timeval MillisToTimeval(std::chrono::milliseconds ms);

/** Sanity check epoch match normal Unix epoch */
bool ChronoSanityCheck();

#endif // BITCOIN_UTIL_TIME_H
