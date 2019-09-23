// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_TIME_H
#define BITCOIN_UTIL_TIME_H

#include <stdint.h>
#include <string>
#include <chrono>

/**
 * Helper to count the seconds of a duration.
 *
 * All durations should be using std::chrono and calling this should generally be avoided in code. Though, it is still
 * preferred to an inline t.count() to protect against a reliance on the exact type of t.
 */
inline int64_t count_seconds(std::chrono::seconds t) { return t.count(); }

/**
 * DEPRECATED
 * Use either GetSysTime (not mockable) or GetTime<T> (mockable)
 */
int64_t GetTime();

/** Returns the system time (not mockable) */
int64_t GetSysTimeMillis();
/** Returns the system time (not mockable) */
int64_t GetSysTimeMicros();
/** Returns the system time (not mockable) */
int64_t GetSysTime(); // Like GetTime(), but not mockable

/** For testing. Set e.g. with the setmocktime rpc, or -mocktime argument */
void SetMockTime(int64_t nMockTimeIn);
/** For testing */
int64_t GetMockTime();

void MilliSleep(int64_t n);

/** Return system time (or mocked time, if set) */
struct mockable_clock
{
    typedef std::chrono::microseconds duration;
    typedef duration::rep rep;
    typedef duration::period period;
    typedef std::chrono::time_point<mockable_clock> time_point;
    static const bool is_steady = false;
    static time_point now() noexcept;
    static constexpr time_point epoch{duration{0}};
};
typedef mockable_clock::time_point mockable_time;
inline int64_t count_seconds(mockable_time t) { return std::chrono::duration_cast<std::chrono::seconds>(t.time_since_epoch()).count(); }

static inline std::chrono::microseconds GetTimeMicros() { return mockable_clock::now().time_since_epoch(); }

/**
 * ISO 8601 formatting is preferred. Use the FormatISO8601{DateTime,Date}
 * helper functions if possible.
 */
std::string FormatISO8601DateTime(int64_t nTime);
std::string FormatISO8601Date(int64_t nTime);

#endif // BITCOIN_UTIL_TIME_H
