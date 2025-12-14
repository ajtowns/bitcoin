// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_TOKENBUCKET_H
#define BITCOIN_UTIL_TOKENBUCKET_H

#include <util/check.h>
#include <util/time.h>

namespace util {

template<auto Max, auto Increment, auto SecondsPerInc, typename Clock = NodeClock>
class TokenBucket
{
public:
    using clock = Clock;
    using time_point = typename Clock::time_point;
    using duration = typename Clock::duration;

    static_assert(SecondsPerInc > 0);

    static constexpr double MAX = Max;
    static constexpr double RATE = double{Increment}/double{SecondsPerInc};

    static_assert(RATE > 0);

    TokenBucket() = default;
    TokenBucket(double d) : m_value{std::min(d, MAX)} { }

    void increment(const time_point& now)
    {
        if (m_value < MAX && m_last_updated.time_since_epoch().count() > 0 && now > m_last_updated) {
            double inc = RATE * std::chrono::duration_cast<SecondsDouble>(now - m_last_updated).count();
            m_value += std::min(MAX - m_value, inc);
        }
        m_last_updated = now;
    }

    bool decrement(double n = 1.0)
    {
        if (m_value >= n) {
            m_value -= n;
            return true;
        } else {
            return false;
        }
    }

    size_t available() const { return (m_value >= 1.0 ? static_cast<size_t>(m_value) : 0); }

    double value() const { return m_value; }

private:
    time_point m_last_updated{duration{0}};
    double m_value{0};
};

} // util namespace


#endif // BITCOIN_UTIL_TOKENBUCKET_H
