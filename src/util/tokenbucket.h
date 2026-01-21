// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_TOKENBUCKET_H
#define BITCOIN_UTIL_TOKENBUCKET_H

#include <util/check.h>

namespace util {

template<typename Clock>
class TokenBucket
{
public:
    using clock = Clock;
    using time_point = typename Clock::time_point;
    using duration = typename Clock::duration;

    const double m_rate{1};
    const double m_cap{0};
    const double m_max_debt{0};

    TokenBucket(double rate, double value, double cap, double debt=0) : m_rate{rate}, m_cap{cap}, m_max_debt{0}, m_value{std::min(value,cap)} { }

    void increment(const time_point& now)
    {
        if (now > m_last_updated) {
            if (m_value < m_cap && m_last_updated.time_since_epoch().count() > 0) {
                double inc = m_rate * std::chrono::duration_cast<SecondsDouble>(now - m_last_updated).count();
                m_value = std::min(m_cap, m_value + inc);
            }
        }
        m_last_updated = now;
    }

    bool decrement(double n = 1.0)
    {
        m_value -= n;
        return (m_value > m_max_debt);
    }

    double value() const { return m_value; }

private:
    time_point m_last_updated{duration{0}};
    double m_value{0};
};

} // util namespace


#endif // BITCOIN_UTIL_TOKENBUCKET_H
