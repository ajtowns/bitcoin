// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <compat.h>
#include <util/time.h>

#include <util/check.h>

#include <atomic>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <ctime>
#include <thread>

#include <tinyformat.h>

void UninterruptibleSleep(const std::chrono::microseconds& n) { std::this_thread::sleep_for(n); }

static std::atomic<std::chrono::seconds> g_mock_time{0s}; //!< For testing

mockable_clock::time_point mockable_clock::real_time() noexcept
{
    int64_t micros = (boost::posix_time::microsec_clock::universal_time() -
                      boost::posix_time::ptime(boost::gregorian::date(1970,1,1))).total_microseconds();
    return time_point{std::chrono::microseconds{micros}};
}

bool ChronoSanityCheck()
{
    // std::chrono::system_clock.time_since_epoch and time_t(0) are not guaranteed
    // to use the Unix epoch timestamp, but in practice they almost certainly will.
    // Any differing behavior will be assumed to be an error, unless certain
    // platforms prove to consistently deviate, at which point we'll cope with it
    // by adding offsets.

    // Create a new clock from time_t(0) and make sure that it represents 0
    // seconds from the system_clock's time_since_epoch. Then convert that back
    // to a time_t and verify that it's the same as before.
    const time_t zeroTime{};
    auto clock = std::chrono::system_clock::from_time_t(zeroTime);
    if (std::chrono::duration_cast<std::chrono::seconds>(clock.time_since_epoch()).count() != 0)
        return false;

    time_t nTime = std::chrono::system_clock::to_time_t(clock);
    if (nTime != zeroTime)
        return false;

    // Check that the above zero time is actually equal to the known unix timestamp.
    tm epoch = *gmtime(&nTime);
    if ((epoch.tm_sec != 0)  || \
       (epoch.tm_min  != 0)  || \
       (epoch.tm_hour != 0)  || \
       (epoch.tm_mday != 1)  || \
       (epoch.tm_mon  != 0)  || \
       (epoch.tm_year != 70))
        return false; 
    return true;
}

std::chrono::seconds mockable_clock::mock_time() noexcept
{
    return std::chrono::seconds{g_mock_time.load(std::memory_order_relaxed)};
}

mockable_clock::time_point mockable_clock::now() noexcept
{
    std::chrono::seconds mock = mock_time();
    return mock.count() ?  time_point{mock} : real_time();
}

void mockable_clock::set_mock_time(std::chrono::seconds since_epoch) noexcept
{
    Assert(since_epoch.count() >= 0);
    g_mock_time.store(since_epoch, std::memory_order_relaxed);
}

int64_t GetTimeMillis()
{
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch());
    assert(now.count() > 0);
    return now.count();
}

int64_t GetTimeMicros()
{
    auto now = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch());
    assert(now.count() > 0);
    return now.count();
}

int64_t GetSystemTimeInSeconds()
{
    return GetTimeMicros()/1000000;
}

std::string FormatISO8601DateTime(int64_t nTime) {
    struct tm ts;
    time_t time_val = nTime;
#ifdef HAVE_GMTIME_R
    if (gmtime_r(&time_val, &ts) == nullptr) {
#else
    if (gmtime_s(&ts, &time_val) != 0) {
#endif
        return {};
    }
    return strprintf("%04i-%02i-%02iT%02i:%02i:%02iZ", ts.tm_year + 1900, ts.tm_mon + 1, ts.tm_mday, ts.tm_hour, ts.tm_min, ts.tm_sec);
}

std::string FormatISO8601Date(int64_t nTime) {
    struct tm ts;
    time_t time_val = nTime;
#ifdef HAVE_GMTIME_R
    if (gmtime_r(&time_val, &ts) == nullptr) {
#else
    if (gmtime_s(&ts, &time_val) != 0) {
#endif
        return {};
    }
    return strprintf("%04i-%02i-%02i", ts.tm_year + 1900, ts.tm_mon + 1, ts.tm_mday);
}

int64_t ParseISO8601DateTime(const std::string& str)
{
    static const boost::posix_time::ptime epoch = boost::posix_time::from_time_t(0);
    static const std::locale loc(std::locale::classic(),
        new boost::posix_time::time_input_facet("%Y-%m-%dT%H:%M:%SZ"));
    std::istringstream iss(str);
    iss.imbue(loc);
    boost::posix_time::ptime ptime(boost::date_time::not_a_date_time);
    iss >> ptime;
    if (ptime.is_not_a_date_time() || epoch > ptime)
        return 0;
    return (ptime - epoch).total_seconds();
}

struct timeval MillisToTimeval(int64_t nTimeout)
{
    struct timeval timeout;
    timeout.tv_sec  = nTimeout / 1000;
    timeout.tv_usec = (nTimeout % 1000) * 1000;
    return timeout;
}

struct timeval MillisToTimeval(std::chrono::milliseconds ms)
{
    return MillisToTimeval(count_milliseconds(ms));
}
