// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_LOG_H
#define BITCOIN_UTIL_LOG_H

// This header works in tandem with `logging/categories.h`
// to expose the complete logging interface.
#include <logging/categories.h> // IWYU pragma: export
#include <tinyformat.h>
#include <util/check.h>
#include <util/kvformat.h>
#include <util/threadnames.h>
#include <util/time.h>

#include <cstdint>
#include <source_location>
#include <string>
#include <string_view>
#include <vector>

/// Like std::source_location, but allowing to override the function name.
class SourceLocation
{
public:
    /// The func argument must be constructed from the C++11 __func__ macro.
    /// Ref: https://en.cppreference.com/w/cpp/language/function.html#func
    /// Non-static string literals are not supported.
    explicit SourceLocation(
        const char* func,
        std::source_location loc = std::source_location::current())
        : m_func{func}, m_loc{loc} {}

    std::string_view file_name() const { return m_loc.file_name(); }
    std::uint_least32_t line() const { return m_loc.line(); }
    std::string_view function_name_short() const { return m_func; }

private:
    std::string_view m_func;
    std::source_location m_loc;
};

namespace util::log {
/** Opaque to util::log; interpreted by consumers (e.g., BCLog::LogFlags). */
using Category = uint64_t;

//! Structure and constant for tagging not to rate limit.
struct NoRateLimitTag {
    explicit NoRateLimitTag() = default;
};
inline constexpr NoRateLimitTag NO_RATE_LIMIT{};

enum class Level {
    Trace = 0, // High-volume or detailed logging for development/debugging
    Debug,     // Reasonably noisy logging, but still usable in production
    Info,      // Default
    Warning,
    Error,
};

struct Entry {
    Category category;
    Level level;
    bool should_ratelimit{false}; //!< Hint for consumers if this entry should be ratelimited
    SystemClock::time_point timestamp{SystemClock::now()};
    std::chrono::seconds mocktime{GetMockTime()};
    std::string thread_name{util::ThreadGetInternalName()};
    SourceLocation source_loc;
    std::string message;
    std::vector<util::kvformat::KV> kvs;
};

/** Send message to be logged. Applications using the logging library need to provide this. */
void Log(Entry entry);

namespace detail {

//! Describe a tinyformat failure: the prose portion of the original
//! format string and the exception message are surfaced as structured
//! kvs.
inline util::kvformat::Formatted MakeFmtErrorFormatted(std::string_view orig_msg, std::string_view error_what)
{
    util::kvformat::Formatted f;
    f.msg = "Error while formatting log message";
    f.kvs.push_back({.name = "msg", .kind = util::kvformat::Kind::String, .value = std::string{orig_msg}});
    f.kvs.push_back({.name = "error", .kind = util::kvformat::Kind::String, .value = std::string{error_what}});
    return f;
}

/**
 * Format the msg + kvs into a `Formatted`, wrap it in an owned `Entry`,
 * and dispatch to `Log()`. Partitioning of positional vs provider args
 * lives in `ConstevalMsgWithKVs<N>::format`. Tinyformat failures are
 * caught and turned into a self-describing entry so a bad call site
 * doesn't propagate an exception out of the logging path.
 */
template <std::size_t N, typename... Args>
inline void DoLog(SourceLocation&& source_loc, BCLog::LogFlags flag, Level level,
                  bool should_ratelimit,
                  const util::kvformat::ConstevalMsgWithKVs<N>& msg,
                  const Args&... args)
{
    util::kvformat::Formatted f;
    try {
        f = msg.format(args...);
    } catch (tinyformat::format_error& fmterr) {
        f = MakeFmtErrorFormatted(msg.msg, fmterr.what());
    }
    util::log::Log(Entry{
        .category = flag,
        .level = level,
        .should_ratelimit = should_ratelimit,
        .source_loc = std::move(source_loc),
        .message = std::move(f.msg),
        .kvs = std::move(f.kvs),
    });
}

//! Default overload: rate-limited.
template <typename... Args>
inline void LogWithSrcLoc(SourceLocation&& source_loc, BCLog::LogFlags flag, Level level,
                          const util::kvformat::ConstevalMsgFor<Args...>& fmt, const Args&... args)
{
    DoLog(std::move(source_loc), flag, level, /*should_ratelimit=*/true, fmt, args...);
}

//! With explicit `NoRateLimitTag` before the format string.
template <typename... Args>
inline void LogWithSrcLoc(SourceLocation&& source_loc, BCLog::LogFlags flag, Level level, NoRateLimitTag,
                          const util::kvformat::ConstevalMsgFor<Args...>& fmt, const Args&... args)
{
    DoLog(std::move(source_loc), flag, level, /*should_ratelimit=*/false, fmt, args...);
}

} // namespace detail

/**
 * Holds the global "is this category enabled?" state used by the
 * @ref ShouldDebugLog and @ref ShouldTraceLog fast paths.
 *
 * The two bitmasks are `constinit` atomics, so they are initialized
 * before any logging functions can be called (even from
 * static-initialization-time code). Reads are lock-free relaxed loads,
 * cheap enough to inline at every `LogDebug`/`LogTrace` call site.
 *
 * This class is never instantiated. It exists only to scope the
 * atomics and grant friendship to the inline accessors below;
 * mutation is performed through `BCLog::Logger`, which inherits
 * privately to gain access.
 *
 * The util::log::Log() provider should use a subclass of
 * util::log::Logger in order to be able to access and update
 * the enabled categories.
 */
class Logger
{
protected:
    /** Debug-enabled categories bitfield. */
    static constinit std::atomic<BCLog::CategoryMask> m_debug_categories;
    /** Tracing-enabled categories bitfield. */
    static constinit std::atomic<BCLog::CategoryMask> m_trace_categories;

    friend inline bool ShouldDebugLog(Category category);
    friend inline bool ShouldTraceLog(Category category);
};

/// Return whether messages in @p category should be debug logged.
inline bool ShouldDebugLog(Category category)
{
    return (Logger::m_debug_categories.load(std::memory_order_relaxed) & category) != 0;
}

/// Return whether messages in @p category should be trace logged.
inline bool ShouldTraceLog(Category category)
{
    return (Logger::m_trace_categories.load(std::memory_order_relaxed) & category) != 0;
}
} // namespace util::log

namespace BCLog {
//! Alias for compatibility. Prefer util::log::Level over BCLog::Level in new code.
using Level = util::log::Level;
} // namespace BCLog

// Allow __func__ to be used in any context without warnings:
// NOLINTNEXTLINE(bugprone-lambda-function-name)
#define detail_LogWithSrcLoc(category, level, ...) util::log::detail::LogWithSrcLoc(SourceLocation{__func__}, category, level, __VA_ARGS__)

// Log unconditionally. Uses basic rate limiting to mitigate disk filling attacks.
// Be conservative when using functions that unconditionally log to debug.log!
// It should not be the case that an inbound peer can fill up a user's storage
// with debug.log entries.
//
// Rate limiting can be skipped on a per-call basis by passing
// `util::log::NO_RATE_LIMIT` as the first argument.
#define LogInfo(...) detail_LogWithSrcLoc(BCLog::LogFlags::ALL, util::log::Level::Info, __VA_ARGS__)
#define LogWarning(...) detail_LogWithSrcLoc(BCLog::LogFlags::ALL, util::log::Level::Warning, __VA_ARGS__)
#define LogError(...) detail_LogWithSrcLoc(BCLog::LogFlags::ALL, util::log::Level::Error, __VA_ARGS__)

// Use a macro instead of a function for conditional logging to prevent
// evaluating arguments when logging for the category is not enabled.

// Log by prefixing the output with the passed category name and severity level. This logs conditionally if
// the category is allowed. No rate limiting is applied, because users specifying -debug are assumed to be
// developers or power users who are aware that -debug may cause excessive disk usage due to logging.
#define detail_LogIfCategoryAndLevelEnabled(category, shouldlog, level, ...)                  \
    do {                                                                                      \
        if (shouldlog(category)) {                                                            \
            detail_LogWithSrcLoc((category), (level), util::log::NO_RATE_LIMIT, __VA_ARGS__); \
        }                                                                                     \
    } while (0)

// Log conditionally, prefixing the output with the passed category name.
#define LogDebug(category, ...) detail_LogIfCategoryAndLevelEnabled(category, util::log::ShouldDebugLog, util::log::Level::Debug, __VA_ARGS__)
#define LogTrace(category, ...) detail_LogIfCategoryAndLevelEnabled(category, util::log::ShouldTraceLog, util::log::Level::Trace, __VA_ARGS__)

/**
 * Construct a structured-context bundle from a format string of
 * `name=value` tokens, to attach to a log line as a trailing arg:
 *
 *     class CNode {
 *         auto DisconnectMsg() {
 *             return LogKVs("peer=%d disconnected=%d", GetId(), true);
 *         }
 *     };
 *     LogInfo("dropping connection", node.DisconnectMsg());
 *
 * The format string must contain only `name=value` tokens (no prose
 * msg, no positional `%`-specs); enforced at compile time by `MakeKVs`'s
 * consteval-parsing of the format string.
 */
#define LogKVs(...) \
    ::util::kvformat::MakeKVs(__VA_ARGS__)

#endif // BITCOIN_UTIL_LOG_H
