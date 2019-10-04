// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_LIB_LOGGING_H
#define BITCOIN_TEST_LIB_LOGGING_H

#include <functional>
#include <list>
#include <string>

class DebugLogHelper
{
private:
    const std::string m_message;
    const bool m_capture;
    std::string m_log;
    bool m_found = false;
    std::list<std::function<void(const std::string&)>>::iterator m_print_connection;

    void check_found();
public:
    DebugLogHelper(const std::string& message, bool capture=false);
    ~DebugLogHelper() { check_found(); }
};

#define PASTE(x, y) x ## y
#define PASTE2(x, y) PASTE(x, y)

#define ASSERT_DEBUG_LOG(message) DebugLogHelper PASTE2(debugloghelper, __COUNTER__)(message)
#define ASSERT_DEBUG_LOG_CAPTURE(message) DebugLogHelper PASTE2(debugloghelper, __COUNTER__)(message, true)

#if 0
#define ASSERT_DEBUG_LOG(vec_messages, code) [&] { \
    assert_debug_log_redirect();                   \
    code;                                          \
    assert_debug_log_helper(vec_messages);         \
}()
#endif

#endif // BITCOIN_TEST_LIB_LOGGING_H
