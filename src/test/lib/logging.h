// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_LIB_LOGGING_H
#define BITCOIN_TEST_LIB_LOGGING_H

#include <string>
#include <vector>

void assert_debug_log_redirect();
void assert_debug_log_helper(const std::vector<std::string>& messages);

#define ASSERT_DEBUG_LOG(vec_messages, code) [&] { \
    assert_debug_log_redirect();                   \
    code;                                          \
    assert_debug_log_helper(vec_messages);         \
}()

#endif // BITCOIN_TEST_LIB_LOGGING_H
