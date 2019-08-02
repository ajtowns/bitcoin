// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/lib/logging.h>

#include <logging.h>
#include <noui.h>
#include <tinyformat.h>
#include <util/memory.h>

#include <stdexcept>

static std::list<std::function<void(const std::string&)>>::iterator g_print_connection;
static std::unique_ptr<std::string> g_log_lines{nullptr};

void assert_debug_log_redirect()
{
    assert(!g_log_lines);
    g_log_lines = MakeUnique<std::string>();
    g_print_connection = LogInstance().PushBackCallback(
        [](const std::string& s) {
            (*g_log_lines) += s;
        });
    noui_test_redirect();
}

void assert_debug_log_helper(const std::vector<std::string>& messages)
{
    for (const auto& m : messages) {
        if (g_log_lines->find(m) == std::string::npos) {
            throw std::runtime_error(strprintf("\n'%s'\n not found in \n'%s'\n", m, *g_log_lines));
        }
    }
    noui_reconnect();
    LogInstance().DeleteCallback(g_print_connection);
    assert(g_log_lines);
    g_log_lines.reset();
}
