// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/lib/logging.h>

#include <logging.h>
#include <noui.h>
#include <tinyformat.h>
#include <util/memory.h>

#include <stdexcept>

DebugLogHelper::DebugLogHelper(const std::string& message, bool capture)
    : m_message{message}, m_capture{capture}
{
    m_print_connection = LogInstance().PushBackCallback(
        [this](const std::string& s) {
            if (m_found) return;
            if (s.find(m_message) != std::string::npos) {
                m_found = true;
                m_log = "";
            } else if (m_capture) {
                m_log += s;
            }
        });
    noui_test_redirect();
}

void DebugLogHelper::check_found()
{
    noui_reconnect();
    LogInstance().DeleteCallback(m_print_connection);
    if (!m_found) {
        throw std::runtime_error(strprintf("'%s' not found in debug log%s\n", m_message, (m_capture ? strprintf(": '''\n%s'''", m_log) : "")));
    }
}
