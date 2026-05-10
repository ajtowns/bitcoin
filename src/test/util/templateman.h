// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_TEMPLATEMAN_H
#define BITCOIN_TEST_UTIL_TEMPLATEMAN_H

#include <node/templateman.h>

/** A PeerTemplateSketch that drops its placeholder refs when it goes away.
 *
 * Tests fill m_txs with pool.end() placeholders, which carry no refcount, so
 * nothing releases them the way TemplateManager does in production. Without
 * this, ~TemplateTxVec's Assume(empty()) fires on every exit path. */
class TestPeerTemplateSketch : public node::PeerTemplateSketch
{
    const node::TemplateTxSet& m_pool;

public:
    TestPeerTemplateSketch(const node::TemplateTxSet& pool) : m_pool{pool} { }

    ~TestPeerTemplateSketch() {
        m_txs.clear_placeholders(m_pool);
    }
};

#endif // BITCOIN_TEST_UTIL_TEMPLATEMAN_H
