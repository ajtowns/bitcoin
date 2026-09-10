// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_TEMPLATEMAN_H
#define BITCOIN_TEST_UTIL_TEMPLATEMAN_H

#include <node/templateman.h>

/** A PeerTemplateSketchT that drops its placeholder refs when it goes away.
 *
 *  Tests fill m_txs with pool.end() placeholders, which carry no refcount, so
 *  nothing releases them the way TemplateManagerT does in production. Without
 *  this, ~TemplateTxVec's Assume(empty()) fires on every exit path. */
template <int SketchCapacity>
class TestPeerTemplateSketchT : public node::PeerTemplateSketchT<SketchCapacity>
{
    const node::TemplateTxSet& m_pool;

public:
    TestPeerTemplateSketchT(const node::TemplateTxSet& pool) : m_pool{pool} { }

    ~TestPeerTemplateSketchT() {
        this->m_txs.clear_placeholders(m_pool);
    }
};

/** Production-capacity version, for tests that don't templatize capacity. */
using TestPeerTemplateSketch = TestPeerTemplateSketchT<node::SKETCH_CAPACITY>;

#endif // BITCOIN_TEST_UTIL_TEMPLATEMAN_H
