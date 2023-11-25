// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/txhash.h>

#include <crypto/ripemd160.h>
#include <crypto/sha1.h>
#include <crypto/sha256.h>
#include <pubkey.h>
#include <script/script.h>
#include <uint256.h>

/// Validate a input/output range selector.
///
/// Returns the number of bytes used from the buffer.
bool parse_inout_selector(
    std::vector<unsigned char>::const_iterator&& bytes,
    const std::vector<unsigned char>::const_iterator& bytes_end,
    unsigned int nb_items,
    bool* out_count = nullptr,
    bool* out_all = nullptr,
    bool* out_current = nullptr,
    unsigned int* out_leading = nullptr,
    std::vector<unsigned int>* out_individual = nullptr
) {
    if (bytes == bytes_end) {
        return false; // unexpected EOF
    }
    bool commit_count = (*bytes & TXFS_INOUT_NUMBER) != 0;
    if (out_count) {
        out_count = &commit_count;
    }
    unsigned int range = *bytes & (0xff ^ TXFS_INOUT_NUMBER);
    bytes++;

    if (range == TXFS_INOUT_RANGE_NONE) {
        if (!commit_count) {
            return false; // no in/output range given and nb_items bitflag also unset
        }
        return true;
    } else if (range == TXFS_INOUT_RANGE_ALL) {
        if (out_all) {
            *out_all = true;
        }
        return true;
    } else if (range == TXFS_INOUT_RANGE_CURRENT) {
        if (out_current) {
            *out_current = true;
        }
        return true;
    } else if ((range & TXFS_INOUT_RANGE_MODE) == 0) {
        // leading mode
        unsigned int count;
        if ((range & TXFS_INOUT_RANGE_SIZE) == 0) {
            count = range & TXFS_INOUT_RANGE_MASK;
            if (count > nb_items) {
                return false; // nb of leading in/outputs too high
            }
        } else {
            if (bytes == bytes_end) {
                return false; // unexpected EOF
            }
            unsigned int next_byte = *bytes;
            bytes++;

            if ((range & TXFS_INOUT_RANGE_MASK) == 0) {
                return false; // non-minimal range
            }
            count = ((range & TXFS_INOUT_RANGE_MASK) << 8) + next_byte;
            if (count > nb_items) {
                return false; // nb of leading in/outputs too high
            }
        }
        if (out_leading) {
            *out_leading = count;
        }
        return true;
    } else {
        // individual mode
        unsigned int count = range & TXFS_INOUT_RANGE_MASK;
        if (count == 0) {
            return false; // invalid 0 range count for individual mode
        }

        std::vector<unsigned int> indices = {};
        if ((range & TXFS_INOUT_RANGE_SIZE) == 0) {
            unsigned char last = 0;
            for (unsigned int i = 0; i < count; i++) {
                if (bytes == bytes_end) {
                    return false; // not enough indices
                }
                unsigned int idx = *bytes;
                bytes++;

                if (idx > nb_items) {
                    return false; // range index out of bounds
                }
                if (i > 0) {
                    if (idx <= last) {
                        return false; // indices not in increasing order
                    }
                }
                last = idx;
                indices.push_back(idx);
            }
        } else {
            unsigned char last = 0;
            for (unsigned int i = 0; i < count; i++) {
                if (bytes == bytes_end) {
                    return false; // not enough index bytes
                }
                unsigned int first = *bytes;
                bytes++;
                if (bytes == bytes_end) {
                    return false; // not enough index bytes
                }
                unsigned int second = *bytes;
                bytes++;

                unsigned int idx = (first << 8) + second;
                if (idx > nb_items) {
                    return false; // range index out of bounds
                }
                if (i > 0) {
                    if (idx <= last) {
                        return false; // indices not in increasing order
                    }
                }
                last = idx;
                indices.push_back(idx);
            }
        }
        if (out_individual) {
            *out_individual = indices;
        }
        return true;
    }

    return false; // should be unreachable
}


bool validate_field_selector(
    std::vector<unsigned char> field_selector,
    unsigned int nb_inputs,
    unsigned int nb_outputs
) {
    if (field_selector.empty()) {
        return true; // DEFAULT
    }
    if (field_selector.size() == 1 && field_selector[0] == 0) {
        return true; // ALL
    }

    auto bytes = field_selector.begin();
    auto bytes_end = field_selector.end();
    unsigned char global = *bytes;
    bytes++;

    if ((global & TXFS_INPUTS) == 0 && (global & TXFS_OUTPUTS) == 0) {
        if (bytes != bytes_end) {
            return false; // input and output bit unset and more than one byte
        }
        return true;
    }

    if (bytes == bytes_end) {
        return false; // in- or output bit set but only one byte
    }
    unsigned char inout_fields = *bytes;
    bytes++;

    if ((global & TXFS_INPUTS) != 0) {
        if ((inout_fields & TXFS_INPUTS_ALL) == 0) {
            return false; // inputs bit set but no input bits set
        }
        if (!parse_inout_selector(bytes, bytes_end, nb_inputs)) {
            return false;
        }
    } else {
        if ((inout_fields & TXFS_INPUTS_ALL) != 0) {
            return false; // inputs bit not set but some input bits set
        }
    }

    if ((global & TXFS_OUTPUTS) != 0) {
        if ((inout_fields & TXFS_OUTPUTS_ALL) == 0) {
            return false; // outputs bit set but no output bits set
        }
        if (!parse_inout_selector(bytes, bytes_end, nb_outputs)) {
            return false;
        }
    } else {
        if ((inout_fields & TXFS_OUTPUTS_ALL) != 0) {
            return false; // outputs bit  not set but some output bits set
        }
    }

    return true;
}


// The following hash calculation methods panic on index out of bounds.

uint256 sha256_bytes(std::vector<unsigned char>& bytes) {
    uint256 out;
    CSHA256().Write(&*bytes.begin(), bytes.size()).Finalize(out.begin());
    return out;
}
uint256 sha256_script(const CScript& script) {
    uint256 out;
    CSHA256().Write(&*script.begin(), script.size()).Finalize(out.begin());
    return out;
}

//TODO(stevenroose) check that resize is noop if already good size
uint256 script_sig_hash(TxHashCache& cache, const std::vector<CTxIn>& inputs, unsigned int idx) {
    if (cache.hashed_script_sigs.empty() || cache.hashed_script_sigs[idx].IsNull()) {
        LOCK(cache.mtx);
        cache.hashed_script_sigs.resize(inputs.size());
        cache.hashed_script_sigs[idx] = sha256_script(inputs[idx].scriptSig);
    }
    return cache.hashed_script_sigs[idx];
}

uint256 spent_script_hash(TxHashCache& cache, const std::vector<CTxOut> spent_outputs, unsigned int idx) {
    if (cache.hashed_spent_scripts.empty() || cache.hashed_spent_scripts[idx].IsNull()) {
        LOCK(cache.mtx);
        cache.hashed_spent_scripts.resize(spent_outputs.size());
        cache.hashed_spent_scripts[idx] = sha256_script(spent_outputs[idx].scriptPubKey);
    }
    return cache.hashed_spent_scripts[idx];
}

uint256 annex_hash(TxHashCache& cache, const std::vector<CTxIn>& inputs, unsigned int idx) {
    if (cache.hashed_annexes.empty() || cache.hashed_annexes[idx].IsNull()) {
        LOCK(cache.mtx);
        cache.hashed_annexes.resize(inputs.size());
        //TODO(stevenroose) annex
        cache.hashed_annexes[idx] = sha256_script(inputs[idx].scriptSig);
    }
    return cache.hashed_annexes[idx];
}

uint256 script_pubkey_hash(TxHashCache& cache, const std::vector<CTxOut>& outputs, unsigned int idx) {
    if (cache.hashed_script_pubkeys.empty() || cache.hashed_script_pubkeys[idx].IsNull()) {
        LOCK(cache.mtx);
        cache.hashed_script_pubkeys.resize(outputs.size());
        cache.hashed_script_pubkeys[idx] = sha256_script(outputs[idx].scriptPubKey);
    }
    return cache.hashed_script_pubkeys[idx];
}

uint256 leading_prevouts_hash(TxHashCache& cache, const std::vector<CTxIn>& inputs, unsigned int nb) {
    if (cache.leading_prevouts.empty()) {
        cache.leading_prevouts.reserve(inputs.size() / LEADING_CACHE_INTERVAL);
    }

    unsigned int cache_cursor = (cache.leading_prevouts.size() + 1) * LEADING_CACHE_INTERVAL;
    unsigned int cursor = std::min(cache_cursor, nb / LEADING_CACHE_INTERVAL);

    HashWriter ss;
    if (cursor != 0) {
        ss = HashWriter(cache.leading_prevouts[cursor / LEADING_CACHE_INTERVAL]);
    } else {
        ss = HashWriter{};
    }

    while (cursor < nb) {
        ss << inputs[cursor].prevout;
        if (cursor % LEADING_CACHE_INTERVAL == 0) {
            cache.leading_prevouts.push_back(ss.GetHashCtx());
        }
        cursor++;
    }

    return ss.GetSHA256();
}

uint256 leading_sequences_hash(TxHashCache& cache, const std::vector<CTxIn>& inputs, unsigned int nb) {
    if (cache.leading_sequences.empty()) {
        cache.leading_sequences.reserve(inputs.size() / LEADING_CACHE_INTERVAL);
    }

    unsigned int cache_cursor = (cache.leading_sequences.size() + 1) * LEADING_CACHE_INTERVAL;
    unsigned int cursor = std::min(cache_cursor, nb / LEADING_CACHE_INTERVAL);

    HashWriter ss;
    if (cursor != 0) {
        ss = HashWriter(cache.leading_sequences[cursor / LEADING_CACHE_INTERVAL]);
    } else {
        ss = HashWriter{};
    }

    while (cursor < nb) {
        ss << inputs[cursor].nSequence;
        if (cursor % LEADING_CACHE_INTERVAL == 0) {
            cache.leading_sequences.push_back(ss.GetHashCtx());
        }
        cursor++;
    }

    return ss.GetSHA256();
}

uint256 leading_script_sigs_hash(TxHashCache& cache, const std::vector<CTxIn>& inputs, unsigned int nb) {
    if (cache.leading_script_sigs.empty()) {
        cache.leading_script_sigs.reserve(inputs.size() / LEADING_CACHE_INTERVAL);
    }

    unsigned int cache_cursor = (cache.leading_script_sigs.size() + 1) * LEADING_CACHE_INTERVAL;
    unsigned int cursor = std::min(cache_cursor, nb / LEADING_CACHE_INTERVAL);

    HashWriter ss;
    if (cursor != 0) {
        ss = HashWriter(cache.leading_script_sigs[cursor / LEADING_CACHE_INTERVAL]);
    } else {
        ss = HashWriter{};
    }

    while (cursor < nb) {
        ss << script_sig_hash(cache, inputs, cursor);
        if (cursor % LEADING_CACHE_INTERVAL == 0) {
            cache.leading_script_sigs.push_back(ss.GetHashCtx());
        }
        cursor++;
    }

    return ss.GetSHA256();
}

uint256 leading_spent_scripts_hash(TxHashCache& cache, const std::vector<CTxOut>& spent_outputs, unsigned int nb) {
    if (cache.leading_spent_scripts.empty()) {
        cache.leading_spent_scripts.reserve(spent_outputs.size() / LEADING_CACHE_INTERVAL);
    }

    unsigned int cache_cursor = (cache.leading_spent_scripts.size() + 1) * LEADING_CACHE_INTERVAL;
    unsigned int cursor = std::min(cache_cursor, nb / LEADING_CACHE_INTERVAL);

    HashWriter ss;
    if (cursor != 0) {
        ss = HashWriter(cache.leading_spent_scripts[cursor / LEADING_CACHE_INTERVAL]);
    } else {
        ss = HashWriter{};
    }

    while (cursor < nb) {
        ss << spent_script_hash(cache, spent_outputs, cursor);
        if (cursor % LEADING_CACHE_INTERVAL == 0) {
            cache.leading_spent_scripts.push_back(ss.GetHashCtx());
        }
        cursor++;
    }

    return ss.GetSHA256();
}

uint256 leading_spent_amounts_hash(TxHashCache& cache, const std::vector<CTxOut>& spent_outputs, unsigned int nb) {
    if (cache.leading_spent_amounts.empty()) {
        cache.leading_spent_amounts.reserve(spent_outputs.size() / LEADING_CACHE_INTERVAL);
    }

    unsigned int cache_cursor = (cache.leading_spent_amounts.size() + 1) * LEADING_CACHE_INTERVAL;
    unsigned int cursor = std::min(cache_cursor, nb / LEADING_CACHE_INTERVAL);

    HashWriter ss;
    if (cursor != 0) {
        ss = HashWriter(cache.leading_spent_amounts[cursor / LEADING_CACHE_INTERVAL]);
    } else {
        ss = HashWriter{};
    }

    while (cursor < nb) {
        ss << spent_outputs[cursor].nValue;
        if (cursor % LEADING_CACHE_INTERVAL == 0) {
            cache.leading_spent_amounts.push_back(ss.GetHashCtx());
        }
        cursor++;
    }

    return ss.GetSHA256();
}

uint256 leading_annexes_hash(TxHashCache& cache, const std::vector<CTxIn>& inputs, unsigned int nb) {
    if (cache.leading_annexes.empty()) {
        cache.leading_annexes.reserve(inputs.size() / LEADING_CACHE_INTERVAL);
    }

    unsigned int cache_cursor = (cache.leading_annexes.size() + 1) * LEADING_CACHE_INTERVAL;
    unsigned int cursor = std::min(cache_cursor, nb / LEADING_CACHE_INTERVAL);

    HashWriter ss;
    if (cursor != 0) {
        ss = HashWriter(cache.leading_annexes[cursor / LEADING_CACHE_INTERVAL]);
    } else {
        ss = HashWriter{};
    }

    while (cursor < nb) {
        ss << annex_hash(cache, inputs, cursor);
        if (cursor % LEADING_CACHE_INTERVAL == 0) {
            cache.leading_annexes.push_back(ss.GetHashCtx());
        }
        cursor++;
    }

    return ss.GetSHA256();
}

uint256 leading_script_pubkeys_hash(TxHashCache& cache, const std::vector<CTxOut>& outputs, unsigned int nb) {
    if (cache.leading_script_pubkeys.empty()) {
        cache.leading_script_pubkeys.reserve(outputs.size() / LEADING_CACHE_INTERVAL);
    }

    unsigned int cache_cursor = (cache.leading_script_pubkeys.size() + 1) * LEADING_CACHE_INTERVAL;
    unsigned int cursor = std::min(cache_cursor, nb / LEADING_CACHE_INTERVAL);

    HashWriter ss;
    if (cursor != 0) {
        ss = HashWriter(cache.leading_script_pubkeys[cursor / LEADING_CACHE_INTERVAL]);
    } else {
        ss = HashWriter{};
    }

    while (cursor < nb) {
        ss << script_pubkey_hash(cache, outputs, cursor);
        if (cursor % LEADING_CACHE_INTERVAL == 0) {
            cache.leading_script_pubkeys.push_back(ss.GetHashCtx());
        }
        cursor++;
    }

    return ss.GetSHA256();
}

uint256 leading_amounts_hash(TxHashCache& cache, const std::vector<CTxOut>& outputs, unsigned int nb) {
    if (cache.leading_amounts.empty()) {
        cache.leading_amounts.reserve(outputs.size() / LEADING_CACHE_INTERVAL);
    }

    unsigned int cache_cursor = (cache.leading_amounts.size() + 1) * LEADING_CACHE_INTERVAL;
    unsigned int cursor = std::min(cache_cursor, nb / LEADING_CACHE_INTERVAL);

    HashWriter ss;
    if (cursor != 0) {
        ss = HashWriter(cache.leading_amounts[cursor / LEADING_CACHE_INTERVAL]);
    } else {
        ss = HashWriter{};
    }

    while (cursor < nb) {
        ss << outputs[cursor].nValue;
        if (cursor % LEADING_CACHE_INTERVAL == 0) {
            cache.leading_amounts.push_back(ss.GetHashCtx());
        }
        cursor++;
    }

    return ss.GetSHA256();
}

uint256 all_prevouts_hash(TxHashCache& cache, const std::vector<CTxIn>& inputs) {
    if (cache.all_prevouts.IsNull()) {
        LOCK(cache.mtx);
        cache.all_prevouts = leading_prevouts_hash(cache, inputs, inputs.size());
    }
    return cache.all_prevouts;
}

uint256 all_sequences_hash(TxHashCache& cache, const std::vector<CTxIn>& inputs) {
    if (cache.all_sequences.IsNull()) {
        LOCK(cache.mtx);
        cache.all_sequences = leading_sequences_hash(cache, inputs, inputs.size());
    }
    return cache.all_sequences;
}

uint256 all_script_sigs_hash(TxHashCache& cache, const std::vector<CTxIn>& inputs) {
    if (cache.all_script_sigs.IsNull()) {
        LOCK(cache.mtx);
        cache.all_script_sigs = leading_script_sigs_hash(cache, inputs, inputs.size());
    }
    return cache.all_script_sigs;
}

uint256 all_spent_scripts_hash(TxHashCache& cache, const std::vector<CTxOut>& spent_outputs) {
    if (cache.all_spent_scripts.IsNull()) {
        LOCK(cache.mtx);
        cache.all_spent_scripts = leading_spent_scripts_hash(cache, spent_outputs, spent_outputs.size());
    }
    return cache.all_spent_scripts;
}

uint256 all_spent_amounts_hash(TxHashCache& cache, const std::vector<CTxOut>& spent_outputs) {
    if (cache.all_spent_amounts.IsNull()) {
        LOCK(cache.mtx);
        cache.all_spent_amounts = leading_spent_amounts_hash(cache, spent_outputs, spent_outputs.size());
    }
    return cache.all_spent_amounts;
}

uint256 all_annexes_hash(TxHashCache& cache, const std::vector<CTxIn>& inputs) {
    if (cache.all_annexes.IsNull()) {
        LOCK(cache.mtx);
        cache.all_annexes = leading_annexes_hash(cache, inputs, inputs.size());
    }
    return cache.all_annexes;
}

uint256 all_script_pubkeys_hash(TxHashCache& cache, const std::vector<CTxOut>& outputs) {
    if (cache.all_script_pubkeys.IsNull()) {
        LOCK(cache.mtx);
        cache.all_script_pubkeys = leading_script_pubkeys_hash(cache, outputs, outputs.size());
    }
    return cache.all_script_pubkeys;
}

uint256 all_amounts_hash(TxHashCache& cache, const std::vector<CTxOut>& outputs) {
    if (cache.all_amounts.IsNull()) {
        LOCK(cache.mtx);
        cache.all_amounts = leading_amounts_hash(cache, outputs, outputs.size());
    }
    return cache.all_amounts;
}

uint256 selected_prevouts_hash(TxHashCache& cache, const std::vector<CTxIn>& inputs, std::vector<unsigned int>& indices) {
    HashWriter ss{};
    for (unsigned int i = 0; i < indices.size(); i++) {
        unsigned int idx = indices[i];
        ss << inputs[idx].prevout;
    }
    return ss.GetSHA256();
}

uint256 selected_sequences_hash(TxHashCache& cache, const std::vector<CTxIn>& inputs, std::vector<unsigned int>& indices) {
    HashWriter ss{};
    for (unsigned int i = 0; i < indices.size(); i++) {
        unsigned int idx = indices[i];
        ss << inputs[idx].nSequence;
    }
    return ss.GetSHA256();
}

uint256 selected_script_sigs_hash(TxHashCache& cache, const std::vector<CTxIn>& inputs, std::vector<unsigned int>& indices) {
    HashWriter ss{};
    for (unsigned int i = 0; i < indices.size(); i++) {
        unsigned int idx = indices[i];
        ss << script_sig_hash(cache, inputs, idx);
    }
    return ss.GetSHA256();
}

uint256 selected_spent_scripts_hash(TxHashCache& cache, const std::vector<CTxOut>& spent_outputs, std::vector<unsigned int>& indices) {
    HashWriter ss{};
    for (unsigned int i = 0; i < indices.size(); i++) {
        unsigned int idx = indices[i];
        ss << spent_script_hash(cache, spent_outputs, idx);
    }
    return ss.GetSHA256();
}

uint256 selected_spent_amounts_hash(TxHashCache& cache, const std::vector<CTxOut>& spent_outputs, std::vector<unsigned int>& indices) {
    HashWriter ss{};
    for (unsigned int i = 0; i < indices.size(); i++) {
        unsigned int idx = indices[i];
        ss << spent_outputs[idx].nValue;
    }
    return ss.GetSHA256();
}

uint256 selected_annexes_hash(TxHashCache& cache, const std::vector<CTxIn>& inputs, std::vector<unsigned int>& indices) {
    HashWriter ss{};
    for (unsigned int i = 0; i < indices.size(); i++) {
        unsigned int idx = indices[i];
        ss << annex_hash(cache, inputs, idx);
    }
    return ss.GetSHA256();
}

uint256 selected_script_pubkeys_hash(TxHashCache& cache, const std::vector<CTxOut>& outputs, std::vector<unsigned int>& indices) {
    HashWriter ss{};
    for (unsigned int i = 0; i < indices.size(); i++) {
        unsigned int idx = indices[i];
        ss << script_pubkey_hash(cache, outputs, idx);
    }
    return ss.GetSHA256();
}

uint256 selected_amounts_hash(TxHashCache& cache, const std::vector<CTxOut>& outputs, std::vector<unsigned int>& indices) {
    HashWriter ss{};
    for (unsigned int i = 0; i < indices.size(); i++) {
        unsigned int idx = indices[i];
        ss << outputs[idx].nValue;
    }
    return ss.GetSHA256();
}

template<class T>
bool calculate_txhash(
    uint256& hash_out,
    const std::vector<unsigned char>& field_selector,
    TxHashCache& cache,
    const T& tx,
    const std::vector<CTxOut>& spent_outputs,
    const std::vector<unsigned char>& control_block,
    uint32_t codeseparator_pos,
    uint32_t in_pos
) {
    assert(tx.vin.size() == spent_outputs.size());
    assert(in_pos < tx.vin.size());

    if (field_selector.empty()) {
        field_selector = TXFS_TEMPLATE_DEFAULT;
    } else if (field_selector.size() == 1 && field_selector[0] == 0) {
        field_selector = TXFS_TEMPLATE_ALL;
    }

    HashWriter ss{};

    unsigned char global = field_selector[0];

    if ((global & TXFS_CONTROL) != 0) {
        ss << field_selector;
    }

    if ((global & TXFS_VERSION) != 0) {
        ss << tx.nVersion;
    }

    if ((global & TXFS_LOCKTIME) != 0) {
        ss << tx.nLockTime;
    }

    if ((global & TXFS_CURRENT_INPUT_IDX) != 0) {
        ss << in_pos;
    }

    if ((global & TXFS_CURRENT_INPUT_CONTROL_BLOCK) != 0) {
        ss << control_block;
    }

    if ((global & TXFS_CURRENT_INPUT_LAST_CODESEPARATOR_POS) != 0) {
        ss << codeseparator_pos;
    }

    // INPUTS
    std::vector<unsigned char>::const_iterator bytes_end = field_selector.end();
    std::vector<unsigned char>::const_iterator bytes = field_selector.begin() + 1;
    if ((global & TXFS_INPUTS) != 0 || (global & TXFS_OUTPUTS) != 0) {
        bytes++;
    }

    if ((global & TXFS_INPUTS) != 0) {
        bool count = false;
        bool all = false;
        bool current = false;
        unsigned int leading = 0;
        std::vector<unsigned int> individual = {};
        assert(parse_inout_selector(bytes, bytes_end, tx.vin.size(), &count, &all, &current, &leading, &individual));

        if (count) {
            uint32_t len32 = tx.vin.size();
            ss << len32;
        }

        unsigned char inout_fields = field_selector[1];

        if ((inout_fields & TXFS_INPUTS_PREVOUTS) != 0) {
            if (all) {
                ss << all_prevouts_hash(cache, tx.vin);
            }
            if (current) {
                ss << (HashWriter{} << tx.vin[in_pos].prevout).GetSHA256();
            }
            if (leading) {
                ss << leading_prevouts_hash(cache, tx.vin, leading);
            }
            if (!individual.empty()) {
                ss << selected_prevouts_hash(cache, tx.vin, individual);
            }
        }

        if ((inout_fields & TXFS_INPUTS_SEQUENCES) != 0) {
            if (all) {
                ss << all_sequences_hash(cache, tx.vin);
            }
            if (current) {
                ss << (HashWriter{} << tx.vin[in_pos].nSequence).GetSHA256();
            }
            if (leading) {
                ss << leading_sequences_hash(cache, tx.vin, leading);
            }
            if (!individual.empty()) {
                ss << selected_sequences_hash(cache, tx.vin, individual);
            }
        }

        if ((inout_fields & TXFS_INPUTS_SCRIPTSIGS) != 0) {
            if (all) {
                ss << all_script_sigs_hash(cache, tx.vin);
            }
            if (current) {
                ss << (HashWriter{} << script_sig_hash(cache, tx.vin, current)).GetSHA256();
            }
            if (leading) {
                ss << leading_script_sigs_hash(cache, tx.vin, leading);
            }
            if (!individual.empty()) {
                ss << selected_script_sigs_hash(cache, tx.vin, individual);
            }
        }

        if ((inout_fields & TXFS_INPUTS_PREV_SCRIPTPUBKEYS) != 0) {
            if (all) {
                ss << all_spent_scripts_hash(cache, spent_outputs);
            }
            if (current) {
                ss << (HashWriter{} << spent_script_hash(cache, spent_outputs, current)).GetSHA256();
            }
            if (leading) {
                ss << leading_spent_scripts_hash(cache, spent_outputs, leading);
            }
            if (!individual.empty()) {
                ss << selected_spent_scripts_hash(cache, spent_outputs, individual);
            }
        }

        if ((inout_fields & TXFS_INPUTS_PREV_VALUES) != 0) {
            if (all) {
                ss << all_spent_amounts_hash(cache, spent_outputs);
            }
            if (current) {
                ss << (HashWriter{} << spent_outputs[current].nValue).GetSHA256();
            }
            if (leading) {
                ss << leading_spent_amounts_hash(cache, spent_outputs, leading);
            }
            if (!individual.empty()) {
                ss << selected_spent_amounts_hash(cache, spent_outputs, individual);
            }
        }

        if ((inout_fields & TXFS_INPUTS_TAPROOT_ANNEXES) != 0) {
            if (all) {
                ss << all_annexes_hash(cache, tx.vin);
            }
            if (current) {
                ss << (HashWriter{} << annex_hash(cache, tx.vin, current)).GetSHA256();
            }
            if (leading) {
                ss << leading_annexes_hash(cache, tx.vin, leading);
            }
            if (!individual.empty()) {
                ss << selected_annexes_hash(cache, tx.vin, individual);
            }
        }
    }

    if ((global & TXFS_OUTPUTS) != 0) {
        bool count = false;
        bool all = false;
        //TODO(stevenroose) handle current output oob
        bool current = false;
        unsigned int leading = 0;
        std::vector<unsigned int> individual = {};
        assert(parse_inout_selector(bytes, bytes_end, tx.vout.size(), &count, &all, &current, &leading, &individual));

        if (count) {
            uint32_t len32 = tx.vout.size();
            ss << len32;
        }

        unsigned char inout_fields = field_selector[1];

        if ((inout_fields & TXFS_OUTPUTS_SCRIPT_PUBKEYS) != 0) {
            if (all) {
                ss << all_script_pubkeys_hash(cache, tx.vout);
            }
            if (current) {
                ss << (HashWriter{} << script_pubkey_hash(cache, tx.vout, current)).GetSHA256();
            }
            if (leading) {
                ss << leading_script_pubkeys_hash(cache, tx.vout, leading);
            }
            if (!individual.empty()) {
                ss << selected_script_pubkeys_hash(cache, tx.vout, individual);
            }
        }

        if ((inout_fields & TXFS_OUTPUTS_VALUES) != 0) {
            if (all) {
                ss << all_amounts_hash(cache, tx.vout);
            }
            if (current) {
                ss << (HashWriter{} << tx.vout[current].nValue).GetSHA256();
            }
            if (leading) {
                ss << leading_amounts_hash(cache, tx.vout, leading);
            }
            if (!individual.empty()) {
                ss << selected_amounts_hash(cache, tx.vout, individual);
            }
        }
    }

    hash_out = ss.GetSHA256();
    return true;
}
