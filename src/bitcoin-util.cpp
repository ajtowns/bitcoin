// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <clientversion.h>
#include <coins.h>
#include <common/args.h>
#include <common/license_info.h>
#include <common/system.h>
#include <compat/compat.h>
#include <core_io.h>
#include <crypto/muhash.h>
#include <hash.h>
#include <node/utxo_snapshot.h>
#include <serialize.h>
#include <streams.h>
#include <univalue.h>
#include <util/exception.h>
#include <util/fs.h>
#include <util/overflow.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <thread>
#include <vector>

namespace {

/** The snapshot format's leaf size and branch width, and the tags its merkle
 * tree hashes with. The root commits to all four, so a reader has to use the
 * same values, and they are format constants rather than anything a chainparams
 * entry carries, since the root binds them. They sit here rather than with the
 * magic in node/utxo_snapshot.h because they are this format's own proposal and
 * the node has no use for them yet. */
static constexpr size_t SNAPSHOT_LEAF_SIZE{1 << 16};
static constexpr size_t SNAPSHOT_BRANCH_LEAVES{2048};
static constexpr std::string_view SNAPSHOT_LEAF_TAG{"BIP452Leaf"};
static constexpr std::string_view SNAPSHOT_BRANCH_TAG{"BIP452Branch"};

/** The tree's two tag hashes, primed once the way hash.h's TaggedHash provides
 * them: the tag's own hash written twice, with the data to follow. GetSHA256,
 * not GetHash, because the tag stands in for the prefix, not for a wrapper. */
const HashWriter LEAF_TAG_HASHER{TaggedHash(std::string{SNAPSHOT_LEAF_TAG})};
const HashWriter BRANCH_TAG_HASHER{TaggedHash(std::string{SNAPSHOT_BRANCH_TAG})};

static uint256 TaggedHashOf(const HashWriter& tag_hasher, std::span<const unsigned char> data)
{
    HashWriter ss{tag_hasher};
    ss.write(std::as_bytes(data));
    return ss.GetSHA256();
}

/** Leaf hashes, taken by workers: leaves are independent of one another, so
 * unlike the stream hash they can be hashed in parallel, with each worker's
 * results kept in its own list and order put back afterwards. */
class LeafHashPool
{
public:
    explicit LeafHashPool(size_t workers)
    {
        m_results.resize(workers);
        m_threads.reserve(workers);
        for (size_t i{0}; i < workers; ++i) {
            m_threads.emplace_back([this, i] { Work(i); });
        }
    }

    void Push(size_t index, std::vector<uint8_t> block)
    {
        {
            std::unique_lock lock{m_mutex};
            m_not_empty.wait(lock, [&] { return m_done || m_blocks.size() < 64; });
            if (m_done) return;
            m_blocks.emplace_back(index, std::move(block));
        }
        m_not_empty.notify_one();
    }

    void Finish()
    {
        {
            std::lock_guard lock{m_mutex};
            m_done = true;
        }
        m_not_empty.notify_all();
        for (auto& thread : m_threads) thread.join();
    }

    /** Wait for the workers, then fold the leaf hashes, in index order, to the
     * snapshot root. */
    uint256 Root()
    {
        Finish();
        std::vector<std::pair<size_t, uint256>> all;
        for (auto& per_worker : m_results) {
            all.insert(all.end(), per_worker.begin(), per_worker.end());
        }
        std::sort(all.begin(), all.end());

        // Each branch folds on its own, so a full one always folds the same way,
        // and the root is the tree over the branch roots.
        std::vector<uint256> branch_roots;
        for (size_t start{0}; start < all.size(); start += SNAPSHOT_BRANCH_LEAVES) {
            const size_t end{std::min(start + SNAPSHOT_BRANCH_LEAVES, all.size())};
            std::vector<uint256> level;
            level.reserve(end - start);
            for (size_t i{start}; i < end; ++i) level.push_back(all[i].second);
            while (level.size() > 1) level = FoldLevel(level);
            branch_roots.push_back(level[0]);
        }
        while (branch_roots.size() > 1) branch_roots = FoldLevel(branch_roots);
        return branch_roots.empty() ? uint256{} : branch_roots[0];
    }

private:
    /** Fold one level of the tree: pair up, and carry an odd node up unchanged
     * rather than duplicating it. */
    static std::vector<uint256> FoldLevel(const std::vector<uint256>& level)
    {
        std::vector<uint256> next;
        next.reserve((level.size() + 1) / 2);
        for (size_t i{0}; i < level.size(); i += 2) {
            if (i + 1 == level.size()) {
                next.push_back(level[i]);
            } else {
                DataStream pair{};
                pair << level[i] << level[i + 1];
                next.push_back(TaggedHashOf(BRANCH_TAG_HASHER, MakeUCharSpan(pair)));
            }
        }
        return next;
    }

    void Work(size_t worker)
    {
        while (true) {
            std::pair<size_t, std::vector<uint8_t>> item;
            {
                std::unique_lock lock{m_mutex};
                m_not_empty.wait(lock, [&] { return m_done || !m_blocks.empty(); });
                if (m_blocks.empty()) return;
                item = std::move(m_blocks.front());
                m_blocks.pop_front();
            }
            m_results[worker].emplace_back(
                item.first,
                TaggedHashOf(LEAF_TAG_HASHER, std::span<const unsigned char>{item.second}));
        }
    }

    std::mutex m_mutex;
    std::condition_variable m_not_empty;
    std::deque<std::pair<size_t, std::vector<uint8_t>>> m_blocks;
    std::vector<std::vector<std::pair<size_t, uint256>>> m_results;
    std::vector<std::thread> m_threads;
    bool m_done{false};
};

/** Batches of bytes for the thread that keeps the stream hash, so the hash of
 * the elements is taken alongside the reading rather than after it. It has to be
 * one consumer in order: hash_serialized_3 is a stream hash and cannot be split
 * the way the muhash can. */
class StreamHashQueue
{
public:
    explicit StreamHashQueue(size_t capacity) : m_capacity{capacity} {}

    void Push(std::vector<uint8_t> batch)
    {
        std::unique_lock lock{m_mutex};
        m_not_full.wait(lock, [&] { return m_done || m_batches.size() < m_capacity; });
        if (m_done) return;
        m_batches.push_back(std::move(batch));
        lock.unlock();
        m_not_empty.notify_one();
    }

    bool Pop(std::vector<uint8_t>& batch)
    {
        std::unique_lock lock{m_mutex};
        m_not_empty.wait(lock, [&] { return m_done || !m_batches.empty(); });
        if (m_batches.empty()) return false;
        batch = std::move(m_batches.front());
        m_batches.pop_front();
        lock.unlock();
        m_not_full.notify_one();
        return true;
    }

    void Finish()
    {
        std::lock_guard lock{m_mutex};
        m_done = true;
        m_not_empty.notify_one();
        m_not_full.notify_one();
    }

private:
    const size_t m_capacity;
    std::mutex m_mutex;
    std::condition_variable m_not_empty;
    std::condition_variable m_not_full;
    std::deque<std::vector<uint8_t>> m_batches;
    bool m_done{false};
};

/** How much of the element stream to hand over at a time. */
static constexpr size_t STREAM_HASH_BATCH_BYTES{1 << 20};

static void StreamHashTask(StreamHashQueue& queue, uint256& out)
{
    // The hash object belongs to this thread, and the result is written into the
    // caller's value before the thread ends, so joining it is all the
    // synchronisation the reader needs.
    HashWriter hasher{};
    std::vector<uint8_t> batch;
    while (queue.Pop(batch)) {
        hasher.write(std::as_bytes(std::span{batch}));
    }
    out = hasher.GetHash();
}

/** A stream that hands reads on and keeps the bytes that passed through, so a
 * reader that parses values can still see the bytes the values came from. The
 * leaf hashes are over the file's own bytes, and this is them. */
class ReadRecorder
{
public:
    explicit ReadRecorder(AutoFile& file) : m_file{file} {}

    // A stream wrapper offers this as a member rather than taking the free
    // operator, so that everything a nested serialization reads comes back
    // through read() below and is kept.
    template <typename U>
    ReadRecorder& operator>>(U&& obj)
    {
        ::Unserialize(*this, obj);
        return *this;
    }

    void read(std::span<std::byte> dst)
    {
        m_file.read(dst);
        const size_t old{m_bytes.size()};
        m_bytes.resize(old + dst.size());
        std::memcpy(m_bytes.data() + old, dst.data(), dst.size());
    }

    void ignore(size_t n)
    {
        // Nothing on the reading side ignores, but a stream offers it, and an
        // ignored byte is still a byte of the file.
        std::vector<std::byte> scratch(n);
        read(scratch);
    }

    std::vector<uint8_t>& bytes() { return m_bytes; }

private:
    AutoFile& m_file;
    std::vector<uint8_t> m_bytes;
};

} // namespace

static const int CONTINUE_EXECUTION=-1;

const TranslateFn G_TRANSLATION_FUN{nullptr};

static void SetupBitcoinUtilArgs(ArgsManager &argsman)
{
    SetupHelpOptions(argsman);

    argsman.AddArg("-version", "Print version and exit", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);

    argsman.AddCommand("grind", "Perform proof of work on hex header string");
    argsman.AddCommand("getchainparams", "Get hardcoded parameters for the selected chain");
    // -muhash belongs to the command, not the tool: it names an option of
    // txoutsetsummary, so it appears and is documented with it.
    argsman.AddArg("-muhash", "Also compute the muhash, which costs a 3072 bit multiply per coin "
                              "rather than one hash (default: 1)",
                   ArgsManager::ALLOW_ANY, OptionsCategory::COMMAND_OPTIONS);
    argsman.AddCommand("txoutsetsummary", "Report what a UTXO set snapshot file holds, as JSON",
                       {"-muhash"});

    SetupChainParamsBaseOptions(argsman);
}

// This function returns either one of EXIT_ codes when it's expected to stop the process or
// CONTINUE_EXECUTION when it's expected to continue further.
static int AppInitUtil(ArgsManager& args, int argc, char* argv[])
{
    SetupBitcoinUtilArgs(args);
    std::string error;
    if (!args.ParseParameters(argc, argv, error)) {
        tfm::format(std::cerr, "Error parsing command line arguments: %s\n", error);
        return EXIT_FAILURE;
    }

    if (HelpRequested(args) || args.GetBoolArg("-version", false)) {
        // First part of help message is specific to this utility
        std::string strUsage = CLIENT_NAME " bitcoin-util utility version " + FormatFullVersion() + "\n";

        if (args.GetBoolArg("-version", false)) {
            strUsage += FormatParagraph(LicenseInfo());
        } else {
            strUsage += "\n"
                "The bitcoin-util tool provides bitcoin related functionality that does not rely on the ability to access a running node. Available [commands] are listed below.\n"
                "\n"
                "Usage:  bitcoin-util [options] [command]\n"
                "or:     bitcoin-util [options] grind <hex-block-header>\n";
            strUsage += "\n" + args.GetHelpMessage();
        }

        tfm::format(std::cout, "%s", strUsage);

        if (argc < 2) {
            tfm::format(std::cerr, "Error: too few parameters\n");
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }

    // Check for chain settings (Params() calls are only valid after this clause)
    try {
        SelectParams(args.GetChainType());
    } catch (const std::exception& e) {
        tfm::format(std::cerr, "Error: %s\n", e.what());
        return EXIT_FAILURE;
    }

    return CONTINUE_EXECUTION;
}

static void grind_task(uint32_t nBits, CBlockHeader header, uint32_t offset, uint32_t step, std::atomic<bool>& found, uint32_t& proposed_nonce)
{
    arith_uint256 target;
    bool neg, over;
    target.SetCompact(nBits, &neg, &over);
    if (target == 0 || neg || over) return;
    header.nNonce = offset;

    uint32_t finish = std::numeric_limits<uint32_t>::max() - step;
    finish = finish - (finish % step) + offset;

    while (!found && header.nNonce < finish) {
        const uint32_t next = (finish - header.nNonce < 5000*step) ? finish : header.nNonce + 5000*step;
        do {
            if (UintToArith256(header.GetHash()) <= target) {
                if (!found.exchange(true)) {
                    proposed_nonce = header.nNonce;
                }
                return;
            }
            header.nNonce += step;
        } while(header.nNonce != next);
    }
}

static int Grind(const std::vector<std::string>& args, std::string& strPrint)
{
    if (args.size() != 1) {
        strPrint = "Must specify block header to grind";
        return EXIT_FAILURE;
    }

    CBlockHeader header;
    if (!DecodeHexBlockHeader(header, args[0])) {
        strPrint = "Could not decode block header";
        return EXIT_FAILURE;
    }

    uint32_t nBits = header.nBits;
    std::atomic<bool> found{false};
    uint32_t proposed_nonce{};

    std::vector<std::thread> threads;
    int n_tasks = std::max(1u, std::thread::hardware_concurrency());
    threads.reserve(n_tasks);
    for (int i = 0; i < n_tasks; ++i) {
        threads.emplace_back(grind_task, nBits, header, i, n_tasks, std::ref(found), std::ref(proposed_nonce));
    }
    for (auto& t : threads) {
        t.join();
    }
    if (found) {
        header.nNonce = proposed_nonce;
    } else {
        strPrint = "Could not satisfy difficulty target";
        return EXIT_FAILURE;
    }

    DataStream ss{};
    ss << header;
    strPrint = HexStr(ss);
    return EXIT_SUCCESS;
}

static int GetChainParams(const std::vector<std::string>& args, std::string& strPrint)
{
    if (!args.empty()) {
        strPrint = "getchainparams does not take arguments";
        return EXIT_FAILURE;
    }

    const auto& params = Params();
    const auto& consensus = params.GetConsensus();

    UniValue result{UniValue::VOBJ};
    result.pushKV("chain", params.GetChainTypeString());
    result.pushKV("test_chain", params.IsTestChain());
    result.pushKV("genesis", HexStr(consensus.hashGenesisBlock));
    result.pushKV("subsidy_halving_interval", consensus.nSubsidyHalvingInterval);

    if (consensus.signet_blocks) {
        UniValue signet{UniValue::VOBJ};
        signet.pushKV("challenge", HexStr(consensus.signet_challenge));
        result.pushKV("signet", signet);
    }

    {
        UniValue pow{UniValue::VOBJ};
        pow.pushKV("limit", consensus.powLimit.ToString());
        if (!consensus.fPowNoRetargeting) {
            pow.pushKV("target_spacing", TicksSeconds(consensus.PowTargetSpacing()));
            pow.pushKV("difficulty_retarget_interval", consensus.DifficultyAdjustmentInterval());
            std::string mindiff_blocks = (consensus.fPowAllowMinDifficultyBlocks ?
                  (consensus.enforce_BIP94 ? "bip94" : "yes") : "no");
            pow.pushKV("mindiff_blocks", mindiff_blocks);
        }
        result.pushKV("pow", pow);
    }

    {
        UniValue net{UniValue::VOBJ};
        net.pushKV("default_port", params.GetDefaultPort());
        net.pushKV("magic", HexStr(params.MessageStart()));
        UniValue dns{UniValue::VARR};
        for (const auto& seed : params.DNSSeeds()) {
            dns.push_back(seed);
        }
        net.pushKV("dns_seeds", dns);
        result.pushKV("net", net);
    }

    {
        UniValue addr{UniValue::VOBJ};
        addr.pushKV("bech32_hrp", params.Bech32HRP());
        result.pushKV("addresses", addr);
    }

    strPrint = result.write(/*prettyIndent=*/2);
    return EXIT_SUCCESS;
}

/** Elements to put in one batch before handing it to a worker. */
static constexpr size_t MUHASH_BATCH_BYTES{1 << 20};

/** Elements to hash, serialized back to back, with one length per element. */
struct MuhashBatch {
    std::vector<unsigned char> bytes;
    std::vector<uint32_t> lengths;
};

/** A bounded queue of batches. The reader waits while it is full. */
class MuhashQueue
{
    const size_t m_max;
    std::mutex m_mutex;
    std::condition_variable m_not_full, m_not_empty;
    std::deque<MuhashBatch> m_batches;
    bool m_done{false};

public:
    explicit MuhashQueue(size_t max) : m_max{max} {}

    void Push(MuhashBatch&& batch)
    {
        std::unique_lock<std::mutex> lock{m_mutex};
        m_not_full.wait(lock, [&] { return m_batches.size() < m_max; });
        m_batches.push_back(std::move(batch));
        lock.unlock();
        m_not_empty.notify_one();
    }

    /** Take the next batch, or return false once there will be no more. */
    bool Pop(MuhashBatch& batch)
    {
        std::unique_lock<std::mutex> lock{m_mutex};
        m_not_empty.wait(lock, [&] { return !m_batches.empty() || m_done; });
        if (m_batches.empty()) return false;
        batch = std::move(m_batches.front());
        m_batches.pop_front();
        lock.unlock();
        m_not_full.notify_one();
        return true;
    }

    void Finish()
    {
        {
            std::lock_guard<std::mutex> lock{m_mutex};
            m_done = true;
        }
        m_not_empty.notify_all();
    }
};

/** Hash every element of every batch into one accumulator. */
static void muhash_task(MuhashQueue& queue, MuHash3072& accumulator)
{
    MuhashBatch batch;
    while (queue.Pop(batch)) {
        const auto elements{MakeUCharSpan(batch.bytes)};
        size_t offset{0};
        for (const uint32_t length : batch.lengths) {
            accumulator.Insert(elements.subspan(offset, length));
            offset += length;
        }
    }
}

/**
 * Compute the muhash of a serialized UTXO set snapshot, as written by the
 * dumptxoutset RPC, the same way the muhash reported by gettxoutsetinfo is
 * computed.
 *
 * The snapshot is read from the given file, or from stdin if no file is given
 * or the file is "-".
 *
 * One thread reads the file and hands batches of elements to a queue that a
 * thread per core pulls from, each with its own accumulator. MuHash is
 * multiplicative and associative, so multiplying the accumulators together and
 * finalizing once gives the same value whatever the threads were handed, and
 * the value therefore does not depend on the number of threads.
 *
 * The element hashed per coin is the one kernel/coinstats.cpp builds in
 * ApplyCoinHash: the outpoint, the packed height/coinbase code, and the
 * uncompressed txout. It is written out here rather than by calling that
 * function, which lives in libbitcoin_node; bitcoin-util does not link it.
 *
 * What is printed is a JSON object: the base block hash the snapshot's header
 * names, how many coins were read (counted, not taken from the header), the
 * total value of them, hash_serialized_3, and the muhash.
 *
 * The two hashes differ in a way worth knowing. hash_serialized_3 hashes a
 * stream, so it depends on the order the coins come in; a snapshot file holds
 * them in the coins database's own order, which is the order a node hashing its
 * own set uses, so the value is the one gettxoutsetinfo reports. The muhash is a
 * product and depends on no order at all, which is what makes it the commitment
 * for a snapshot that travels in pieces. It is also far more expensive, so it is
 * computed only when asked for: -muhash (default 1, -nomuhash to leave it out).
 */
static int TxoutSetSummary(const std::vector<std::string>& args, std::string& strPrint)
{
    if (args.size() > 1) {
        strPrint = "Must specify at most one UTXO set snapshot file";
        return EXIT_FAILURE;
    }

    const bool from_stdin{args.empty() || args[0] == "-"};
    // Wrapping stdin this way makes the destructor close it, which is harmless
    // for a command that exits immediately afterwards.
    AutoFile file{from_stdin ? stdin : fsbridge::fopen(fs::u8path(args[0]), "rb")};
    if (file.IsNull()) {
        strPrint = strprintf("Could not open %s", from_stdin ? "stdin" : args[0]);
        return EXIT_FAILURE;
    }

    // The header is read here rather than through node::SnapshotMetadata, which
    // validates the file's network against the selected chain. A node loading
    // untrusted metadata wants that check; a tool hashing a file does not, since
    // the muhash is over the coins and the chain cannot change it. The magic and
    // the version are still checked, because those say whether the file can be
    // read at all.
    uint64_t coins_count{0};
    uint256 base_blockhash;
    ReadRecorder in{file};
    try {
        std::array<uint8_t, SNAPSHOT_MAGIC_BYTES.size()> magic;
        in >> magic;
        if (magic != SNAPSHOT_MAGIC_BYTES) {
            throw std::ios_base::failure("Invalid UTXO set snapshot magic bytes.");
        }
        uint16_t version;
        in >> version;
        if (version != node::SnapshotMetadata::VERSION) {
            throw std::ios_base::failure(strprintf("Unsupported UTXO set snapshot version %u.",
                                                   version));
        }
        MessageStartChars network_magic;
        in >> network_magic;  // the file's own network, which is not this tool's business
        in >> base_blockhash;
        in >> coins_count;
    } catch (const std::ios_base::failure& e) {
        strPrint = strprintf("Could not read snapshot metadata: %s", e.what());
        return EXIT_FAILURE;
    }

    const bool want_muhash{gArgs.GetBoolArg("-muhash", true)};
    const size_t num_threads{std::max(1u, std::thread::hardware_concurrency())};
    MuhashQueue queue{num_threads};
    std::vector<MuHash3072> accumulators(num_threads);
    std::vector<std::thread> threads;
    if (want_muhash) {
        threads.reserve(num_threads);
        for (size_t i{0}; i < num_threads; ++i) {
            threads.emplace_back(muhash_task, std::ref(queue), std::ref(accumulators[i]));
        }
    }

    // The stream hash is taken in file order on this thread; the muhash can be
    // split across the workers, this cannot.
    LeafHashPool leaf_pool{num_threads};
    size_t leaf_index{0};
    StreamHashQueue hash_queue{32};
    uint256 hash_serialized_3;
    std::thread stream_hash_thread{StreamHashTask, std::ref(hash_queue),
                                   std::ref(hash_serialized_3)};
    std::vector<uint8_t> stream_batch;
    stream_batch.reserve(STREAM_HASH_BATCH_BYTES);
    std::optional<CAmount> total_amount{0};
    // The leaf hashes the root folds from. The reader sees values rather than
    // bytes, so the bytes of each coin are serialized again exactly as the file
    // had them and gathered up to the leaf size.


    static constexpr uint64_t PROGRESS_INTERVAL{10000000};
    uint64_t coins_left{coins_count};
    uint64_t coins_done{0};
    uint64_t coins_reported{0};
    std::string error;
    {
        MuhashBatch batch;
        // Reused for every coin: clear() keeps the buffer it has grown.
        DataStream element{};
        auto flush = [&]() {
            if (!want_muhash || batch.lengths.empty()) return;
            queue.Push(std::move(batch));
            batch = MuhashBatch{};
        };
        try {
            while (coins_left > 0) {
                Txid txid;
                in >> txid;

                const size_t coins_per_txid{ReadCompactSize(in)};
                if (coins_per_txid > coins_left) {
                    error = "Snapshot holds fewer coins than its metadata claims";
                    break;
                }

                for (size_t i{0}; i < coins_per_txid; ++i) {
                    COutPoint outpoint;
                    outpoint.n = static_cast<uint32_t>(ReadCompactSize(in));
                    outpoint.hash = txid;
                    Coin coin;
                    in >> coin;

                    const uint32_t code{(uint32_t{coin.nHeight} << 1) | uint32_t{coin.fCoinBase}};
                    element.clear();
                    element << outpoint << code << coin.out;
                    while (in.bytes().size() >= SNAPSHOT_LEAF_SIZE) {
                        std::vector<uint8_t> block{in.bytes().begin(),
                                                   in.bytes().begin() + SNAPSHOT_LEAF_SIZE};
                        in.bytes().erase(in.bytes().begin(),
                                         in.bytes().begin() + SNAPSHOT_LEAF_SIZE);
                        leaf_pool.Push(leaf_index++, std::move(block));
                    }

                    const auto data{MakeUCharSpan(element)};
                    // Handed to the stream hash thread rather than hashed here.
                    stream_batch.insert(stream_batch.end(), data.begin(), data.end());
                    if (stream_batch.size() >= STREAM_HASH_BATCH_BYTES) {
                        hash_queue.Push(std::move(stream_batch));
                        stream_batch = std::vector<uint8_t>{};
                        stream_batch.reserve(STREAM_HASH_BATCH_BYTES);
                    }
                    total_amount = CheckedAdd(*total_amount, coin.out.nValue);
                    if (!total_amount) {
                        error = "The total value of the coins overflows";
                        break;
                    }
                    if (want_muhash) {
                        batch.bytes.insert(batch.bytes.end(), data.begin(), data.end());
                        batch.lengths.push_back(data.size());
                        if (batch.bytes.size() >= MUHASH_BATCH_BYTES) flush();
                    }
                }

                coins_left -= coins_per_txid;
                coins_done += coins_per_txid;
                if (coins_done - coins_reported >= PROGRESS_INTERVAL) {
                    coins_reported = coins_done;
                    tfm::format(std::cerr, "read %.1fM of %.1fM coins\n",
                                coins_done / 1000000.0, coins_count / 1000000.0);
                }
            }
        } catch (const std::ios_base::failure& e) {
            error = strprintf("Could not read snapshot data after %d of %d coins: %s",
                              coins_done, coins_count, e.what());
        }
        flush();
    }
    queue.Finish();
    for (auto& thread : threads) {
        thread.join();
    }
    if (!stream_batch.empty()) hash_queue.Push(std::move(stream_batch));
    hash_queue.Finish();
    stream_hash_thread.join();
    if (!error.empty()) {
        strPrint = error;
        return EXIT_FAILURE;
    }

    // The last leaf of a snapshot is short unless its length divides by the leaf
    // size, and it is a leaf like any other.
    if (!in.bytes().empty()) {
        leaf_pool.Push(leaf_index++, std::vector<uint8_t>{in.bytes().begin(), in.bytes().end()});
    }

    UniValue summary{UniValue::VOBJ};
    summary.pushKV("bestblock", base_blockhash.GetHex());
    summary.pushKV("txouts", static_cast<int64_t>(coins_done));
    // ValueFromAmount, the same helper gettxoutsetinfo uses: a JSON number whose
    // text is the exact eight decimals, so it prints as 5050.00000000 and not as
    // a double's approximation of it.
    summary.pushKV("total_amount", ValueFromAmount(*total_amount));
    summary.pushKV("hash_serialized_3", hash_serialized_3.GetHex());
    summary.pushKV("merkle_root", leaf_pool.Root().GetHex());
    if (want_muhash) {
        MuHash3072 muhash;
        for (const auto& accumulator : accumulators) {
            muhash *= accumulator;
        }
        uint256 muhash_result;
        muhash.Finalize(muhash_result);
        summary.pushKV("muhash", muhash_result.GetHex());
    }
    strPrint = summary.write(2);
    return EXIT_SUCCESS;
}

MAIN_FUNCTION
{
    ArgsManager& args = gArgs;
    SetupEnvironment();

    try {
        int ret = AppInitUtil(args, argc, argv);
        if (ret != CONTINUE_EXECUTION) {
            return ret;
        }
    } catch (const std::exception& e) {
        PrintExceptionContinue(&e, "AppInitUtil()");
        return EXIT_FAILURE;
    } catch (...) {
        PrintExceptionContinue(nullptr, "AppInitUtil()");
        return EXIT_FAILURE;
    }

    const auto cmd = args.GetCommand();
    if (!cmd) {
        tfm::format(std::cerr, "Error: must specify a command\n");
        return EXIT_FAILURE;
    }

    int ret = EXIT_FAILURE;
    std::string strPrint;
    try {
        if (cmd->command == "grind") {
            ret = Grind(cmd->args, strPrint);
        } else if (cmd->command == "getchainparams") {
            ret = GetChainParams(cmd->args, strPrint);
        } else if (cmd->command == "txoutsetsummary") {
            ret = TxoutSetSummary(cmd->args, strPrint);
        } else {
            assert(false); // unknown command should be caught earlier
        }
    } catch (const std::exception& e) {
        strPrint = std::string("error: ") + e.what();
    } catch (...) {
        strPrint = "unknown error";
    }

    if (strPrint != "") {
        tfm::format(ret == 0 ? std::cout : std::cerr, "%s\n", strPrint);
    }

    return ret;
}
