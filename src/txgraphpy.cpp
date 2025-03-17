#include <txgraph.h>
#include <util/translation.h>
#include <tinyformat.h>

#include <cstdint>
#include <atomic>

#include <boost/python.hpp>

/**
 Example usage:

>>> import libtxgraph_ext
>>> tx = libtxgraph_ext.TxGraph()
>>> r3 = libtxgraph_ext.Ref(tx, 100, 20)
>>> r4 = libtxgraph_ext.Ref(tx, 100, 30)
>>> r5 = libtxgraph_ext.Ref(tx, 500, 10)
>>> tx.AddDependency(r4, r5)
>>> tx.AddDependency(r3, r4)
>>> tx.GetMainChunkFeerate(r4)
Fee(700/60)
>>> tx.GetMainChunkFeerate(r4).rate()
11.666666666666666
>>> tx.GetIndividualFeerate(r3)
Fee(100/20)
>>> tx.GetIndividualFeerate(r3).rate()
5.0
>>> tx.GetIndividualFeerate(r4).rate()
3.3333333333333335
>>> tx.GetIndividualFeerate(r5).rate()
50.0

 */

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {

struct TxGraphPy;

struct RefPy : public TxGraph::Ref
{
    static std::atomic<int64_t> counter;
    static int64_t get_next() { return ++counter; }

    const int64_t m_id{0};

    RefPy(TxGraphPy& txgraph, int64_t fee, int32_t size);

    RefPy(TxGraph::Ref&& other) : TxGraph::Ref{std::move(other)}, m_id{get_next()} { }

    RefPy(RefPy&& other) = default;

    std::string repr() const { return strprintf("Ref<%s>", m_id); }
};

std::atomic<int64_t> RefPy::counter{0};

struct TxGraphPy {
    std::unique_ptr<TxGraph> m_txgraph;

    TxGraphPy(unsigned max_cluster_count = MAX_CLUSTER_COUNT_LIMIT)
      : m_txgraph{MakeTxGraph(max_cluster_count)}
    { }

    [[nodiscard]] RefPy AddTransaction(int64_t fee, int32_t size) {
        return m_txgraph->AddTransaction(FeePerWeight{fee, size});
    }

    void RemoveTransaction(const RefPy& arg) {
        return m_txgraph->RemoveTransaction(arg);
    }

    void AddDependency(const RefPy& parent, const RefPy& child) {
        return m_txgraph->AddDependency(parent, child);
    }

    void SetTransactionFee(const RefPy& arg, int64_t fee) {
        return m_txgraph->SetTransactionFee(arg, fee);
    }

    void DoWork() { return m_txgraph->DoWork(); }

    void StartStaging() { return m_txgraph->StartStaging(); }
    void AbortStaging() { return m_txgraph->AbortStaging(); }
    void CommitStaging() { return m_txgraph->CommitStaging(); }
    bool HaveStaging() const { return m_txgraph->HaveStaging(); }

    bool Exists(const RefPy& arg, bool main_only = false) { return m_txgraph->Exists(arg, main_only); }

    bool IsOversized(bool main_only = false) { return m_txgraph->IsOversized(main_only); }

    FeePerWeight GetMainChunkFeerate(const RefPy& arg) { return m_txgraph->GetMainChunkFeerate(arg); }
    FeePerWeight GetIndividualFeerate(const RefPy& arg) { return m_txgraph->GetIndividualFeerate(arg); }

#if 0
    std::vector<Ref*> GetAncestors(const Ref& arg, bool main_only = false) noexcept = 0;
    std::vector<Ref*> GetAncestorsUnion(std::span<const Ref* const> args, bool main_only = false) noexcept = 0;
    std::vector<Ref*> GetDescendants(const Ref& arg, bool main_only = false) noexcept = 0;
    std::vector<Ref*> GetDescendantsUnion(std::span<const Ref* const> args, bool main_only = false) noexcept = 0;
    GraphIndex GetTransactionCount(bool main_only = false) noexcept = 0;
    std::strong_ordering CompareMainOrder(const Ref& a, const Ref& b) noexcept = 0;
    GraphIndex CountDistinctClusters(std::span<const Ref* const>, bool main_only = false) noexcept = 0;
#endif

};

BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(Exists_overloads, Exists, 1, 2)
BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(IsOversized_overloads, IsOversized, 0, 1)

RefPy::RefPy(TxGraphPy& txgraph, int64_t fee, int32_t size)
  : TxGraph::Ref{txgraph.m_txgraph->AddTransaction(FeePerWeight{fee, size})},
    m_id{get_next()}
  { }

std::string FeePerWeightRepr(const FeePerWeight& fpw)
{
    if (fpw.size == 0) { return "Fee(0)"; }
    return strprintf("Fee(%s/%s)", fpw.fee, fpw.size);
}

double FeePerWeightRate(const FeePerWeight& fpw)
{
    if (fpw.size == 0) { return 0; }
    return (double)fpw.fee/(double)fpw.size;
}

} // namespace

using namespace boost::python;

BOOST_PYTHON_MODULE(libtxgraph_ext)
{
    class_<FeePerWeight>("FeePerWeight", init<int64_t, int32_t>())
        .def("__repr__", FeePerWeightRepr)
        .def("rate", FeePerWeightRate)
        ;

    class_<TxGraphPy, boost::noncopyable>("TxGraph")
        .def("AddTransaction", &TxGraphPy::AddTransaction)
        .def("RemoveTransaction", &TxGraphPy::RemoveTransaction)
        .def("AddDependency", &TxGraphPy::AddDependency)
        .def("SetTransactionFee", &TxGraphPy::SetTransactionFee)
        .def("DoWork", &TxGraphPy::DoWork)
        .def("StartStaging", &TxGraphPy::StartStaging)
        .def("AbortStaging", &TxGraphPy::AbortStaging)
        .def("CommitStaging", &TxGraphPy::CommitStaging)
        .def("HaveStaging", &TxGraphPy::HaveStaging)
        .def("Exists", &TxGraphPy::Exists, Exists_overloads())
        .def("IsOversized", &TxGraphPy::IsOversized, IsOversized_overloads())
        .def("GetMainChunkFeerate", &TxGraphPy::GetMainChunkFeerate)
        .def("GetIndividualFeerate", &TxGraphPy::GetIndividualFeerate)
        ;

    class_<RefPy, boost::noncopyable>("Ref", init<TxGraphPy&, int64_t, int32_t>())
        .def_readonly("id", &RefPy::m_id)
        .def("__repr__", &RefPy::repr)
        ;

}
