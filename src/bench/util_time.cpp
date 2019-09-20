// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>

#include <util/time.h>

static void BenchTimeDeprecated(benchmark::State& state)
{
    while (state.KeepRunning()) {
        (void)GetTime();
    }
}

static void BenchTimeMock(benchmark::State& state)
{
    SetMockTime(111);
    while (state.KeepRunning()) {
        (void)mockable_clock::now();
    }
    SetMockTime(0);
}

static void BenchTimeMicros(benchmark::State& state)
{
    while (state.KeepRunning()) {
        (void)mockable_clock::now();
    }
}

static void BenchSysTimeMillis(benchmark::State& state)
{
    while (state.KeepRunning()) {
        (void)GetSysTimeMillis();
    }
}

BENCHMARK(BenchTimeDeprecated, 100000000);
BENCHMARK(BenchTimeMicros, 6000000);
BENCHMARK(BenchSysTimeMillis, 6000000);
BENCHMARK(BenchTimeMock, 300000000);
