// Package perf is the measurement harness for private capacity work
// (Step 21). It computes exact percentiles (sorted selection, reported
// only when the sample count supports them), snapshots process
// resources, and drives deterministic synthetic workloads. It asserts
// nothing about speed: benchmark data belongs here, correctness
// assertions belong in the domain suites. No production code depends
// on this package.
package perf

import (
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// percentile returns the exact p-th percentile by sorted selection
// (nearest-rank). Callers must check support via percentileOf.
func percentile(sorted []time.Duration, p int) time.Duration {
	s := append([]time.Duration(nil), sorted...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	rank := (p*len(s) + 99) / 100
	if rank < 1 {
		rank = 1
	}
	if rank > len(s) {
		rank = len(s)
	}
	return s[rank-1]
}

// percentileOf reports the percentile only when supported: p50 needs
// >=10 samples, p95 >=50, p99 >=100. Anything else returns ok=false so
// callers cannot fabricate precision they do not have.
func percentileOf(samples []time.Duration, p int) (time.Duration, bool) {
	need := 10
	switch {
	case p >= 99:
		need = 100
	case p >= 95:
		need = 50
	}
	if len(samples) < need {
		return 0, false
	}
	return percentile(samples, p), true
}

// Resources is one process resource snapshot.
type Resources struct {
	RSSBytes   int64
	Goroutines int
	FDCount    int
}

func snapshotResources() Resources {
	var r Resources
	if raw, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, "VmRSS:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if kb, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
						r.RSSBytes = kb * 1024
					}
				}
			}
		}
	}
	r.Goroutines = runtime.NumGoroutine()
	if entries, err := os.ReadDir("/proc/self/fd"); err == nil {
		r.FDCount = len(entries)
	} else {
		r.FDCount = -1
	}
	return r
}

// Summary aggregates one workload run for reporting.
type Summary struct {
	Name        string
	Ops         int
	Concurrency int
	Elapsed     time.Duration
	Errors      int
	Min, P50    time.Duration
	P95, P99    time.Duration
	P95ok       bool
	P99ok       bool
	Max         time.Duration
}

// Summarize builds the report: min/max always, p50 at n>=10, p95 at
// n>=50, p99 at n>=100. Throughput is derived, never asserted.
func Summarize(name string, latencies []time.Duration, concurrency int, elapsed time.Duration, errors int) Summary {
	s := Summary{Name: name, Ops: len(latencies), Concurrency: concurrency, Elapsed: elapsed, Errors: errors}
	if len(latencies) == 0 {
		return s
	}
	sorted := append([]time.Duration(nil), latencies...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	s.Min = sorted[0]
	s.Max = sorted[len(sorted)-1]
	if v, ok := percentileOf(latencies, 50); ok {
		s.P50 = v
	}
	if v, ok := percentileOf(latencies, 95); ok {
		s.P95, s.P95ok = v, true
	}
	if v, ok := percentileOf(latencies, 99); ok {
		s.P99, s.P99ok = v, true
	}
	return s
}
