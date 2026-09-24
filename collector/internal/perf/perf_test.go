// Step 21A RED: measurement harness correctness. Percentiles are exact
// (sorted selection, no interpolation invention) and only reported when
// the sample count supports them; resource snapshots are sanity-checked.
package perf

import (
	"testing"
	"time"
)

func TestPercentilesExact(t *testing.T) {
	d := func(ms ...int) []time.Duration {
		out := make([]time.Duration, len(ms))
		for i, v := range ms {
			out[i] = time.Duration(v) * time.Millisecond
		}
		return out
	}
	mk := func(n int) []time.Duration {
		out := make([]time.Duration, n)
		for i := range out {
			out[i] = time.Duration(i+1) * time.Millisecond
		}
		return out
	}
	if got := percentile(d(10, 20, 30), 50); got != 20*time.Millisecond {
		t.Fatalf("p50: %v", got)
	}
	if got := percentile(mk(100), 50); got != 50*time.Millisecond {
		t.Fatalf("p50 of 1..100: %v", got)
	}
	if got := percentile(mk(100), 95); got != 95*time.Millisecond {
		t.Fatalf("p95 of 1..100: %v", got)
	}
	if got := percentile(mk(100), 99); got != 99*time.Millisecond {
		t.Fatalf("p99 of 1..100: %v", got)
	}
	if percentile(mk(100), 99) == 0 {
		t.Fatalf("p99 must be measurable at n=100")
	}
	if _, ok := percentileOf(nil, 50); ok {
		t.Fatalf("empty samples must report unsupported")
	}
	if _, ok := percentileOf(mk(10), 99); ok {
		t.Fatalf("p99 at n=10 must report unsupported (needs >=100)")
	}
	if _, ok := percentileOf(mk(50), 95); !ok {
		t.Fatalf("p95 at n=50 must be supported")
	}
}

func TestResourceSnapshotSane(t *testing.T) {
	r := snapshotResources()
	if r.RSSBytes <= 0 {
		t.Fatalf("RSS must be positive: %+v", r)
	}
	if r.Goroutines <= 0 {
		t.Fatalf("goroutines must be positive: %+v", r)
	}
	if r.FDCount < 0 {
		t.Fatalf("fds must be non-negative: %+v", r)
	}
}
