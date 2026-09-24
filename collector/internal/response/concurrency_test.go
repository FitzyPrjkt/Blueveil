// Step 14D: simultaneous audit writes land exactly once each with
// unique sequential ids; concurrent readers never fail. Run with -race.
package response

import (
	"fmt"
	"sync"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "blueveil/collector/internal/contract/v1"
)

func TestConcurrentAuditAppends(t *testing.T) {
	var log InMemoryAuditLog
	const n = 32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			log.Append(AuditEntry{
				DecidedAt: timestamppb.Now(), Actor: "race",
				Operation: v1.OperationType_OPERATION_TYPE_OBSERVE,
				Risk:      v1.RiskLevel_RISK_LEVEL_LOW,
				Decision:  AuditRecommended, Reason: "race",
				Result: fmt.Sprintf("rec-%d", i), ResponseID: fmt.Sprintf("rec-%d", i),
				Phase: StateRecommend.String(),
			})
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			_ = log.Entries()
		}
	}()
	wg.Wait()
	entries := log.Entries()
	if len(entries) != n {
		t.Fatalf("want %d entries, got %d", n, len(entries))
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if e.ID == "" || seen[e.ID] {
			t.Fatalf("duplicate or empty audit id %q", e.ID)
		}
		seen[e.ID] = true
	}
}
