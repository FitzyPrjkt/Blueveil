// Step 14D: SQLite concurrency. Concurrent unique appends all land;
// concurrent duplicate appends have exactly one winner; readers never
// fail. Run with -race. (Busy timeout is configured in Open; lock
// contention surfaces as slowness, not errors.)
package sqlite

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/store"
)

func raceEvent(id string, base time.Time) *v1.TelemetryEvent {
	return &v1.TelemetryEvent{
		Id: id, OccurredAt: timestamppb.New(base),
		Source: "race", AssetId: "ast-race",
		EventType: "net.connection", Severity: v1.Severity_SEVERITY_INFO,
		Attributes: map[string]string{
			"net.src_ip": "10.0.0.9", "net.dst_ip": "10.0.0.1",
			"net.dst_port": "80", "net.protocol": "TCP", "net.verdict": "allowed",
		},
	}
}

func TestConcurrentAppendTelemetry(t *testing.T) {
	ctx := context.Background()
	db := openMemory(t)
	be := db.Backend()
	base := time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)
	const writers = 4
	const perWriter = 10
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				if err := be.Telemetry.Append(ctx, raceEvent(fmt.Sprintf("evt-srace-%d-%d", w, i), base)); err != nil {
					t.Errorf("append: %v", err)
					return
				}
			}
		}(w)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 30; i++ {
			if _, err := be.Telemetry.List(ctx); err != nil {
				t.Errorf("concurrent list: %v", err)
				return
			}
		}
	}()
	wg.Wait()
	list, err := be.Telemetry.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != writers*perWriter {
		t.Fatalf("want %d events, got %d", writers*perWriter, len(list))
	}
}

func TestConcurrentDuplicateAppendTelemetry(t *testing.T) {
	ctx := context.Background()
	db := openMemory(t)
	be := db.Backend()
	base := time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)
	const n = 8
	var won atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch err := be.Telemetry.Append(ctx, raceEvent("evt-srace-dup", base)); {
			case err == nil:
				won.Add(1)
			case errors.Is(err, store.ErrDuplicate):
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatalf("want exactly 1 winner, got %d", won.Load())
	}
}
