// Step 14D: concurrency and idempotency over the memory backend.
// Duplicate insertion is deterministic (exactly one winner, the rest
// ErrDuplicate); concurrent readers never observe torn state; final
// counts are exact (no silent loss). Run with -race.
package store

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
	"blueveil/collector/internal/supplychain"
)

func TestConcurrentDuplicateComponentInsert(t *testing.T) {
	be := NewMemoryBackend()
	ctx := context.Background()
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	c := supplychain.Component{
		Type: supplychain.ComponentLibrary, Ecosystem: "npm", Name: "race-lib",
		Version: "1.0.0", Provenance: supplychain.ProvenanceLockfile,
		Source: "race-test", ObservedAt: now, Status: supplychain.StatusObserved,
	}
	const n = 16
	var won atomic.Int32
	var dups atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch err := be.Components.Create(ctx, c); {
			case err == nil:
				won.Add(1)
			case errors.Is(err, ErrDuplicate):
				dups.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if won.Load() != 1 || dups.Load() != n-1 {
		t.Fatalf("want exactly 1 winner and %d duplicates, got %d/%d", n-1, won.Load(), dups.Load())
	}
	list, err := be.Components.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("final list must hold exactly one: %+v %v", list, err)
	}
}

func TestConcurrentTelemetryReadWrite(t *testing.T) {
	be := NewMemoryBackend()
	ctx := context.Background()
	base := time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)
	const writers = 4
	const perWriter = 25
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				id := fmt.Sprintf("evt-race-%d-%d", w, i)
				_ = be.Telemetry.Append(ctx, &v1.TelemetryEvent{
					Id: id, OccurredAt: timestamppb.New(base),
					Source: "race", AssetId: "ast-race",
					EventType: "net.connection", Severity: v1.Severity_SEVERITY_INFO,
					Attributes: map[string]string{
						"net.src_ip": "10.0.0.9", "net.dst_ip": "10.0.0.1",
						"net.dst_port": "80", "net.protocol": "TCP", "net.verdict": "allowed",
					},
				})
			}
		}(w)
	}
	// Concurrent readers must never fail or observe partial writes.
	for r := 0; r < 2; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if _, err := be.Telemetry.List(ctx); err != nil {
					t.Errorf("concurrent list: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	list, err := be.Telemetry.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != writers*perWriter {
		t.Fatalf("want %d events, got %d (silent loss)", writers*perWriter, len(list))
	}
	seen := map[string]bool{}
	for _, e := range list {
		if seen[e.GetId()] {
			t.Fatalf("duplicate id %q in list", e.GetId())
		}
		seen[e.GetId()] = true
	}
}

func TestConcurrentDuplicateTelemetryAppend(t *testing.T) {
	be := NewMemoryBackend()
	ctx := context.Background()
	base := time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)
	evt := &v1.TelemetryEvent{
		Id: "evt-race-dup", OccurredAt: timestamppb.New(base),
		Source: "race", AssetId: "ast-race",
		EventType: "net.connection", Severity: v1.Severity_SEVERITY_INFO,
		Attributes: map[string]string{
			"net.src_ip": "10.0.0.9", "net.dst_ip": "10.0.0.1",
			"net.dst_port": "80", "net.protocol": "TCP", "net.verdict": "allowed",
		},
	}
	const n = 8
	var won atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := be.Telemetry.Append(ctx, evt); err == nil {
				won.Add(1)
			} else if !errors.Is(err, ErrDuplicate) {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatalf("want exactly 1 append winner, got %d", won.Load())
	}
}
