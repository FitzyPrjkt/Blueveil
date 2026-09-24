// Step 14D: simultaneous lifecycle transitions. Two racers moving one
// incident along different edges: exactly one legal move lands, the other
// gets an explicit transition error, and the incident is never torn.
package incident

import (
	"sync"
	"sync/atomic"
	"testing"

	v1 "blueveil/collector/internal/contract/v1"
)

func TestSimultaneousTransitions(t *testing.T) {
	mgr, err := NewManager(testClock)
	if err != nil {
		t.Fatal(err)
	}
	events := []*v1.TelemetryEvent{testEvent("e-race", "corr-race")}
	det := testDetection("d-race", "e-race")
	alert := testAlert("a-race", "d-race", v1.Severity_SEVERITY_HIGH)
	inc, created, err := mgr.Ingest(alert, det, events)
	if err != nil || !created {
		t.Fatalf("ingest: %v", err)
	}
	// Rename to the fixed race id via re-ingest is unnecessary: use the
	// real id for transitions.
	raceID := inc.GetId()
	if inc.GetStatus() != v1.IncidentStatus_INCIDENT_STATUS_OPEN {
		t.Fatalf("precondition: want OPEN, got %v", inc.GetStatus())
	}
	var okInvest, okClosed, errs atomic.Int32
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		// Legal: OPEN → INVESTIGATING.
		if _, err := mgr.Transition(raceID, v1.IncidentStatus_INCIDENT_STATUS_INVESTIGATING); err != nil {
			errs.Add(1)
		} else {
			okInvest.Add(1)
		}
	}()
	go func() {
		defer wg.Done()
		// Illegal skip: OPEN → CLOSED must always fail.
		if _, err := mgr.Transition(raceID, v1.IncidentStatus_INCIDENT_STATUS_CLOSED); err != nil {
			errs.Add(1)
		} else {
			okClosed.Add(1)
		}
	}()
	wg.Wait()
	if okClosed.Load() != 0 {
		t.Fatalf("lifecycle skip must never succeed")
	}
	if okInvest.Load() != 1 || errs.Load() != 1 {
		t.Fatalf("want 1 legal move + 1 explicit error, got ok=%d errs=%d", okInvest.Load(), errs.Load())
	}
	got, ok := mgr.Get(raceID)
	if !ok || got.GetStatus() != v1.IncidentStatus_INCIDENT_STATUS_INVESTIGATING {
		t.Fatalf("final state must be INVESTIGATING: %+v", got)
	}
}
