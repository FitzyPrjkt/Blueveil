// RED: COMMUNICATES_WITH joins CONTAINS as a known relationship kind.
package asset

import (
	"testing"
	"time"
)

func TestCommunicatesWithValidates(t *testing.T) {
	r := Relationship{
		ParentID: "ast-aaaaaaaaaaaaaaaa", ChildID: "ast-bbbbbbbbbbbbbbbb",
		Kind:   RelationCommunicatesWith,
		Source: "lab-sensor", ObservedAt: time.Now().UTC(),
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("COMMUNICATES_WITH must validate: %v", err)
	}
	// CONTAINS still validates.
	r.Kind = RelationContains
	if err := r.Validate(); err != nil {
		t.Fatalf("CONTAINS must still validate: %v", err)
	}
	// Unknown kinds still rejected; self-links still refused in both kinds.
	r.Kind = "RESOLVES_TO"
	if err := r.Validate(); err == nil {
		t.Fatalf("unknown kind must be rejected")
	}
	r.Kind = RelationCommunicatesWith
	r.ChildID = r.ParentID
	if err := r.Validate(); err == nil {
		t.Fatalf("self-link must be refused")
	}
}
