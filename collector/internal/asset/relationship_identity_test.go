// RED: identity relationship kinds validate; unknown kinds still rejected.
package asset

import (
	"testing"
	"time"
)

func TestIdentityRelationshipKinds(t *testing.T) {
	for _, kind := range []string{RelationAccesses, RelationMemberOf, RelationAssumes, RelationAuthenticatesTo} {
		r := Relationship{
			ParentID: "ast-aaaaaaaaaaaaaaaa", ChildID: "ast-bbbbbbbbbbbbbbbb",
			Kind: kind, Source: "lab", ObservedAt: time.Now().UTC(),
		}
		if err := r.Validate(); err != nil {
			t.Errorf("kind %s must validate: %v", kind, err)
		}
	}
	bad := Relationship{
		ParentID: "ast-aaaaaaaaaaaaaaaa", ChildID: "ast-bbbbbbbbbbbbbbbb",
		Kind: "OWNS", Source: "lab", ObservedAt: time.Now().UTC(),
	}
	if err := bad.Validate(); err == nil {
		t.Errorf("unknown kind OWNS must be rejected")
	}
}
