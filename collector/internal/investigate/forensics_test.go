// RED: metadata-level forensic artifacts — classification, provenance,
// redaction. No acquisition, no certainty claims.
package investigate

import (
	"testing"
)

func TestClassifyArtifacts(t *testing.T) {
	cases := map[string]ArtifactType{
		"endpoint.activity":   ArtifactProcess,
		"server.activity":     ArtifactService,
		"net.connection":      ArtifactNetwork,
		"http.request":        ArtifactNetwork,
		"auth.activity":       ArtifactAuthentication,
		"identity.activity":   ArtifactIdentity,
		"container.activity":  ArtifactContainer,
		"cloud.activity":      ArtifactCloud,
		"waf.request_blocked": ArtifactNetwork,
		"unknown.type":        ArtifactUnknown,
	}
	for typ, want := range cases {
		e := mkEvt("x", typ, "s", "a", 0, map[string]string{})
		a, err := ArtifactFor(e)
		if err != nil {
			t.Errorf("%s: %v", typ, err)
			continue
		}
		if a.Type != want {
			t.Errorf("%s: want %s, got %s", typ, want, a.Type)
		}
		if a.EventID != "x" || a.AssetID != "a" || a.Source != "s" {
			t.Errorf("%s: provenance missing: %+v", typ, a)
		}
		if a.ObservedAt.IsZero() {
			t.Errorf("%s: timestamp missing", typ)
		}
	}
	// file_modify classifies as file activity, not generic process.
	e := mkEvt("f1", "endpoint.activity", "s", "a", 0, map[string]string{
		"endpoint.host": "web01", "endpoint.process": "agent",
		"endpoint.action": "file_modify", "endpoint.file_path": "/etc/app.conf",
	})
	a, err := ArtifactFor(e)
	if err != nil {
		t.Fatal(err)
	}
	if a.Type != ArtifactFileActivity {
		t.Fatalf("file_modify must classify FILE_ACTIVITY, got %s", a.Type)
	}
	if a.Metadata["endpoint.file_path"] != "/etc/app.conf" {
		t.Fatalf("file metadata missing: %+v", a.Metadata)
	}
}

func TestArtifactRedaction(t *testing.T) {
	e := mkEvt("s1", "auth.activity", "s", "a", 0, map[string]string{
		"auth.principal": "erin", "auth.outcome": "failure",
		"auth.password": "hunter2",
	})
	a, err := ArtifactFor(e)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range a.Metadata {
		if k == "auth.password" || v == "hunter2" {
			t.Fatalf("secret leaked into artifact: %+v", a.Metadata)
		}
	}
}

func TestArtifactCorruptFailsClosed(t *testing.T) {
	e := mkEvt("s1", "auth.activity", "s", "a", 0, map[string]string{})
	e.OccurredAt = nil
	if _, err := ArtifactFor(e); err == nil {
		t.Errorf("corrupt event must fail closed")
	}
}

func TestArtifactTypeStrings(t *testing.T) {
	// Classification vocabulary is explicit and bounded.
	for _, at := range []ArtifactType{
		ArtifactProcess, ArtifactFileActivity, ArtifactService, ArtifactNetwork,
		ArtifactAuthentication, ArtifactIdentity, ArtifactContainer, ArtifactCloud,
		ArtifactUnknown,
	} {
		if string(at) == "" {
			t.Errorf("empty artifact type string")
		}
	}
}
