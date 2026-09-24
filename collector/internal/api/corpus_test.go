// Step 20D: deterministic bounded adversarial corpus over the HTTP
// boundary. No randomness, no external fuzz infrastructure: every case
// asserts a bounded code (400/404/405/413/500-envelope) and a valid
// error envelope — never a panic, never an empty 200, never a trace.
package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"blueveil/collector/internal/store"
)

func corpusServer(t *testing.T) *Server {
	t.Helper()
	return NewServer(store.NewMemoryBackend())
}

func corpusDo(srv *Server, method, path, body string) (int, string) {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// corpusDoRaw bypasses httptest's URL parsing so control characters and
// other transport-level hostile bytes actually reach the handlers (a real
// server parses raw bytes off the wire; the test harness must too).
func corpusDoRaw(srv *Server, method, rawPath, rawQuery, body string) (int, string) {
	u := &url.URL{Path: rawPath, RawQuery: rawQuery}
	req := &http.Request{
		Method: method, URL: u, Host: "example.com",
		Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)),
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestCorpusQueryParams(t *testing.T) {
	srv := corpusServer(t)
	cases := []string{
		"/api/v1/validation/history?limit=9999999999999999999", // overflow
		"/api/v1/validation/history?limit=-0",
		"/api/v1/validation/history?limit=𝟙𝟚𝟛", // unicode digits
		"/api/v1/validation/history?limit=1.5",
		"/api/v1/assets?status=" + strings.Repeat("A", 100000),
		"/api/v1/monitoring/events?order=" + strings.Repeat("x", 10000),
		"/api/v1/continuous-security/checks?vendor_window=99999999999999999999h",
		"/api/v1/continuous-security/checks?vendor_window=-1h",
		"/api/v1/continuous-security/checks?check=" + strings.Repeat("s", 50000),
	}
	// Well-formed but unknown filter values are NOT errors: an empty
	// list is the honest answer (distinguished from corruption/absence).
	for _, p := range []string{
		"/api/v1/supply-chain/components?ecosystem=" + strings.Repeat("é", 5000),
		"/api/v1/assets?type=ASSET_TYPE_HOST&status=ASSET_STATUS_ACTIVE",
	} {
		code, _ := corpusDo(srv, http.MethodGet, p, "")
		if code != 200 {
			t.Errorf("GET %.60s: want 200-empty, got %d", p, code)
		}
	}
	for _, p := range cases {
		code, body := corpusDo(srv, http.MethodGet, p, "")
		if code != 400 && code != 404 {
			t.Errorf("GET %.60s: want 400/404, got %d (%s)", p, code, truncate(body, 80))
		}
		assertEnvelope(t, body)
	}
	// Transport-level hostile bytes (httptest cannot even parse these
	// into a request — a real server receives them raw).
	rawCases := []struct{ path, query string }{
		{"/api/v1/assets", "type=" + strings.Repeat("\x00", 100)},
		{"/api/v1/grc/controls", "domain=identity\x00"},
		{"/api/v1/assets", "status=" + strings.Repeat("\x7f", 1000)},
	}
	for _, c := range rawCases {
		code, body := corpusDoRaw(srv, http.MethodGet, c.path, c.query, "")
		if code != 400 && code != 404 {
			t.Errorf("RAW %s?%.20s: want 400/404, got %d (%s)", c.path, c.query, code, truncate(body, 80))
		}
		assertEnvelope(t, body)
	}
}

func TestCorpusPathIDs(t *testing.T) {
	srv := corpusServer(t)
	cases := []string{
		"/api/v1/assets/" + strings.Repeat("a", 100000),
		"/api/v1/evidence/%00",
		"/api/v1/incidents/%2e%2e%2fadmin",
		"/api/v1/grc/controls/" + strings.Repeat("é", 1000),
	}
	for _, p := range cases {
		code, body := corpusDo(srv, http.MethodGet, p, "")
		if code != 400 && code != 404 {
			t.Errorf("GET %.60s: want 400/404, got %d (%s)", p, code, truncate(body, 80))
		}
		assertEnvelope(t, body)
	}
	// Dot-segment traversal: Go's mux cleans the path with a 307 to the
	// canonical form (stdlib behavior), which then 404s. Both are safe;
	// neither reaches a handler with the dirty path.
	for _, p := range []string{
		"/api/v1/telemetry/" + strings.Repeat("../", 100) + "x",
		"/api/v1/assets/%2e%2e/ns",
	} {
		code, body := corpusDo(srv, http.MethodGet, p, "")
		if code != 307 && code != 400 && code != 404 {
			t.Errorf("GET %.60s: want 307/400/404, got %d", p, code)
		}
		if code >= 400 {
			assertEnvelope(t, body)
		}
	}
	// Raw spaces/control bytes in paths (harness cannot parse these;
	// raw servers receive them).
	for _, rawPath := range []string{
		"/api/v1/supply-chain/components/" + strings.Repeat(" ", 100),
		"/api/v1/assets/" + strings.Repeat("\x7f", 50),
	} {
		code, body := corpusDoRaw(srv, http.MethodGet, rawPath, "", "")
		if code != 400 && code != 404 {
			t.Errorf("RAW %.40s: want 400/404, got %d (%s)", rawPath, code, truncate(body, 80))
		}
		assertEnvelope(t, body)
	}
}

func TestCorpusBodies(t *testing.T) {
	srv := corpusServer(t)
	deep := strings.Repeat(`{"a":`, 500) + `1` + strings.Repeat(`}`, 500)
	cases := []struct {
		name string
		body string
		want []int
	}{
		{"empty", ``, []int{400}},
		{"null", `null`, []int{400}},
		{"array", `[]`, []int{400}},
		{"wrong types", `{"source":1,"type":[],"raw":{},"observed_at":{}}`, []int{400}},
		{"huge string", `{"source":"` + strings.Repeat("x", 1<<20) + `"}`, []int{400, 413}},
		{"deep nesting", deep, []int{400}},
		{"huge array", `[` + strings.Repeat(`1,`, 100000) + `1]`, []int{400}},
		{"duplicate keys", `{"source":"a","source":"b","type":"ASSET_TYPE_HOST","raw":"h","observed_at":"2026-09-12T10:00:00Z"}`, []int{201, 400}},
		{"control chars", "{\"source\":\"a\\u0000b\",\"type\":\"ASSET_TYPE_HOST\",\"raw\":\"h\",\"observed_at\":\"2026-09-12T10:00:00Z\"}", []int{201, 400}},
		{"unicode confusables", `{"source":"аdmin","type":"ASSET_TYPE_HOST","raw":"h","observed_at":"2026-09-12T10:00:00Z"}`, []int{201, 400}},
		{"bad timestamp", `{"source":"s","type":"ASSET_TYPE_HOST","raw":"h","observed_at":"9999-99-99"}`, []int{400}},
		{"year zero", `{"source":"s","type":"ASSET_TYPE_HOST","raw":"h","observed_at":"0000-01-01T00:00:00Z"}`, []int{400, 201}},
		{"unknown fields", `{"source":"s","type":"ASSET_TYPE_HOST","raw":"h","observed_at":"2026-09-12T10:00:00Z","exploit":"yes"}`, []int{201, 400}},
	}
	for _, c := range cases {
		code, body := corpusDo(srv, http.MethodPost, "/api/v1/assets/observations", c.body)
		ok := false
		for _, w := range c.want {
			if code == w {
				ok = true
			}
		}
		if !ok {
			t.Errorf("POST %s: want %v, got %d (%s)", c.name, c.want, code, truncate(body, 80))
		}
		if code >= 400 {
			assertEnvelope(t, body)
		}
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func assertEnvelope(t *testing.T, body string) {
	t.Helper()
	if !strings.Contains(body, `"error"`) || !strings.Contains(body, `"code"`) {
		t.Errorf("error response must carry the bounded envelope: %s", truncate(body, 120))
	}
	for _, leak := range []string{"goroutine", "panic:", ".go:", "traceback"} {
		if strings.Contains(strings.ToLower(body), leak) {
			t.Errorf("error leaks internals %q: %s", leak, truncate(body, 120))
		}
	}
}
