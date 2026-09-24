// Package httpobs normalizes HTTP/API observations carried by the existing
// TelemetryEvent contract (13C.2-4). Event type is "http.request", facts live
// in attributes namespace http.*. Missing optional fields stay unknown;
// malformed present fields fail explicitly. Sensitive headers/bodies are
// redacted before any persistence.
package httpobs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
)

const EventTypeHTTPRequest = "http.request"

var knownMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true,
	"PATCH": true, "HEAD": true, "OPTIONS": true, "CONNECT": true, "TRACE": true,
}

var knownSchemes = map[string]bool{"http": true, "https": true}

var knownDirections = map[string]bool{"inbound": true, "outbound": true, "internal": true}

var contentTypeRe = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&\-^_.+]*\/[a-z0-9][a-z0-9!#$&\-^_.+]*$`)

// rawBodyFragment is the HTTP-layer redaction extra on top of the
// canonical contract.SensitiveFragments: request bodies may carry
// credentials and are never stored.
const rawBodyFragment = "raw_body"

type Observation struct {
	EventID      string
	Source       string
	AssetID      string
	OccurredAt   time.Time
	Severity     v1.Severity
	Method       string
	Scheme       string
	Host         string
	Path         string
	QueryPresent bool
	HasQuery     bool
	StatusCode   int
	HasStatus    bool
	ContentType  string
	Route        string
	APIVersion   string
	RequestID    string
	UserAgent    string
	Direction    string
	BytesIn      int
	HasBytesIn   bool
	BytesOut     int
	HasBytesOut  bool
	AuthOutcome  string
	RawAttrs     map[string]string
}

func Parse(event *v1.TelemetryEvent) (Observation, error) {
	var o Observation
	if event == nil {
		return o, fmt.Errorf("httpobs: nil event")
	}
	if event.GetEventType() != EventTypeHTTPRequest {
		return o, fmt.Errorf("httpobs: event_type %q is not %q", event.GetEventType(), EventTypeHTTPRequest)
	}
	attrs := event.GetAttributes()
	// Redact sensitive keys first (canonical fragments; raw_body is an
	// HTTP-layer extra — bodies may carry credentials).
	clean := map[string]string{}
	for k, v := range attrs {
		low := strings.ToLower(k)
		if contract.SensitiveField(k) || strings.Contains(low, rawBodyFragment) {
			continue
		}
		clean[k] = v
	}
	methodRaw := strings.TrimSpace(clean["http.method"])
	if methodRaw == "" {
		return o, fmt.Errorf("httpobs: http.method required")
	}
	method := strings.ToUpper(methodRaw)
	if !knownMethods[method] {
		return o, fmt.Errorf("httpobs: unknown http.method %q", methodRaw)
	}
	hostRaw := strings.TrimSpace(clean["http.host"])
	if hostRaw == "" {
		return o, fmt.Errorf("httpobs: http.host required")
	}
	host := strings.ToLower(hostRaw)
	// Very light host validation: non-empty and no spaces.
	if strings.Contains(host, " ") || strings.Contains(host, "/") {
		return o, fmt.Errorf("httpobs: invalid http.host %q", hostRaw)
	}
	pathRaw := strings.TrimSpace(clean["http.path"])
	if pathRaw == "" {
		return o, fmt.Errorf("httpobs: http.path required")
	}
	path := pathRaw
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	scheme := strings.ToLower(strings.TrimSpace(clean["http.scheme"]))
	if scheme != "" && !knownSchemes[scheme] {
		return o, fmt.Errorf("httpobs: unknown http.scheme %q", scheme)
	}
	qpRaw := strings.TrimSpace(clean["http.query_present"])
	hasQP := false
	qp := false
	if qpRaw != "" {
		switch strings.ToLower(qpRaw) {
		case "true":
			qp = true
			hasQP = true
		case "false":
			qp = false
			hasQP = true
		default:
			return o, fmt.Errorf("httpobs: invalid http.query_present %q", qpRaw)
		}
	}
	status := 0
	hasStatus := false
	if scRaw := strings.TrimSpace(clean["http.status_code"]); scRaw != "" {
		n, err := strconv.Atoi(scRaw)
		if err != nil || n < 100 || n > 599 {
			return o, fmt.Errorf("httpobs: invalid http.status_code %q", scRaw)
		}
		status = n
		hasStatus = true
	}
	ct := strings.ToLower(strings.TrimSpace(clean["http.content_type"]))
	// Strip RFC 9110 parameters ("text/html; charset=utf-8"): a valid
	// media type with parameters must not abort the pipeline.
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if ct != "" && !contentTypeRe.MatchString(ct) {
		return o, fmt.Errorf("httpobs: invalid http.content_type %q", ct)
	}
	direction := strings.ToLower(strings.TrimSpace(clean["http.direction"]))
	if direction != "" && !knownDirections[direction] {
		return o, fmt.Errorf("httpobs: unknown http.direction %q", direction)
	}
	bytesIn := 0
	hasBytesIn := false
	if b := strings.TrimSpace(clean["http.bytes_in"]); b != "" {
		n, err := strconv.Atoi(b)
		if err != nil || n < 0 {
			return o, fmt.Errorf("httpobs: invalid http.bytes_in %q", b)
		}
		bytesIn = n
		hasBytesIn = true
	}
	bytesOut := 0
	hasBytesOut := false
	if b := strings.TrimSpace(clean["http.bytes_out"]); b != "" {
		n, err := strconv.Atoi(b)
		if err != nil || n < 0 {
			return o, fmt.Errorf("httpobs: invalid http.bytes_out %q", b)
		}
		bytesOut = n
		hasBytesOut = true
	}
	authOutcome := strings.ToLower(strings.TrimSpace(clean["http.auth_outcome"]))
	if authOutcome != "" && authOutcome != "success" && authOutcome != "failure" {
		return o, fmt.Errorf("httpobs: unknown http.auth_outcome %q", authOutcome)
	}
	// Keep non-sensitive raw attrs for provenance.
	o = Observation{
		EventID:      event.GetId(),
		Source:       event.GetSource(),
		AssetID:      event.GetAssetId(),
		OccurredAt:   event.GetOccurredAt().AsTime(),
		Severity:     event.GetSeverity(),
		Method:       method,
		Scheme:       scheme,
		Host:         host,
		Path:         path,
		QueryPresent: qp,
		HasQuery:     hasQP,
		StatusCode:   status,
		HasStatus:    hasStatus,
		ContentType:  ct,
		Route:        strings.TrimSpace(clean["http.route"]),
		APIVersion:   strings.TrimSpace(clean["http.api_version"]),
		RequestID:    strings.TrimSpace(clean["http.request_id"]),
		UserAgent:    strings.TrimSpace(clean["http.user_agent"]),
		Direction:    direction,
		BytesIn:      bytesIn,
		HasBytesIn:   hasBytesIn,
		BytesOut:     bytesOut,
		HasBytesOut:  hasBytesOut,
		AuthOutcome:  authOutcome,
		RawAttrs:     clean,
	}
	return o, nil
}

func (o Observation) ID() string {
	var b strings.Builder
	b.WriteString(o.Method)
	b.WriteString("\x1f")
	b.WriteString(o.Host)
	b.WriteString("\x1f")
	b.WriteString(o.Path)
	b.WriteString("\x1f")
	if o.HasStatus {
		fmt.Fprintf(&b, "%d", o.StatusCode)
	}
	b.WriteString("\x1f")
	b.WriteString(o.Route)
	b.WriteString("\x1f")
	b.WriteString(o.APIVersion)
	sum := sha256.Sum256([]byte(b.String()))
	return "httpobs-" + hex.EncodeToString(sum[:])[:16]
}
