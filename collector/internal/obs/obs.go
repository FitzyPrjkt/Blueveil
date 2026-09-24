// Package obs is the operational observability foundation: structured
// logging with request/correlation IDs and honest counters. It measures
// only actual behavior (requests, failures, ingestion, provider errors)
// — never security scores, trends, or guarantees.
//
// Secret redaction is structural: a fixed sensitive-key list is dropped
// from every log record at the handler level, so no call site can leak
// credentials by accident.
package obs

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
)

// sensitiveLogKeys are dropped from log records (case-insensitive
// substring, mirroring contract.SensitiveFragments without importing the
// contract boundary into the ops layer).
var sensitiveLogKeys = []string{
	"password", "passwd", "token", "secret", "credential", "cookie",
	"authorization", "session", "api_key", "apikey", "private_key", "mfa",
	"access_key",
}

func redactAttrs(attrs []any) []any {
	out := make([]any, 0, len(attrs))
	for i := 0; i < len(attrs); i++ {
		k, ok := attrs[i].(string)
		if !ok {
			out = append(out, attrs[i])
			continue
		}
		low := strings.ToLower(k)
		drop := false
		for _, frag := range sensitiveLogKeys {
			if strings.Contains(low, frag) {
				drop = true
				break
			}
		}
		if drop {
			// Drop the key AND its value (key=value or structured pairs).
			if i+1 < len(attrs) {
				i++
			}
			continue
		}
		out = append(out, attrs[i])
	}
	return out
}

// Logger wraps slog with record-level secret redaction.
type Logger struct{ inner *slog.Logger }

// New builds a levelled logger in text or json form. Unknown levels and
// formats are construction errors (fail fast at startup).
func New(level, format string, w io.Writer) (*Logger, error) {
	var lvl slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		lvl = slog.LevelDebug
	case "info":
		lvl = slog.LevelInfo
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		return nil, fmt.Errorf("obs: logging level must be debug|info|warn|error")
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "text":
		h = slog.NewTextHandler(w, opts)
	case "json":
		h = slog.NewJSONHandler(w, opts)
	default:
		return nil, fmt.Errorf("obs: logging format must be text|json")
	}
	return &Logger{inner: slog.New(&redactingHandler{next: h})}, nil
}

// redactingHandler drops sensitive keys before the record is written.
type redactingHandler struct{ next slog.Handler }

func (h *redactingHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.next.Enabled(ctx, l)
}

func (h *redactingHandler) Handle(ctx context.Context, r slog.Record) error {
	dropped := []string{}
	r.Attrs(func(a slog.Attr) bool {
		low := strings.ToLower(a.Key)
		for _, frag := range sensitiveLogKeys {
			if strings.Contains(low, frag) {
				dropped = append(dropped, a.Key)
				return true
			}
		}
		return true
	})
	for _, k := range dropped {
		r = deleteAttr(r, k)
	}
	return h.next.Handle(ctx, r)
}

func deleteAttr(r slog.Record, key string) slog.Record {
	var kept []slog.Attr
	r.Attrs(func(a slog.Attr) bool {
		if a.Key != key {
			kept = append(kept, a)
		}
		return true
	})
	out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	for _, a := range kept {
		out.AddAttrs(a)
	}
	return out
}

func (h *redactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &redactingHandler{next: h.next.WithAttrs(attrs)}
}

func (h *redactingHandler) WithGroup(name string) slog.Handler {
	return &redactingHandler{next: h.next.WithGroup(name)}
}

// Info logs at info level with redaction applied to key/value pairs.
func (l *Logger) Info(msg string, kv ...any) { l.inner.Info(msg, redactAttrs(kv)...) }

// Warn logs at warn level with redaction applied.
func (l *Logger) Warn(msg string, kv ...any) { l.inner.Warn(msg, redactAttrs(kv)...) }

// Error logs at error level with redaction applied.
func (l *Logger) Error(msg string, kv ...any) { l.inner.Error(msg, redactAttrs(kv)...) }

// Debug logs at debug level with redaction applied.
func (l *Logger) Debug(msg string, kv ...any) { l.inner.Debug(msg, redactAttrs(kv)...) }

// With returns a child logger with fixed attributes (redacted first).
func (l *Logger) With(kv ...any) *Logger {
	return &Logger{inner: l.inner.With(redactAttrs(kv)...)}
}

// Slog exposes the underlying logger for stdlib interop.
func (l *Logger) Slog() *slog.Logger { return l.inner }

// Metrics counts actual measured behavior with atomics. Every counter
// maps to an event the system really observes; there are no derived
// rates, scores, or security judgments.
type Metrics struct {
	requests                 atomic.Uint64
	requestErr4xx            atomic.Uint64
	requestErr5xx            atomic.Uint64
	persistenceFailures      atomic.Uint64
	ingestAccepted           atomic.Uint64
	ingestRejected           atomic.Uint64
	detectionErrors          atomic.Uint64
	validationProviderErrors atomic.Uint64
}

// NewMetrics returns zeroed counters.
func NewMetrics() *Metrics { return &Metrics{} }

// Request records one served request.
func (m *Metrics) Request() { m.requests.Add(1) }

// RequestError records one failed request by class (4xx vs 5xx).
func (m *Metrics) RequestError(status int) {
	if status >= 500 {
		m.requestErr5xx.Add(1)
	} else if status >= 400 {
		m.requestErr4xx.Add(1)
	}
}

// PersistenceFailure records one failed store write/read.
func (m *Metrics) PersistenceFailure() { m.persistenceFailures.Add(1) }

// IngestAccepted records one accepted ingestion event.
func (m *Metrics) IngestAccepted() { m.ingestAccepted.Add(1) }

// IngestRejected records one rejected ingestion event.
func (m *Metrics) IngestRejected() { m.ingestRejected.Add(1) }

// DetectionError records one rule-evaluation failure.
func (m *Metrics) DetectionError() { m.detectionErrors.Add(1) }

// ValidationProviderError records one validation provider failure.
func (m *Metrics) ValidationProviderError() { m.validationProviderErrors.Add(1) }

// Snapshot returns a copy of all counters (stable keys, uint64 values).
func (m *Metrics) Snapshot() map[string]uint64 {
	return map[string]uint64{
		"requests_total":             m.requests.Load(),
		"request_errors_4xx":         m.requestErr4xx.Load(),
		"request_errors_5xx":         m.requestErr5xx.Load(),
		"persistence_failures":       m.persistenceFailures.Load(),
		"ingest_accepted":            m.ingestAccepted.Load(),
		"ingest_rejected":            m.ingestRejected.Load(),
		"detection_errors":           m.detectionErrors.Load(),
		"validation_provider_errors": m.validationProviderErrors.Load(),
	}
}
