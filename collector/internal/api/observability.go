// Operational middleware (15G): structured access logging and honest
// request metrics. Logs carry method, path, status, duration,
// request id, and authenticated role — never credentials, headers, or
// bodies. Metrics count requests and failures by class only.
package api

import (
	"net/http"
	"time"

	"blueveil/collector/internal/obs"
)

// observability bundles the logger, metrics, and health hook.
type observability struct {
	log     *obs.Logger
	metrics *obs.Metrics
	health  func(r *http.Request) error
}

// UseObservability attaches logging, metrics, and the readiness health
// hook. Either logger or metrics may be nil (that signal is skipped).
func (s *Server) UseObservability(log *obs.Logger, m *obs.Metrics, health func(r *http.Request) error) {
	s.obs = &observability{log: log, metrics: m, health: health}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (o *observability) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		dur := time.Since(start)
		if o.metrics != nil {
			o.metrics.Request()
			if sw.status >= 400 {
				o.metrics.RequestError(sw.status)
			}
		}
		if o.log != nil {
			role := ""
			if id, ok := IdentityOf(r); ok {
				role = id.Role
			}
			o.log.Info("request",
				"operation", r.Method+" "+r.URL.Path,
				"request_id", RequestIDOf(r),
				"status", sw.status,
				"duration_ms", dur.Milliseconds(),
				"role", role,
			)
		}
	})
}
