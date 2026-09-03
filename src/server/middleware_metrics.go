package server

import (
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	smetrics "github.com/apimgr/ipgaze/src/server/metrics"
)

var (
	uuidRegex      = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	numericIDRegex = regexp.MustCompile(`/\d+(/|$)`)
)

// normalizePath replaces UUIDs and numeric path segments with ":id" so high-cardinality
// paths are collapsed into a single metric label. Used only as a fallback when chi has
// not matched a route pattern (e.g. 404s), so unmatched paths can't still blow up
// cardinality with attacker-chosen segments.
func normalizePath(path string) string {
	path = uuidRegex.ReplaceAllString(path, ":id")
	path = numericIDRegex.ReplaceAllString(path, "/:id$1")
	return path
}

// metricsPath returns the routed chi pattern (e.g. "/api/v1/lookup/{ip}") for the
// metrics label instead of the raw request path, bounding label cardinality to the
// fixed set of registered routes rather than growing per distinct path parameter
// value an attacker can supply. Falls back to normalizePath for unmatched routes.
func metricsPath(r *http.Request) string {
	if rctx := chi.RouteContext(r.Context()); rctx != nil {
		if pattern := rctx.RoutePattern(); pattern != "" {
			return pattern
		}
	}
	return normalizePath(r.URL.Path)
}

// metricsResponseWriter wraps http.ResponseWriter to capture status code and bytes written.
type metricsResponseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func newMetricsResponseWriter(w http.ResponseWriter) *metricsResponseWriter {
	return &metricsResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
}

func (mw *metricsResponseWriter) WriteHeader(code int) {
	mw.statusCode = code
	mw.ResponseWriter.WriteHeader(code)
}

func (mw *metricsResponseWriter) Write(b []byte) (int, error) {
	n, err := mw.ResponseWriter.Write(b)
	mw.bytesWritten += n
	return n, err
}

// metricsMiddleware records Prometheus HTTP metrics for every request.
// It is a no-op when metricsEnabled is false.
func (s *Server) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.metricsEnabled {
			next.ServeHTTP(w, r)
			return
		}

		method := r.Method

		smetrics.HTTPActiveRequests.Inc()
		defer smetrics.HTTPActiveRequests.Dec()

		// Estimate request size from Content-Length header.
		reqSize := r.ContentLength
		if reqSize < 0 {
			reqSize = 0
		}

		wrapped := newMetricsResponseWriter(w)
		start := time.Now()
		next.ServeHTTP(wrapped, r)
		duration := time.Since(start)

		// Resolved after next.ServeHTTP so chi's RouteContext has the matched
		// pattern populated, bounding the label to the fixed route set rather
		// than the raw (attacker-influenced) request path.
		path := metricsPath(r)

		status := strconv.Itoa(wrapped.statusCode)
		smetrics.HTTPRequestSize.WithLabelValues(method, path).Observe(float64(reqSize))
		smetrics.HTTPRequestsTotal.WithLabelValues(method, path, status).Inc()
		smetrics.HTTPRequestDuration.WithLabelValues(method, path).Observe(duration.Seconds())
		smetrics.HTTPResponseSize.WithLabelValues(method, path).Observe(float64(wrapped.bytesWritten))
	})
}
