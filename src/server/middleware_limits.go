package server

import (
	"compress/gzip"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/apimgr/ipgaze/src/config"
)

// parseByteSize converts a "10MB"/"512KB"/"1GB" style config value (or a bare
// byte count) to bytes. Returns 0 when the value is empty or unparseable, in
// which case the caller must fall back to a safe default rather than leaving
// the body unbounded.
func parseByteSize(v string) int64 {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	upper := strings.ToUpper(v)
	multiplier := int64(1)
	digits := upper
	switch {
	case strings.HasSuffix(upper, "GB"):
		multiplier, digits = 1024*1024*1024, strings.TrimSuffix(upper, "GB")
	case strings.HasSuffix(upper, "MB"):
		multiplier, digits = 1024*1024, strings.TrimSuffix(upper, "MB")
	case strings.HasSuffix(upper, "KB"):
		multiplier, digits = 1024, strings.TrimSuffix(upper, "KB")
	case strings.HasSuffix(upper, "B"):
		digits = strings.TrimSuffix(upper, "B")
	}
	n, err := strconv.ParseInt(strings.TrimSpace(digits), 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	return n * multiplier
}

// BodyLimitMiddleware enforces server.limits.max_body_size (AI.md PART 12
// "Request Limits"). A Content-Length that already exceeds the ceiling is
// rejected immediately; every request body is additionally wrapped in
// http.MaxBytesReader so a chunked or lying-Content-Length body still stops
// at the same limit once the handler reads past it.
func BodyLimitMiddleware(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if maxBytes <= 0 {
				next.ServeHTTP(w, r)
				return
			}
			if r.ContentLength > maxBytes {
				writePayloadTooLarge(w, r)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}

// writePayloadTooLarge mirrors writeMaintenanceRejection's guaranteed,
// template-free response shape — the canonical JSON envelope for API/tool
// clients, a minimal inline HTML page for browsers.
func writePayloadTooLarge(w http.ResponseWriter, r *http.Request) {
	if detectClientType(r) == "html" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		fmt.Fprint(w, "<!DOCTYPE html><html><head><title>413 Payload Too Large</title></head>"+
			"<body><h1>413</h1><p>The request body exceeds the maximum allowed size.</p>"+
			"<a href=\"/\">Home</a></body></html>")
		return
	}
	w.Header().Set("Content-Type", jsonMediaType)
	w.WriteHeader(http.StatusRequestEntityTooLarge)
	fmt.Fprint(w, `{"ok":false,"error":"PAYLOAD_TOO_LARGE","message":"Request body exceeds the maximum allowed size"}`+"\n")
}

// gzipResponseWriter defers the compress-or-not decision to the first
// WriteHeader/Write call so the wrapped handler's own Content-Type is always
// what decides eligibility (AI.md PART 12 "Response Compression" — only the
// configured MIME types are compressed).
type gzipResponseWriter struct {
	http.ResponseWriter
	types    map[string]bool
	level    int
	decided  bool
	compress bool
	gz       *gzip.Writer
}

func (w *gzipResponseWriter) decide() {
	if w.decided {
		return
	}
	w.decided = true
	ct := w.Header().Get("Content-Type")
	if idx := strings.IndexByte(ct, ';'); idx >= 0 {
		ct = ct[:idx]
	}
	if w.types[strings.TrimSpace(strings.ToLower(ct))] {
		w.compress = true
		w.Header().Del("Content-Length")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Add("Vary", "Accept-Encoding")
	}
}

func (w *gzipResponseWriter) WriteHeader(status int) {
	w.decide()
	w.ResponseWriter.WriteHeader(status)
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	w.decide()
	if !w.compress {
		return w.ResponseWriter.Write(b)
	}
	if w.gz == nil {
		gz, err := gzip.NewWriterLevel(w.ResponseWriter, w.level)
		if err != nil {
			gz = gzip.NewWriter(w.ResponseWriter)
		}
		w.gz = gz
	}
	return w.gz.Write(b)
}

func (w *gzipResponseWriter) Flush() {
	if w.gz != nil {
		w.gz.Flush()
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *gzipResponseWriter) Close() error {
	if w.gz != nil {
		return w.gz.Close()
	}
	return nil
}

// acceptsGzip reports whether the client's Accept-Encoding list includes gzip.
func acceptsGzip(r *http.Request) bool {
	for _, enc := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		if strings.TrimSpace(strings.SplitN(strings.TrimSpace(enc), ";", 2)[0]) == "gzip" {
			return true
		}
	}
	return false
}

// CompressionMiddleware gzip-encodes responses whose Content-Type is in
// server.compression.types, per AI.md PART 12. Disabled outright when the
// config toggle is off, no types are configured, or the client sent no
// Accept-Encoding: gzip.
func CompressionMiddleware(cfg config.CompressionConfig) func(http.Handler) http.Handler {
	types := make(map[string]bool, len(cfg.Types))
	for _, t := range cfg.Types {
		if t = strings.TrimSpace(strings.ToLower(t)); t != "" {
			types[t] = true
		}
	}
	level := cfg.Level
	if level < 1 || level > 9 {
		level = gzip.DefaultCompression
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.Enabled || len(types) == 0 || !acceptsGzip(r) {
				next.ServeHTTP(w, r)
				return
			}
			gw := &gzipResponseWriter{ResponseWriter: w, types: types, level: level}
			defer gw.Close()
			next.ServeHTTP(gw, r)
		})
	}
}
