// Package server debug logging helpers — only active when --debug / DEBUG=true.
package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	applog "github.com/apimgr/ipgaze/src/log"
)

// debugLogRequest records detailed request information when debug mode is
// active. It emits to slog for the console and to debug.log through lm, which
// AI.md PART 11 mandates as one of the eight log files. Every interpolated
// value is sanitized so a client cannot forge extra log lines.
func debugLogRequest(lm *applog.Manager, debug bool, r *http.Request, status int, duration time.Duration, size int) {
	if !debug {
		return
	}

	method := r.Method
	path := sanitizeLogValue(r.URL.Path)
	query := sanitizeLogValue(r.URL.RawQuery)
	remoteAddr := sanitizeLogValue(r.RemoteAddr)
	userAgent := sanitizeLogValue(r.UserAgent())
	referer := sanitizeLogValue(r.Referer())
	requestID := sanitizeLogValue(r.Header.Get("X-Request-ID"))

	slog.Debug("request",
		"method", method,
		"path", path,
		"query", query,
		"status", status,
		"duration_ms", duration.Milliseconds(),
		"size", size,
		"remote_addr", remoteAddr,
		"user_agent", userAgent,
		"referer", referer,
		"request_id", requestID,
	)

	lm.WriteDebug(fmt.Sprintf(
		"request method=%s path=%s query=%s status=%d duration_ms=%d size=%d remote_addr=%s user_agent=%q referer=%q request_id=%s",
		method, path, query, status, duration.Milliseconds(), size, remoteAddr, userAgent, referer, requestID))
}
