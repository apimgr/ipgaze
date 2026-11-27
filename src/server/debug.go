// Package server debug routes — only registered when --debug / DEBUG=true is active.
package server

import (
	"bytes"
	"encoding/json"
	"expvar"
	"io"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"runtime"
	"strings"

	"github.com/apimgr/ipgaze/src/swagger"
	"github.com/go-chi/chi/v5"
)

// respondJSON writes v as indented JSON with the given status code.
func respondJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// respondError writes a canonical JSON error response per AI.md PART 9.
// Used only by debug endpoints (registered only when IsDebug() is true).
func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]interface{}{
		"ok":      false,
		"error":   "DEBUG_ERROR",
		"message": message,
	})
}

// debugRouteDefinitions returns the debug-only Route values that belong to the
// shared registry. No route exists unless debug mode and its specific feature
// gate are enabled.
func (s *Server) debugRouteDefinitions() []swagger.Route {
	if s.config == nil || !s.config.IsDebug() {
		return nil
	}
	var routes []swagger.Route
	add := func(method, path, id string, h http.Handler) {
		routes = append(routes, swagger.Route{Method: method, Path: "/debug/" + strings.TrimPrefix(path, "/"), OperationID: "debug_" + id, Auth: "operator", Listed: false, Internal: true, Handler: h.ServeHTTP})
	}
	if s.config.Server.Debug.Pprof {
		add(http.MethodGet, "pprof/", "pprof_index", http.HandlerFunc(pprof.Index))
		add(http.MethodGet, "pprof/cmdline", "pprof_cmdline", http.HandlerFunc(pprof.Cmdline))
		add(http.MethodGet, "pprof/profile", "pprof_profile", http.HandlerFunc(pprof.Profile))
		add(http.MethodGet, "pprof/symbol", "pprof_symbol", http.HandlerFunc(pprof.Symbol))
		add(http.MethodGet, "pprof/trace", "pprof_trace", http.HandlerFunc(pprof.Trace))
		for _, profile := range []string{"heap", "goroutine", "allocs", "block", "mutex", "threadcreate"} {
			add(http.MethodGet, "pprof/"+profile, "pprof_"+profile, pprof.Handler(profile))
		}
	}
	if s.config.Server.Debug.RuntimeEndpoints {
		add(http.MethodGet, "vars", "vars", expvar.Handler())
		add(http.MethodGet, "error500", "error500", http.HandlerFunc(s.handleDebugError500))
		add(http.MethodGet, "config", "config", http.HandlerFunc(s.handleDebugConfig))
		add(http.MethodGet, "routes", "routes", http.HandlerFunc(s.handleDebugRoutes))
		add(http.MethodGet, "cache", "cache", http.HandlerFunc(s.handleDebugCache))
		add(http.MethodPost, "cache/resize", "cache_resize", http.HandlerFunc(s.handleDebugCacheResize))
		add(http.MethodGet, "db", "db", http.HandlerFunc(s.handleDebugDB))
		add(http.MethodGet, "scheduler", "scheduler", http.HandlerFunc(s.handleDebugScheduler))
		add(http.MethodGet, "memory", "memory", http.HandlerFunc(s.handleDebugMemory))
		add(http.MethodGet, "goroutines", "goroutines", http.HandlerFunc(s.handleDebugGoroutines))
	}
	return routes
}

// registerDebugRoutes mounts the Internal values from the shared route list.
func (s *Server) registerDebugRoutes(r chi.Router, routes []swagger.Route) {
	var debugRoutes []swagger.Route
	for _, route := range routes {
		if route.Internal && strings.HasPrefix(route.Path, "/debug/") && route.Handler != nil {
			debugRoutes = append(debugRoutes, route)
		}
	}
	if len(debugRoutes) == 0 {
		return
	}
	r.Route("/debug", func(r chi.Router) {
		r.Use(s.RequireOperatorToken)
		for _, route := range debugRoutes {
			path := strings.TrimPrefix(route.Path, "/debug")
			r.Method(route.Method, path, route.Handler)
		}
	})
}

// handleDebugError500 provides a deterministic trigger for the themed 500
// page used by the E2E suite. It remains behind the debug routes and their
// operator-token middleware.
func (s *Server) handleDebugError500(w http.ResponseWriter, r *http.Request) {
	writeNegotiatedError(w, r, http.StatusInternalServerError, "", "Internal Server Error")
}

// handleDebugConfig returns sanitized configuration (sensitive values redacted).
func (s *Server) handleDebugConfig(w http.ResponseWriter, r *http.Request) {
	if s.config == nil {
		respondJSON(w, http.StatusOK, map[string]string{"status": "config not loaded"})
		return
	}
	sanitized := s.config.Sanitized()
	respondJSON(w, http.StatusOK, sanitized)
}

// handleDebugRoutes returns all registered routes from the chi router.
func (s *Server) handleDebugRoutes(w http.ResponseWriter, r *http.Request) {
	routes := []map[string]string{}

	if s.router != nil {
		walkFunc := func(method string, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
			routes = append(routes, map[string]string{
				"method": method,
				"route":  route,
			})
			return nil
		}
		if err := chi.Walk(s.router, walkFunc); err != nil {
			respondError(w, http.StatusInternalServerError, "failed to walk routes")
			return
		}
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"count":  len(routes),
		"routes": routes,
	})
}

// handleDebugCache returns cache statistics.
func (s *Server) handleDebugCache(w http.ResponseWriter, r *http.Request) {
	if s.CacheHandler != nil {
		s.CacheHandler.CacheStatsHandler(w, r)
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "cache not available"})
}

// handleDebugCacheResize resizes the in-memory cache capacity.
func (s *Server) handleDebugCacheResize(w http.ResponseWriter, r *http.Request) {
	if s.CacheHandler != nil {
		s.CacheHandler.CacheResizeHandler(w, r)
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "cache not available"})
}

// handleDebugDB returns database connection pool statistics.
func (s *Server) handleDebugDB(w http.ResponseWriter, r *http.Request) {
	if s.sqlDB == nil {
		respondJSON(w, http.StatusOK, map[string]string{"status": "database not available"})
		return
	}
	stats := s.sqlDB.Stats()
	respondJSON(w, http.StatusOK, map[string]any{
		"open_connections":    stats.OpenConnections,
		"in_use":              stats.InUse,
		"idle":                stats.Idle,
		"wait_count":          stats.WaitCount,
		"wait_duration_ms":    stats.WaitDuration.Milliseconds(),
		"max_idle_closed":     stats.MaxIdleClosed,
		"max_lifetime_closed": stats.MaxLifetimeClosed,
	})
}

// handleDebugScheduler returns scheduler task status.
func (s *Server) handleDebugScheduler(w http.ResponseWriter, r *http.Request) {
	if s.sched == nil {
		respondJSON(w, http.StatusOK, map[string]string{"status": "scheduler not available"})
		return
	}
	tasks := s.sched.Status()
	respondJSON(w, http.StatusOK, tasks)
}

// handleDebugMemory returns Go runtime memory statistics.
func (s *Server) handleDebugMemory(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	respondJSON(w, http.StatusOK, map[string]any{
		"alloc_mb":       m.Alloc / 1024 / 1024,
		"total_alloc_mb": m.TotalAlloc / 1024 / 1024,
		"sys_mb":         m.Sys / 1024 / 1024,
		"num_gc":         m.NumGC,
		"heap_objects":   m.HeapObjects,
		"goroutines":     runtime.NumGoroutine(),
	})
}

// handleDebugGoroutines returns current goroutine count and full stack traces.
func (s *Server) handleDebugGoroutines(w http.ResponseWriter, r *http.Request) {
	buf := make([]byte, 1024*1024)
	n := runtime.Stack(buf, true)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf[:n])
}

// bodyCapturingWriter wraps http.ResponseWriter, tee-ing every write into a
// bounded buffer (up to limit bytes) so debugBodyLoggingMiddleware can log a
// preview of the response body per AI.md PART 6 server.debug.log_bodies.
type bodyCapturingWriter struct {
	http.ResponseWriter
	limit      int64
	captured   bytes.Buffer
	statusCode int
}

func (w *bodyCapturingWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *bodyCapturingWriter) Write(b []byte) (int, error) {
	if int64(w.captured.Len()) < w.limit {
		remaining := w.limit - int64(w.captured.Len())
		if remaining > int64(len(b)) {
			w.captured.Write(b)
		} else {
			w.captured.Write(b[:remaining])
		}
	}
	return w.ResponseWriter.Write(b)
}

// debugBodyLoggingMiddleware logs request and response bodies (truncated to
// server.debug.max_body_log_size) when both --debug/DEBUG=true and
// server.debug.log_bodies are active per AI.md PART 6. No-op passthrough
// otherwise so normal request handling never pays the buffering cost.
func (s *Server) debugBodyLoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.config == nil || !s.config.IsDebug() || !s.config.Server.Debug.LogBodies {
			next.ServeHTTP(w, r)
			return
		}

		limit := s.config.Server.Debug.MaxBodyLogSizeBytes()

		var reqBody []byte
		if r.Body != nil {
			limited := io.LimitReader(r.Body, limit)
			reqBody, _ = io.ReadAll(limited)
			// Restore the body for downstream handlers using the captured
			// bytes plus whatever remains unread on the original body.
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(reqBody), r.Body))
		}

		wrapped := &bodyCapturingWriter{ResponseWriter: w, limit: limit, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)

		slog.Debug("http body",
			"method", r.Method,
			"path", r.URL.Path,
			"status", wrapped.statusCode,
			"request_body", string(reqBody),
			"response_body", wrapped.captured.String(),
		)
	})
}
