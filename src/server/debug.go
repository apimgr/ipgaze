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

	"github.com/go-chi/chi/v5"
)

// respondJSON writes v as indented JSON with the given status code.
func respondJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
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

// registerDebugRoutes mounts all debug endpoints under /debug/.
// Returns immediately (no routes registered) unless s.config.IsDebug() is true.
func (s *Server) registerDebugRoutes(r chi.Router) {
	if s.config == nil || !s.config.IsDebug() {
		return
	}

	r.Route("/debug", func(r chi.Router) {
		// pprof endpoints — gated by server.debug.pprof per AI.md PART 6.
		if s.config.Server.Debug.Pprof {
			r.HandleFunc("/pprof/", pprof.Index)
			r.HandleFunc("/pprof/cmdline", pprof.Cmdline)
			r.HandleFunc("/pprof/profile", pprof.Profile)
			r.HandleFunc("/pprof/symbol", pprof.Symbol)
			r.HandleFunc("/pprof/trace", pprof.Trace)
			r.Handle("/pprof/heap", pprof.Handler("heap"))
			r.Handle("/pprof/goroutine", pprof.Handler("goroutine"))
			r.Handle("/pprof/allocs", pprof.Handler("allocs"))
			r.Handle("/pprof/block", pprof.Handler("block"))
			r.Handle("/pprof/mutex", pprof.Handler("mutex"))
			r.Handle("/pprof/threadcreate", pprof.Handler("threadcreate"))
		}

		// Custom runtime endpoints — gated by server.debug.runtime_endpoints
		// per AI.md PART 6.
		if s.config.Server.Debug.RuntimeEndpoints {
			r.Handle("/vars", expvar.Handler())
			r.Get("/config", s.handleDebugConfig)
			r.Get("/routes", s.handleDebugRoutes)
			r.Get("/cache", s.handleDebugCache)
			r.Post("/cache/resize", s.handleDebugCacheResize)
			r.Get("/db", s.handleDebugDB)
			r.Get("/scheduler", s.handleDebugScheduler)
			r.Get("/memory", s.handleDebugMemory)
			r.Get("/goroutines", s.handleDebugGoroutines)
		}
	})
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
	w.Write(buf[:n])
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
