package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// maintenanceProbeInterval is the self-healing retry cadence from AI.md PART 12
// "Self-Healing Process": while maintenance mode is active the server re-tests
// the failed subsystem every 30 seconds and leaves maintenance automatically
// once the condition clears.
const maintenanceProbeInterval = 30 * time.Second

// maintenanceState carries the current maintenance flag plus the operator
// guidance that goes with it. The flag is an atomic so the hot request path
// reads it without taking a lock; the strings are only touched on transitions.
type maintenanceState struct {
	active   atomic.Bool
	mu       sync.RWMutex
	reason   string
	guidance string
	monitor  sync.Once
}

// MaintenanceActive reports whether the server is currently in maintenance mode.
func (s *Server) MaintenanceActive() bool {
	return s.maintenance.active.Load()
}

// MaintenanceReason returns the current reason and operator guidance, both
// empty when the server is healthy. Per AI.md PART 12 this text is for the
// operator-facing status endpoint and the logs, never for anonymous clients.
func (s *Server) MaintenanceReason() (string, string) {
	s.maintenance.mu.RLock()
	defer s.maintenance.mu.RUnlock()
	return s.maintenance.reason, s.maintenance.guidance
}

// EnterMaintenance puts the server into read-only maintenance mode after one of
// the two critical errors of AI.md PART 12 — a database connection failure or a
// file-write failure. It never terminates the process: the whole point of
// maintenance mode is that a critical error degrades the server to read-only
// instead of taking it down, while the self-healing loop keeps retrying.
func (s *Server) EnterMaintenance(reason, guidance string) {
	s.maintenance.mu.Lock()
	s.maintenance.reason = reason
	s.maintenance.guidance = guidance
	s.maintenance.mu.Unlock()

	if s.maintenance.active.Swap(true) {
		return
	}
	if s.logManager != nil {
		s.logManager.WriteError("error", "entering maintenance mode: "+sanitizeLogValue(reason)+
			" - "+sanitizeLogValue(guidance))
	}
	s.StartMaintenanceMonitor()
}

// ExitMaintenance returns the server to normal operation once the critical
// condition has cleared.
func (s *Server) ExitMaintenance() {
	if !s.maintenance.active.Swap(false) {
		return
	}
	s.maintenance.mu.Lock()
	s.maintenance.reason = ""
	s.maintenance.guidance = ""
	s.maintenance.mu.Unlock()

	if s.logManager != nil {
		s.logManager.WriteServer("info", "leaving maintenance mode: critical condition recovered")
	}
}

// StartMaintenanceMonitor launches the single self-healing loop. It is safe to
// call repeatedly; only the first call starts the goroutine, which then runs
// for the life of the process and is idle while the server is healthy.
func (s *Server) StartMaintenanceMonitor() {
	s.maintenance.monitor.Do(func() {
		go s.maintenanceMonitorLoop()
	})
}

// maintenanceMonitorLoop probes the two critical subsystems on every tick. It
// both enters maintenance when a probe starts failing and leaves it once every
// probe passes again (AI.md PART 12 "Self-Healing Process").
func (s *Server) maintenanceMonitorLoop() {
	ticker := time.NewTicker(maintenanceProbeInterval)
	defer ticker.Stop()
	for range ticker.C {
		reason, guidance, err := s.probeCriticalSubsystems()
		if err != nil {
			s.EnterMaintenance(reason, guidance)
			if s.logManager != nil {
				s.logManager.WriteError("error", "self-healing attempt failed: "+
					sanitizeLogValue(reason)+" - "+sanitizeLogValue(guidance))
			}
			continue
		}
		s.ExitMaintenance()
	}
}

// probeCriticalSubsystems tests database connectivity and data-directory
// writability — the only two critical error classes in AI.md PART 12. It
// returns the reason and the operator guidance alongside the error so both the
// log line and the maintenance status carry actionable text.
func (s *Server) probeCriticalSubsystems() (string, string, error) {
	if s.sqlDB != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := s.sqlDB.PingContext(ctx)
		cancel()
		if err != nil {
			return "database connection failed: " + err.Error(),
				"Verify the database is reachable and that server.yml's database credentials are correct.",
				err
		}
	}
	if err := s.probeDataDirWritable(); err != nil {
		return "data directory is not writable: " + err.Error(),
			"Check free disk space and the ownership and permissions of the data directory.",
			err
	}
	return "", "", nil
}

// probeDataDirWritable creates and removes a probe file so a full disk or a
// permissions change is detected before a real write fails.
func (s *Server) probeDataDirWritable() error {
	if s.DataDir == "" {
		return nil
	}
	probe := filepath.Join(s.DataDir, ".write-probe")
	file, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.WriteString("ok\n")
	closeErr := file.Close()
	removeErr := os.Remove(probe)
	return errors.Join(writeErr, closeErr, removeErr)
}

// MaintenanceMiddleware rejects state-changing requests with 503 while
// maintenance mode is active (AI.md PART 12 "Maintenance Mode": public API is
// read-only, writes are rejected with 503). Safe methods keep working so the
// status endpoint and every read path stay available to operators.
func (s *Server) MaintenanceMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.MaintenanceActive() || isReadOnlyMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Retry-After", "30")
		writeMaintenanceRejection(w, r)
	})
}

// isReadOnlyMethod reports whether the method is safe under RFC 9110 and so is
// still permitted while the server is read-only.
func isReadOnlyMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

// writeMaintenanceRejection emits the content-negotiated 503 body. It never
// renders a template: the maintenance path must not be able to fail for the
// same reason the server is already degraded (AI.md PART 9 guaranteed response).
// The reason string is deliberately omitted — it names internal subsystems and
// belongs in the logs and the authenticated status endpoint only.
func writeMaintenanceRejection(w http.ResponseWriter, r *http.Request) {
	if detectClientType(r) == "html" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, "<!DOCTYPE html><html><head><title>503 Maintenance Mode</title></head>"+
			"<body><h1>503</h1><p>The server is in read-only maintenance mode. "+
			"Please retry shortly.</p><a href=\"/\">Home</a></body></html>")
		return
	}
	w.Header().Set("Content-Type", jsonMediaType)
	w.WriteHeader(http.StatusServiceUnavailable)
	fmt.Fprint(w, `{"ok":false,"error":"MAINTENANCE_MODE",`+
		`"message":"Server is in read-only maintenance mode","retry_in_seconds":30}`+"\n")
}
