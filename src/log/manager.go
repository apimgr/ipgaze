// Package log provides a multi-file log manager per AI.md PART 11.
// Each log category writes to its own file with a configurable format,
// rotation policy and retention policy. All file writes are goroutine-safe.
package log

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// LogFileConfig configures a single log file.
type LogFileConfig struct {
	// Enabled controls whether this log file is written (true by default).
	Enabled bool `yaml:"enabled"`
	// Filename is the base file name (e.g. "access.log"). Resolved relative to logDir.
	Filename string `yaml:"filename"`
	// Format is the output format (varies by log type).
	Format string `yaml:"format"`
	// Custom is the custom format string when Format=="custom".
	Custom string `yaml:"custom"`
	// Rotate is the rotation policy: "daily", "weekly", "monthly", "NMB", combined.
	Rotate string `yaml:"rotate"`
	// Keep is the retention policy: "none", "N", "Nd", "Nw", "Nm", "forever".
	Keep string `yaml:"keep"`
}

// AuditEventFilter configures which event categories appear in audit.log.
type AuditEventFilter struct {
	Configuration bool `yaml:"configuration"`
	Security      bool `yaml:"security"`
	Backup        bool `yaml:"backup"`
	Server        bool `yaml:"server"`
}

// AuditLogConfig extends LogFileConfig with audit-specific options.
type AuditLogConfig struct {
	LogFileConfig    `yaml:",inline"`
	Compress         bool             `yaml:"compress"`
	Events           AuditEventFilter `yaml:"events"`
	IncludeUserAgent bool             `yaml:"include_user_agent"`
}

// AuditEvent is the canonical structured event written to audit.log per AI.md PART 11.
type AuditEvent struct {
	ID       string         `json:"id"`
	Time     string         `json:"time"`
	Event    string         `json:"event"`
	Category string         `json:"category"`
	Severity string         `json:"severity"`
	Actor    AuditActor     `json:"actor"`
	Target   *AuditTarget   `json:"target,omitempty"`
	Details  map[string]any `json:"details,omitempty"`
	Result   string         `json:"result"`
	Reason   string         `json:"reason,omitempty"`
}

// AuditActor describes who performed the audited action.
type AuditActor struct {
	IP        string `json:"ip,omitempty"`
	UserID    string `json:"user_id,omitempty"`
	TokenHash string `json:"token_hash,omitempty"`
}

// AuditTarget describes what was acted upon.
type AuditTarget struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// AccessEntry carries the fields of one HTTP request for access.log.
// The caller is responsible for sanitizing client-supplied values before
// handing them over; the writer sanitizes the assembled line as well.
type AccessEntry struct {
	IP        string
	Method    string
	Path      string
	Proto     string
	Status    int
	Bytes     int
	Referer   string
	UserAgent string
	RequestID string
}

// writer is a thread-safe, self-rotating log file writer.
type writer struct {
	mu   sync.Mutex
	file *os.File
	// dir and filename locate the active file so it can be renamed on rotation.
	dir      string
	filename string
	// format is the resolved output format for this file.
	format string
	// size tracks the active file's byte count for size-based rotation.
	size int64
	// opened anchors the current rotation period.
	opened time.Time
	// rotate and keep are the parsed rotation and retention policies.
	rotate rotatePolicy
	keep   keepPolicy
	// compress gzips each archive immediately after rotation.
	compress bool
}

// write appends line (with newline) to the file, rotating first when the
// configured policy is due. Empty lines are dropped so a formatting failure
// never produces a blank record.
func (w *writer) write(line string) {
	if w == nil || w.file == nil {
		return
	}
	line = sanitizeLine(line)
	if line == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	now := time.Now()
	n := int64(len(line)) + 1
	if w.needsRotateLocked(now, n) {
		// A rotation failure must not silence logging: rotateLocked always
		// leaves a usable handle when it can, so the write still proceeds.
		_ = w.rotateLocked(now)
	}
	if w.file == nil {
		return
	}
	written, err := fmt.Fprintln(w.file, line)
	if err == nil {
		w.size += int64(written)
	}
}

// close closes the underlying file.
func (w *writer) close() {
	if w == nil || w.file == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	_ = w.file.Close()
	w.file = nil
}

// Manager writes to multiple per-category log files.
// A nil *Manager is safe to use — all writes become no-ops.
type Manager struct {
	logDir string
	// program is the process name used in syslog and CEF records.
	program string
	// version is the product version used in CEF records.
	version  string
	access   *writer
	server   *writer
	errLog   *writer
	app      *writer
	auth     *writer
	audit    *writer
	security *writer
	debug    *writer
}

// openWriter opens (or creates) a log file in logDir and returns a
// thread-safe, self-rotating writer. Returns a silent no-op writer when the
// log file is disabled or unnamed.
func openWriter(logDir string, cfg LogFileConfig, defaultFormat string, compress bool) (*writer, error) {
	w := &writer{format: resolveFormat(cfg.Format, defaultFormat)}
	if !cfg.Enabled || logDir == "" || cfg.Filename == "" {
		return w, nil
	}
	if err := os.MkdirAll(logDir, 0o750); err != nil {
		return nil, fmt.Errorf("log: mkdir %s: %w", logDir, err)
	}
	path := filepath.Join(logDir, cfg.Filename)
	// O_APPEND + O_CREATE is the only safe combination for append-only logs.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return nil, fmt.Errorf("log: open %s: %w", path, err)
	}
	w.file = f
	w.dir = logDir
	w.filename = cfg.Filename
	w.rotate = parseRotate(cfg.Rotate)
	w.keep = parseKeep(cfg.Keep)
	w.compress = compress
	w.size = fileSize(f)
	// Anchor the rotation period to the file's own mtime so a restart does not
	// reset a period that already rolled over while the process was down.
	w.opened = time.Now()
	if info, statErr := f.Stat(); statErr == nil && w.size > 0 {
		w.opened = info.ModTime()
	}
	return w, nil
}

// Config holds per-file config for all log types.
type Config struct {
	Level string
	// Program is the process name recorded in syslog and CEF lines.
	Program string
	// Version is the product version recorded in CEF lines.
	Version  string
	Access   LogFileConfig
	Server   LogFileConfig
	Error    LogFileConfig
	App      LogFileConfig
	Auth     LogFileConfig
	Audit    AuditLogConfig
	Security LogFileConfig
	Debug    LogFileConfig
}

// DefaultConfig returns a Config with sane defaults per AI.md PART 11.
func DefaultConfig() Config {
	return Config{
		Level:   "warn",
		Program: "ipgaze",
		Access: LogFileConfig{
			Enabled:  true,
			Filename: "access.log",
			Format:   "apache",
			Rotate:   "monthly",
			Keep:     "none",
		},
		Server: LogFileConfig{
			Enabled:  true,
			Filename: "server.log",
			Format:   "text",
			Rotate:   "weekly,50MB",
			Keep:     "none",
		},
		Error: LogFileConfig{
			Enabled:  true,
			Filename: "error.log",
			Format:   "text",
			Rotate:   "weekly,50MB",
			Keep:     "none",
		},
		App: LogFileConfig{
			Enabled:  true,
			Filename: "app.log",
			Format:   "logfmt",
			Rotate:   "weekly,50MB",
			Keep:     "none",
		},
		Auth: LogFileConfig{
			Enabled:  true,
			Filename: "auth.log",
			Format:   "syslog",
			Rotate:   "weekly,50MB",
			Keep:     "none",
		},
		Audit: AuditLogConfig{
			LogFileConfig: LogFileConfig{
				Enabled:  true,
				Filename: "audit.log",
				Format:   "json",
				Rotate:   "daily",
				Keep:     "none",
			},
			Events: AuditEventFilter{
				Configuration: true,
				Security:      true,
				Backup:        true,
				Server:        true,
			},
			IncludeUserAgent: true,
		},
		Security: LogFileConfig{
			Enabled:  true,
			Filename: "security.log",
			Format:   "fail2ban",
			Rotate:   "weekly,50MB",
			Keep:     "none",
		},
		Debug: LogFileConfig{
			Enabled:  false,
			Filename: "debug.log",
			Format:   "text",
			Rotate:   "weekly,50MB",
			Keep:     "none",
		},
	}
}

// NewManager opens all configured log files under logDir.
// logDir must be the resolved, absolute log directory path.
func NewManager(logDir string, cfg Config) (*Manager, error) {
	program := cfg.Program
	if program == "" {
		program = "ipgaze"
	}
	m := &Manager{logDir: logDir, program: program, version: cfg.Version}
	var err error

	if m.access, err = openWriter(logDir, cfg.Access, "apache", false); err != nil {
		return nil, err
	}
	if m.server, err = openWriter(logDir, cfg.Server, "text", false); err != nil {
		return nil, err
	}
	if m.errLog, err = openWriter(logDir, cfg.Error, "text", false); err != nil {
		return nil, err
	}
	if m.app, err = openWriter(logDir, cfg.App, "logfmt", false); err != nil {
		return nil, err
	}
	if m.auth, err = openWriter(logDir, cfg.Auth, "syslog", false); err != nil {
		return nil, err
	}
	if m.audit, err = openWriter(logDir, cfg.Audit.LogFileConfig, "json", cfg.Audit.Compress); err != nil {
		return nil, err
	}
	if m.security, err = openWriter(logDir, cfg.Security, "fail2ban", false); err != nil {
		return nil, err
	}
	if m.debug, err = openWriter(logDir, cfg.Debug, "text", false); err != nil {
		return nil, err
	}
	return m, nil
}

// Close flushes and closes all open log files.
func (m *Manager) Close() {
	if m == nil {
		return
	}
	m.access.close()
	m.server.close()
	m.errLog.close()
	m.app.close()
	m.auth.close()
	m.audit.close()
	m.security.close()
	m.debug.close()
}

// Rotate rotates every log file whose policy is due and prunes archives that
// fall outside its retention policy. This is the entry point for the
// scheduler's log_rotation task; rotation also happens lazily on write, so
// calling this on an idle server only enforces retention.
// Returns the first error encountered; remaining files are still processed.
func (m *Manager) Rotate() error {
	if m == nil {
		return nil
	}
	now := time.Now()
	var firstErr error
	for _, w := range []*writer{m.access, m.server, m.errLog, m.app, m.auth, m.audit, m.security, m.debug} {
		if err := w.rotateIfDue(now); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// WriteAccess writes one pre-formatted line to access.log verbatim.
// Callers that have the individual request fields should use WriteAccessRequest
// so the operator's configured format is honoured.
func (m *Manager) WriteAccess(line string) {
	if m == nil {
		return
	}
	m.access.write(line)
}

// WriteAccessRequest writes one request to access.log in the configured
// format: apache (Combined, default), nginx (Common) or json.
func (m *Manager) WriteAccessRequest(e AccessEntry) {
	if m == nil || m.access == nil {
		return
	}
	if e.Referer == "" {
		e.Referer = "-"
	}
	if e.UserAgent == "" {
		e.UserAgent = "-"
	}
	now := time.Now()
	switch m.access.format {
	case "nginx":
		m.access.write(nginxAccessLine(now, e))
	case "json":
		m.access.write(jsonAccessLine(now, e))
	default:
		m.access.write(apacheAccessLine(now, e))
	}
}

// WriteServer writes one application event to server.log as text or json.
func (m *Manager) WriteServer(level, message string) {
	if m == nil {
		return
	}
	m.writeLeveled(m.server, level, message)
}

// WriteError writes one error event to error.log as text or json.
func (m *Manager) WriteError(level, message string) {
	if m == nil {
		return
	}
	m.writeLeveled(m.errLog, level, message)
}

// WriteDebug writes one debug event to debug.log as text or json.
// No-op when the debug log file is not enabled.
func (m *Manager) WriteDebug(message string) {
	if m == nil {
		return
	}
	m.writeLeveled(m.debug, "DEBUG", message)
}

// writeLeveled renders a level+message record in w's text or json format.
func (m *Manager) writeLeveled(w *writer, level, message string) {
	if w == nil {
		return
	}
	now := time.Now()
	if w.format == "json" {
		w.write(jsonLine(map[string]any{
			"time":  now.UTC().Format(time.RFC3339),
			"level": level,
			"msg":   message,
		}))
		return
	}
	w.write(textLine(now, level, message))
}

// WriteApp writes one general application event to app.log in logfmt or json.
// The kvpairs slice must be alternating key, value strings.
// Example: WriteApp("INFO", "user created", "id", "abc123", "ip", "1.2.3.4")
func (m *Manager) WriteApp(level, msg string, kvpairs ...string) {
	if m == nil || m.app == nil {
		return
	}
	now := time.Now()
	if m.app.format == "json" {
		fields := kvMap(kvpairs)
		fields["time"] = now.UTC().Format(time.RFC3339)
		fields["level"] = level
		fields["msg"] = msg
		m.app.write(jsonLine(fields))
		return
	}
	m.app.write(logfmtLine(now, level, msg, kvpairs))
}

// WriteAuth writes one authentication event to auth.log in syslog (RFC 3164)
// or json format. The kvpairs slice must be alternating key, value strings.
// Example: WriteAuth("ipgaze", 1234, "user", "bob", "result", "fail", "reason", "invalid_token")
func (m *Manager) WriteAuth(program string, pid int, kvpairs ...string) {
	if m == nil || m.auth == nil {
		return
	}
	if program == "" {
		program = m.program
	}
	now := time.Now()
	if m.auth.format == "json" {
		fields := kvMap(kvpairs)
		fields["time"] = now.UTC().Format(time.RFC3339)
		fields["program"] = program
		fields["pid"] = pid
		m.auth.write(jsonLine(fields))
		return
	}
	m.auth.write(syslog3164Line(now, hostname(), program, pid, "auth: "+kvJoin(kvpairs)))
}

// WriteAuthFailure records a failed authentication attempt in auth.log.
// reason must be a stable machine code, never a free-form message, so
// Fail2ban and SIEM parsers stay stable (AI.md PART 11).
func (m *Manager) WriteAuthFailure(ip, endpoint, reason string) {
	if m == nil {
		return
	}
	m.WriteAuth("", os.Getpid(), "ip", ip, "endpoint", endpoint, "result", "fail", "reason", reason)
}

// WriteAudit writes a structured JSON event to audit.log (JSON Lines format).
// The event ID should be a ULID; Time is set to UTC now if empty.
func (m *Manager) WriteAudit(evt AuditEvent) {
	if m == nil {
		return
	}
	if evt.ID == "" {
		evt.ID = NewAuditID()
	}
	if evt.Time == "" {
		evt.Time = time.Now().UTC().Format(time.RFC3339Nano)
	}
	b, err := json.Marshal(evt)
	if err != nil {
		return
	}
	m.audit.write(string(b))
}

// WriteAuditEvent is a convenience wrapper that fills required fields.
func (m *Manager) WriteAuditEvent(id, event, category, severity, result, ip string, details map[string]any) {
	if m == nil {
		return
	}
	m.WriteAudit(AuditEvent{
		ID:       id,
		Time:     time.Now().UTC().Format(time.RFC3339Nano),
		Event:    event,
		Category: category,
		Severity: severity,
		Actor:    AuditActor{IP: ip},
		Details:  details,
		Result:   result,
	})
}

// WriteSecurity writes one security event to security.log in the configured
// format: fail2ban (default), syslog (RFC 5424), cef, json or text.
// message must be a short, stable phrase — Fail2ban filters match on it.
func (m *Manager) WriteSecurity(message, ip string) {
	if m == nil || m.security == nil {
		return
	}
	now := time.Now()
	switch m.security.format {
	case "syslog":
		m.security.write(syslog5424Line(now, hostname(), m.program, os.Getpid(),
			"security: "+message+" from "+ip))
	case "cef":
		m.security.write(cefLine("CasjaysDev", m.program, m.version, "security", message, 5, "src="+ip))
	case "json":
		m.security.write(jsonLine(map[string]any{
			"time":  now.UTC().Format(time.RFC3339),
			"level": "SECURITY",
			"msg":   message,
			"ip":    ip,
		}))
	case "text":
		m.security.write(textLine(now, "SECURITY", message+" from "+ip))
	default:
		m.security.write(fmt.Sprintf("%s [security] %s from %s", now.Format(time.RFC3339), message, ip))
	}
}

// hostname returns the local hostname, or "localhost" when unavailable.
func hostname() string {
	h, _ := os.Hostname()
	if h == "" {
		return "localhost"
	}
	return h
}
