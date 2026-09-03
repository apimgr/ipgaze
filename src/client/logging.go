// Package main client logging subsystem (AI.md PART 32 "logging" section of
// cli.yml). Writes cli.log at 0600 with size-based rotation.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apimgr/ipgaze/src/client/setup"
)

// Log levels ordered from most to least verbose.
const (
	logLevelDebug = iota
	logLevelInfo
	logLevelWarn
	logLevelError
)

// logLevelNames maps a configured level name to its numeric severity.
var logLevelNames = map[string]int{
	"debug": logLevelDebug,
	"info":  logLevelInfo,
	"warn":  logLevelWarn,
	"error": logLevelError,
}

// clientLogger writes leveled messages to the CLI log file. A nil logger is a
// valid no-op, so callers never need a nil check.
type clientLogger struct {
	mu       sync.Mutex
	path     string
	minLevel int
	maxSize  int64
	maxFiles int
}

// parseLogSize converts a human size such as "10MB" or "512KB" to bytes.
// An unparsable value falls back to 10 MB.
func parseLogSize(value string) int64 {
	const fallback = 10 * 1024 * 1024

	trimmed := strings.TrimSpace(strings.ToUpper(value))
	multiplier := int64(1)
	switch {
	case strings.HasSuffix(trimmed, "GB"):
		multiplier, trimmed = 1024*1024*1024, strings.TrimSuffix(trimmed, "GB")
	case strings.HasSuffix(trimmed, "MB"):
		multiplier, trimmed = 1024*1024, strings.TrimSuffix(trimmed, "MB")
	case strings.HasSuffix(trimmed, "KB"):
		multiplier, trimmed = 1024, strings.TrimSuffix(trimmed, "KB")
	case strings.HasSuffix(trimmed, "B"):
		trimmed = strings.TrimSuffix(trimmed, "B")
	}

	n, err := strconv.ParseInt(strings.TrimSpace(trimmed), 10, 64)
	if err != nil || n <= 0 {
		return fallback
	}
	return n * multiplier
}

// newClientLogger builds a logger from the cli.yml logging section. It returns
// nil when the log directory cannot be created, so logging never blocks the
// CLI's real work.
func newClientLogger(cfg *setup.CLIConfig, forceDebug bool) *clientLogger {
	if cfg == nil {
		cfg = &setup.CLIConfig{}
	}

	level, ok := logLevelNames[strings.ToLower(cfg.LogLevel())]
	if !ok {
		level = logLevelWarn
	}
	if forceDebug {
		level = logLevelDebug
	}

	path := cfg.LogFilePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil
	}

	return &clientLogger{
		path:     path,
		minLevel: level,
		maxSize:  parseLogSize(cfg.LogMaxSize()),
		maxFiles: cfg.LogMaxFiles(),
	}
}

// rotate renames cli.log to cli.log.1 (shifting older files up) once it grows
// past maxSize, discarding anything beyond maxFiles. The caller holds the lock.
func (l *clientLogger) rotate() {
	info, err := os.Stat(l.path)
	if err != nil || info.Size() < l.maxSize {
		return
	}

	oldest := fmt.Sprintf("%s.%d", l.path, l.maxFiles)
	_ = os.Remove(oldest)

	for i := l.maxFiles - 1; i >= 1; i-- {
		from := fmt.Sprintf("%s.%d", l.path, i)
		if _, statErr := os.Stat(from); statErr != nil {
			continue
		}
		_ = os.Rename(from, fmt.Sprintf("%s.%d", l.path, i+1))
	}
	_ = os.Rename(l.path, l.path+".1")
}

// write appends one formatted line at the given level.
func (l *clientLogger) write(level int, levelName, format string, args ...any) {
	if l == nil || level < l.minLevel {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.rotate()

	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()

	if err := setFilePermissions(l.path); err != nil {
		return
	}

	line := fmt.Sprintf("%s %-5s %s\n",
		time.Now().UTC().Format(time.RFC3339),
		strings.ToUpper(levelName),
		fmt.Sprintf(format, args...),
	)
	_, _ = f.WriteString(line)
}

// Debug logs a debug-level message.
func (l *clientLogger) Debug(format string, args ...any) {
	l.write(logLevelDebug, "debug", format, args...)
}

// Info logs an info-level message.
func (l *clientLogger) Info(format string, args ...any) {
	l.write(logLevelInfo, "info", format, args...)
}

// Warn logs a warning-level message.
func (l *clientLogger) Warn(format string, args ...any) {
	l.write(logLevelWarn, "warn", format, args...)
}

// Error logs an error-level message.
func (l *clientLogger) Error(format string, args ...any) {
	l.write(logLevelError, "error", format, args...)
}
