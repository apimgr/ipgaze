package metrics

import (
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// LogEntry is one captured structured log record, already sanitized.
type LogEntry struct {
	// Time is when the record was emitted.
	Time time.Time
	// Level is the lowercase slog level name used as the Loki stream label.
	Level string
	// Line is the rendered, credential-redacted log line.
	Line string
}

// bearerPattern matches an Authorization bearer value anywhere in a rendered line.
var bearerPattern = regexp.MustCompile(`(?i)\bbearer\s+\S+`)

// sensitiveKeyParts are attribute-key fragments whose values are always redacted.
var sensitiveKeyParts = []string{
	"token",
	"password",
	"passwd",
	"secret",
	"apikey",
	"api_key",
	"credential",
	"authorization",
	"encryption_key",
	"private_key",
}

// redactedValue is the fixed replacement for any redacted credential.
const redactedValue = "xxxxx"

// isSensitiveKey reports whether an attribute key names a credential.
func isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	for _, part := range sensitiveKeyParts {
		if strings.Contains(lower, part) {
			return true
		}
	}
	return false
}

// redactLine masks bearer credentials that were embedded in free-form text.
func redactLine(line string) string {
	return bearerPattern.ReplaceAllString(line, "Bearer "+redactedValue)
}

// LogBuffer is a bounded ring of the most recent structured log records.
// It is safe for concurrent use.
type LogBuffer struct {
	mu      sync.RWMutex
	entries []LogEntry
	max     int
}

// NewLogBuffer creates a ring buffer holding at most max entries.
// A non-positive max falls back to the PART 20 default of 1000.
func NewLogBuffer(max int) *LogBuffer {
	if max <= 0 {
		max = 1000
	}
	return &LogBuffer{
		entries: make([]LogEntry, 0, max),
		max:     max,
	}
}

// Append stores one entry, evicting the oldest once the buffer is full.
func (b *LogBuffer) Append(e LogEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.entries) >= b.max {
		copy(b.entries, b.entries[len(b.entries)-b.max+1:])
		b.entries = b.entries[:b.max-1]
	}
	b.entries = append(b.entries, e)
}

// Recent returns up to limit entries no older than maxAge, oldest first.
// A non-positive limit or maxAge means "no bound from that argument".
func (b *LogBuffer) Recent(limit int, maxAge time.Duration) []LogEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()

	cutoff := time.Time{}
	if maxAge > 0 {
		cutoff = time.Now().Add(-maxAge)
	}
	out := make([]LogEntry, 0, len(b.entries))
	for _, e := range b.entries {
		if !cutoff.IsZero() && e.Time.Before(cutoff) {
			continue
		}
		out = append(out, e)
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

// Len returns the number of entries currently buffered.
func (b *LogBuffer) Len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.entries)
}

// Streams groups entries into Loki push-API streams keyed by level.
// The result is ready to be marshalled as {"streams":[...]}.
func (b *LogBuffer) Streams(entries []LogEntry, appName string) []LokiStream {
	byLevel := make(map[string][][2]string)
	for _, e := range entries {
		ts := fmt.Sprintf("%d", e.Time.UnixNano())
		byLevel[e.Level] = append(byLevel[e.Level], [2]string{ts, e.Line})
	}
	levels := make([]string, 0, len(byLevel))
	for level := range byLevel {
		levels = append(levels, level)
	}
	sort.Strings(levels)

	streams := make([]LokiStream, 0, len(levels))
	for _, level := range levels {
		streams = append(streams, LokiStream{
			Stream: map[string]string{"app": appName, "level": level},
			Values: byLevel[level],
		})
	}
	return streams
}

// LokiStream is one labelled stream in a Loki push-API payload.
type LokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][2]string       `json:"values"`
}

// LokiPayload is the top-level Loki push-API document.
type LokiPayload struct {
	Streams []LokiStream `json:"streams"`
}

// Record sanitizes and stores one log line built from a level, a message, and
// optional structured attributes.
func (b *LogBuffer) Record(level, msg string, attrs ...slog.Attr) {
	parts := make([]string, 0, len(attrs)+1)
	parts = append(parts, redactLine(msg))
	for _, a := range attrs {
		parts = append(parts, formatAttr(a))
	}
	b.Append(LogEntry{
		Time:  time.Now(),
		Level: strings.ToLower(level),
		Line:  strings.Join(parts, " "),
	})
}

// formatAttr renders one attribute as key=value, redacting credential values.
func formatAttr(a slog.Attr) string {
	if isSensitiveKey(a.Key) {
		return a.Key + "=" + redactedValue
	}
	return a.Key + "=" + redactLine(a.Value.String())
}

// defaultLogBuffer is the process-wide buffer served by the loki endpoint.
var (
	defaultLogBuffer     *LogBuffer
	defaultLogBufferOnce sync.Once
)

// DefaultLogBuffer returns the process-wide recent-log ring buffer, creating it
// with the given capacity on first call. Later calls return the same buffer and
// ignore max, so every writer and the loki endpoint share one bounded window.
func DefaultLogBuffer(max int) *LogBuffer {
	defaultLogBufferOnce.Do(func() {
		defaultLogBuffer = NewLogBuffer(max)
	})
	return defaultLogBuffer
}
