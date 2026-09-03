package log

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// sanitizeLine strips CR/LF and other control characters from a fully
// formatted log line. Every log file is "raw text only, one event per line"
// (AI.md PART 11), and a client-supplied value that slipped through an earlier
// sanitizer must never be able to forge an extra line here.
func sanitizeLine(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\n' || r == '\r' || (r < 0x20 && r != '\t') || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// resolveFormat lowercases the configured format, falling back to def when the
// operator left it empty.
func resolveFormat(configured, def string) string {
	f := strings.ToLower(strings.TrimSpace(configured))
	if f == "" {
		return def
	}
	return f
}

// jsonLine marshals fields as a single JSON object line. Marshalling a
// map[string]any of strings/ints never fails, so an error yields an empty
// string the caller skips.
func jsonLine(fields map[string]any) string {
	b, err := json.Marshal(fields)
	if err != nil {
		return ""
	}
	return string(b)
}

// textLine renders the canonical text log line: RFC 3339 time, bracketed
// level, message.
func textLine(now time.Time, level, msg string) string {
	return fmt.Sprintf("%s [%s] %s", now.Format(time.RFC3339), level, msg)
}

// logfmtLine renders a logfmt line: time, level, msg, then the caller's
// alternating key/value pairs. Values containing spaces or "=" are quoted.
func logfmtLine(now time.Time, level, msg string, kvpairs []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "time=%s level=%s msg=%q", now.Format(time.RFC3339), level, msg)
	for i := 0; i+1 < len(kvpairs); i += 2 {
		k, v := kvpairs[i], kvpairs[i+1]
		if needsQuote(v) {
			fmt.Fprintf(&b, " %s=%q", k, v)
		} else {
			fmt.Fprintf(&b, " %s=%s", k, v)
		}
	}
	return b.String()
}

// needsQuote returns true when v contains spaces or special characters.
func needsQuote(v string) bool {
	if v == "" {
		return true
	}
	for _, c := range v {
		if c == ' ' || c == '=' || c == '"' || c == '\n' || c == '\t' {
			return true
		}
	}
	return false
}

// kvJoin joins alternating key/value pairs into "k=v k=v".
func kvJoin(kvpairs []string) string {
	var b strings.Builder
	for i := 0; i+1 < len(kvpairs); i += 2 {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(kvpairs[i])
		b.WriteByte('=')
		b.WriteString(kvpairs[i+1])
	}
	return b.String()
}

// kvMap converts alternating key/value pairs into a map for JSON output.
func kvMap(kvpairs []string) map[string]any {
	m := make(map[string]any, len(kvpairs)/2)
	for i := 0; i+1 < len(kvpairs); i += 2 {
		m[kvpairs[i]] = kvpairs[i+1]
	}
	return m
}

// syslog3164Line renders an RFC 3164 syslog line:
// "Jan  2 15:04:05 hostname program[pid]: message".
func syslog3164Line(now time.Time, hostname, program string, pid int, msg string) string {
	return fmt.Sprintf("%s %s %s[%d]: %s", now.Format("Jan _2 15:04:05"), hostname, program, pid, msg)
}

// syslog5424Line renders an RFC 5424 syslog line. Priority 134 is
// facility 16 (local0) with severity 6 (informational), the conventional
// value for application security events shipped to a SIEM.
func syslog5424Line(now time.Time, hostname, program string, pid int, msg string) string {
	return fmt.Sprintf("<134>1 %s %s %s %d - - %s",
		now.Format(time.RFC3339), hostname, program, pid, msg)
}

// cefEscapeHeader escapes the CEF header field separator and backslashes.
func cefEscapeHeader(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, "|", `\|`)
}

// cefLine renders a Common Event Format line for SIEM ingestion.
// Severity 5 is CEF's mid-scale value, the correct default for a
// single blocked request that is suspicious but not confirmed malicious.
func cefLine(vendor, product, version, eventClass, name string, severity int, extension string) string {
	return fmt.Sprintf("CEF:0|%s|%s|%s|%s|%s|%d|%s",
		cefEscapeHeader(vendor), cefEscapeHeader(product), cefEscapeHeader(version),
		cefEscapeHeader(eventClass), cefEscapeHeader(name), severity, extension)
}

// apacheAccessLine renders an Apache Combined Log Format line with the
// request ID appended.
func apacheAccessLine(now time.Time, e AccessEntry) string {
	return fmt.Sprintf(`%s - - %s "%s %s %s" %d %d "%s" "%s" %s`,
		e.IP, now.Format("[02/Jan/2006:15:04:05 -0700]"), e.Method, e.Path, e.Proto,
		e.Status, e.Bytes, e.Referer, e.UserAgent, e.RequestID)
}

// nginxAccessLine renders an Nginx Common Log Format line (no referer/agent).
func nginxAccessLine(now time.Time, e AccessEntry) string {
	return fmt.Sprintf(`%s - - %s "%s %s %s" %d %d`,
		e.IP, now.Format("[02/Jan/2006:15:04:05 -0700]"), e.Method, e.Path, e.Proto,
		e.Status, e.Bytes)
}

// jsonAccessLine renders the structured JSON access line from AI.md PART 11.
func jsonAccessLine(now time.Time, e AccessEntry) string {
	return jsonLine(map[string]any{
		"ip":     e.IP,
		"time":   now.UTC().Format(time.RFC3339),
		"method": e.Method,
		"path":   e.Path,
		"status": e.Status,
		"size":   e.Bytes,
		"ua":     e.UserAgent,
	})
}
