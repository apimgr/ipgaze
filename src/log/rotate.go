package log

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// rotatePolicy is the parsed form of a LogFileConfig.Rotate string.
// A policy may carry a time period, a size ceiling, or both — whichever
// triggers first rotates the file (AI.md PART 11 "Rotation Options").
type rotatePolicy struct {
	// period is "", "daily", "weekly", "monthly" or "yearly".
	period string
	// maxBytes is the size ceiling in bytes; 0 disables size-based rotation.
	maxBytes int64
}

// enabled reports whether the policy can ever trigger a rotation.
func (p rotatePolicy) enabled() bool {
	return p.period != "" || p.maxBytes > 0
}

// keepPolicy is the parsed form of a LogFileConfig.Keep string
// (AI.md PART 11 "Retention Options").
type keepPolicy struct {
	// mode is "none", "count", "age" or "forever".
	mode string
	// count is the number of archives to keep when mode=="count".
	count int
	// age is the maximum archive age when mode=="age".
	age time.Duration
}

// parseRotate converts a rotate string into a rotatePolicy.
// Accepted tokens, comma-separated: never, daily, weekly, monthly, yearly,
// and size ceilings such as 50MB, 1GB, 512KB. Unknown tokens are ignored so a
// typo degrades to "no rotation" rather than crashing the server at startup.
func parseRotate(s string) rotatePolicy {
	var p rotatePolicy
	for _, tok := range strings.Split(strings.ToLower(strings.TrimSpace(s)), ",") {
		tok = strings.TrimSpace(tok)
		switch tok {
		case "", "never", "none":
			continue
		case "daily", "weekly", "monthly", "yearly":
			p.period = tok
			continue
		}
		if n := parseSize(tok); n > 0 {
			p.maxBytes = n
		}
	}
	return p
}

// parseSize converts "50mb", "1gb", "512kb" or a bare byte count to bytes.
// Returns 0 when the token is not a size.
func parseSize(tok string) int64 {
	multiplier := int64(1)
	digits := tok
	switch {
	case strings.HasSuffix(tok, "kb"):
		multiplier, digits = 1024, strings.TrimSuffix(tok, "kb")
	case strings.HasSuffix(tok, "mb"):
		multiplier, digits = 1024*1024, strings.TrimSuffix(tok, "mb")
	case strings.HasSuffix(tok, "gb"):
		multiplier, digits = 1024*1024*1024, strings.TrimSuffix(tok, "gb")
	case strings.HasSuffix(tok, "b"):
		digits = strings.TrimSuffix(tok, "b")
	}
	n, err := strconv.ParseInt(strings.TrimSpace(digits), 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	return n * multiplier
}

// parseKeep converts a keep string into a keepPolicy.
// Accepted: none, forever, N (archive count), Nd, Nw, Nm (age).
// An unrecognised value is treated as "none", matching the documented default.
func parseKeep(s string) keepPolicy {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "", "none":
		return keepPolicy{mode: "none"}
	case "forever", "always":
		return keepPolicy{mode: "forever"}
	}
	unit := s[len(s)-1]
	if unit >= '0' && unit <= '9' {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return keepPolicy{mode: "none"}
		}
		if n == 0 {
			return keepPolicy{mode: "none"}
		}
		return keepPolicy{mode: "count", count: n}
	}
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil || n <= 0 {
		return keepPolicy{mode: "none"}
	}
	day := 24 * time.Hour
	switch unit {
	case 'd':
		return keepPolicy{mode: "age", age: time.Duration(n) * day}
	case 'w':
		return keepPolicy{mode: "age", age: time.Duration(n) * 7 * day}
	case 'm':
		return keepPolicy{mode: "age", age: time.Duration(n) * 30 * day}
	}
	return keepPolicy{mode: "none"}
}

// periodKey returns a string that changes exactly when the rotation period
// rolls over. An empty period yields an empty key, which never changes.
func periodKey(period string, t time.Time) string {
	switch period {
	case "daily":
		return t.Format("2006-01-02")
	case "weekly":
		y, w := t.ISOWeek()
		return fmt.Sprintf("%04d-W%02d", y, w)
	case "monthly":
		return t.Format("2006-01")
	case "yearly":
		return t.Format("2006")
	}
	return ""
}

// archiveName builds the rotated file name for filename at time t:
// "access.log" rotated on 2026-01-02 03:04:05 becomes
// "access-20260102-030405.log".
func archiveName(filename string, t time.Time) string {
	ext := filepath.Ext(filename)
	base := strings.TrimSuffix(filename, ext)
	return base + "-" + t.Format("20060102-150405") + ext
}

// archivePrefixSuffix returns the prefix and suffix that identify a rotated
// archive of filename, so pruning never touches an unrelated file.
func archivePrefixSuffix(filename string) (string, string) {
	ext := filepath.Ext(filename)
	base := strings.TrimSuffix(filename, ext)
	return base + "-", ext
}

// needsRotateLocked reports whether the next write of n bytes must be preceded
// by a rotation. The writer mutex must already be held.
func (w *writer) needsRotateLocked(now time.Time, n int64) bool {
	if w.file == nil || !w.rotate.enabled() || w.size == 0 {
		return false
	}
	if w.rotate.maxBytes > 0 && w.size+n > w.rotate.maxBytes {
		return true
	}
	if w.rotate.period != "" && periodKey(w.rotate.period, w.opened) != periodKey(w.rotate.period, now) {
		return true
	}
	return false
}

// rotateLocked closes the current file, renames it to a timestamped archive,
// reopens a fresh file at the original path, and prunes old archives.
// The writer mutex must already be held. On any failure the writer keeps
// whatever file handle it can still use so logging never stops entirely.
func (w *writer) rotateLocked(now time.Time) error {
	if w.file == nil || w.dir == "" || w.filename == "" {
		return nil
	}
	path := filepath.Join(w.dir, w.filename)
	archive := filepath.Join(w.dir, archiveName(w.filename, now))
	if err := w.file.Close(); err != nil {
		return err
	}
	w.file = nil
	if err := os.Rename(path, archive); err != nil {
		// The active file is gone or unmovable; reopen the original path so
		// subsequent writes still land somewhere rather than being dropped.
		f, openErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
		if openErr == nil {
			w.file = f
			w.size = fileSize(f)
			w.opened = now
		}
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	w.file = f
	w.size = 0
	w.opened = now
	if w.compress {
		if err := compressFile(archive); err != nil {
			return err
		}
	}
	return w.pruneLocked(now)
}

// pruneLocked deletes rotated archives that fall outside the keep policy.
// The writer mutex must already be held.
func (w *writer) pruneLocked(now time.Time) error {
	if w.keep.mode == "forever" || w.dir == "" || w.filename == "" {
		return nil
	}
	prefix, suffix := archivePrefixSuffix(w.filename)
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return err
	}
	var archives []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		if !strings.HasSuffix(name, suffix) && !strings.HasSuffix(name, suffix+".gz") {
			continue
		}
		archives = append(archives, name)
	}
	// Archive names embed a sortable timestamp, so descending lexical order is
	// newest-first without stat'ing every file.
	sort.Sort(sort.Reverse(sort.StringSlice(archives)))

	var firstErr error
	remove := func(name string) {
		if err := os.Remove(filepath.Join(w.dir, name)); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	switch w.keep.mode {
	case "count":
		for i, name := range archives {
			if i >= w.keep.count {
				remove(name)
			}
		}
	case "age":
		cutoff := now.Add(-w.keep.age)
		for _, name := range archives {
			info, err := os.Stat(filepath.Join(w.dir, name))
			if err != nil {
				continue
			}
			if info.ModTime().Before(cutoff) {
				remove(name)
			}
		}
	default:
		for _, name := range archives {
			remove(name)
		}
	}
	return firstErr
}

// rotateIfDue rotates the writer when its time period has rolled over or its
// size ceiling is already exceeded, then prunes. Used by the scheduler-facing
// Manager.Rotate so retention is enforced even on an idle server.
func (w *writer) rotateIfDue(now time.Time) error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	if w.needsRotateLocked(now, 0) {
		return w.rotateLocked(now)
	}
	return w.pruneLocked(now)
}

// compressFile gzips path in place, replacing it with path+".gz".
func compressFile(path string) error {
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()

	gzPath := path + ".gz"
	out, err := os.OpenFile(gzPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(out)
	if _, err := io.Copy(gz, in); err != nil {
		gz.Close()
		out.Close()
		os.Remove(gzPath)
		return err
	}
	if err := gz.Close(); err != nil {
		out.Close()
		os.Remove(gzPath)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(gzPath)
		return err
	}
	return os.Remove(path)
}

// fileSize returns the current size of f, or 0 when it cannot be determined.
func fileSize(f *os.File) int64 {
	info, err := f.Stat()
	if err != nil {
		return 0
	}
	return info.Size()
}
