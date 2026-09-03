package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/email"
	applog "github.com/apimgr/ipgaze/src/log"
)

// backupFullFileRe matches the timestamped full-backup filenames produced by
// both scheduled ("_YYYY-MM-DD") and manual/CLI ("_YYYY-MM-DD_HHMMSS") backups
// per AI.md PART 21. The always-replaced ipgaze-daily.tar.gz / ipgaze-hourly.tar.gz
// incrementals are excluded — they are not subject to retention.
var backupFullFileRe = regexp.MustCompile(`^ipgaze_backup_\d{4}-\d{2}-\d{2}(_\d{6})?\.tar\.gz(\.enc)?$`)

type backupFileInfo struct {
	path string
	name string
	mod  time.Time
	size int64
}

// listFullBackups returns the timestamped full backups in backupDir, newest first.
func listFullBackups(backupDir string) ([]backupFileInfo, error) {
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []backupFileInfo
	for _, e := range entries {
		if e.IsDir() || !backupFullFileRe.MatchString(e.Name()) {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		out = append(out, backupFileInfo{
			path: filepath.Join(backupDir, e.Name()),
			name: e.Name(),
			mod:  info.ModTime(),
			size: info.Size(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].mod.After(out[j].mod) })
	return out, nil
}

// isFalseyRetentionValue implements AI.md PART 21's "falsey values" table for
// disabling max_total_size: 0, false, no, none, disable, disabled, off.
func isFalseyRetentionValue(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "0", "false", "no", "none", "disable", "disabled", "off", "":
		return true
	}
	return false
}

// parseByteSize parses sizes like "500M", "10G", "1T", or a plain byte count.
func parseByteSize(s string) (int64, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "T"):
		mult = 1 << 40
		s = strings.TrimSuffix(s, "T")
	case strings.HasSuffix(s, "G"):
		mult = 1 << 30
		s = strings.TrimSuffix(s, "G")
	case strings.HasSuffix(s, "M"):
		mult = 1 << 20
		s = strings.TrimSuffix(s, "M")
	case strings.HasSuffix(s, "K"):
		mult = 1 << 10
		s = strings.TrimSuffix(s, "K")
	case strings.HasSuffix(s, "B"):
		s = strings.TrimSuffix(s, "B")
	}
	n, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: %w", s, err)
	}
	return int64(n * float64(mult)), nil
}

// backupDirSize returns the total size in bytes of all files under dir.
func backupDirSize(dir string) (int64, error) {
	var total int64
	err := filepath.Walk(dir, func(_ string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			if os.IsNotExist(walkErr) {
				return nil
			}
			return walkErr
		}
		if !fi.IsDir() {
			total += fi.Size()
		}
		return nil
	})
	if os.IsNotExist(err) {
		return 0, nil
	}
	return total, err
}

// parseBackupSizeCap resolves retention.max_total_size ("10%", "50G", "0", …)
// to an absolute byte cap. ok=false means the cap is disabled.
func parseBackupSizeCap(spec, backupDir string) (capBytes int64, ok bool, err error) {
	if isFalseyRetentionValue(spec) {
		return 0, false, nil
	}
	trimmed := strings.TrimSpace(spec)
	if strings.HasSuffix(trimmed, "%") {
		pct, perr := strconv.ParseFloat(strings.TrimSuffix(trimmed, "%"), 64)
		if perr != nil || pct <= 0 {
			return 0, false, fmt.Errorf("invalid max_total_size percentage %q", spec)
		}
		free, _, dsErr := diskFreeAndUsedPercent(backupDir)
		if dsErr != nil {
			return 0, false, dsErr
		}
		used, sizeErr := backupDirSize(backupDir)
		if sizeErr != nil {
			return 0, false, sizeErr
		}
		// Approximate volume total as free + currently used backup size; this
		// is a soft cap and does not require statfs's raw block-total field.
		volumeTotal := free + uint64(used)
		return int64(float64(volumeTotal) * pct / 100.0), true, nil
	}
	n, perr := parseByteSize(trimmed)
	if perr != nil {
		return 0, false, perr
	}
	if n <= 0 {
		return 0, false, nil
	}
	return n, true, nil
}

// keepPeriodic marks up to n of fulls (in newest-first order) as kept, where
// matches(f.mod) is true — used for weekly/monthly/yearly retention buckets.
func keepPeriodic(fulls []backupFileInfo, keep map[string]bool, n int, matches func(time.Time) bool) {
	if n <= 0 {
		return
	}
	kept := 0
	for _, f := range fulls {
		if !matches(f.mod) {
			continue
		}
		keep[f.path] = true
		kept++
		if kept >= n {
			return
		}
	}
}

// applyBackupRetention enforces AI.md PART 21's backup retention policy
// (max_backups, keep_weekly, keep_monthly, keep_yearly, max_total_size) on
// the timestamped full backups in backupDir. Only called after a successful
// backup creation + verification (PART 21 Backup Creation Flow step 7).
func applyBackupRetention(backupDir string, retention config.BackupRetentionConfig, logMgr *applog.Manager) {
	fulls, err := listFullBackups(backupDir)
	if err != nil {
		log.Printf("backup retention: list backups: %v", err)
		return
	}
	if len(fulls) == 0 {
		return
	}

	maxBackups := retention.MaxBackups
	if maxBackups < 1 {
		maxBackups = 1
	}

	keep := make(map[string]bool, len(fulls))
	for i, f := range fulls {
		if i < maxBackups {
			keep[f.path] = true
		}
	}
	keepPeriodic(fulls, keep, retention.KeepWeekly, func(t time.Time) bool { return t.Weekday() == time.Sunday })
	keepPeriodic(fulls, keep, retention.KeepMonthly, func(t time.Time) bool { return t.Day() == 1 })
	keepPeriodic(fulls, keep, retention.KeepYearly, func(t time.Time) bool { return t.YearDay() == 1 })

	var deleted []string
	for _, f := range fulls {
		if keep[f.path] {
			continue
		}
		if rmErr := os.Remove(f.path); rmErr != nil {
			log.Printf("backup retention: remove %s: %v", f.path, rmErr)
			continue
		}
		deleted = append(deleted, f.name)
	}

	// Hard size cap overrides count-based retention: delete oldest kept
	// backups until under cap, always leaving at least one backup.
	if cap, ok, capErr := parseBackupSizeCap(retention.MaxTotalSize, backupDir); capErr != nil {
		log.Printf("backup retention: max_total_size: %v", capErr)
	} else if ok {
		remaining, lerr := listFullBackups(backupDir)
		if lerr == nil {
			var total int64
			for _, f := range remaining {
				total += f.size
			}
			for i := len(remaining) - 1; i >= 0 && total > cap && len(remaining) > 1; i-- {
				f := remaining[i]
				if rmErr := os.Remove(f.path); rmErr != nil {
					continue
				}
				total -= f.size
				deleted = append(deleted, f.name)
				remaining = remaining[:i]
			}
		}
	}

	if len(deleted) > 0 {
		log.Printf("backup retention: deleted %d old backup(s): %s", len(deleted), strings.Join(deleted, ", "))
		if logMgr != nil {
			// AI.md PART 21 requires a per-file backup.deleted event in addition
			// to the aggregate retention_cleanup summary.
			for _, name := range deleted {
				logMgr.WriteAuditEvent("", "backup.deleted", "backup", "info", "success", "", map[string]any{
					"filename": name,
					"reason":   "retention",
				})
			}
			remaining, _ := listFullBackups(backupDir)
			logMgr.WriteAuditEvent("", "backup.retention_cleanup", "backup", "info", "success", "", map[string]any{
				"deleted":   deleted,
				"remaining": len(remaining),
			})
		}
	}
}

// backupDiskSpaceExceeded implements AI.md PART 21 Backup Creation Flow step 2:
// check free disk space before creating a backup. Returns skip=true with a
// human-readable reason (and writes a backup.skipped_disk_full audit event)
// when disk usage exceeds thresholdPercent, or when there isn't roughly
// enough free space to hold another backup the size of the most recent one.
// Platforms without a statfs-style syscall (see disk_space_other.go) always
// return skip=false — the check degrades gracefully rather than blocking backups.
func backupDiskSpaceExceeded(backupDir string, thresholdPercent int, logMgr *applog.Manager) (bool, string) {
	free, usedPercent, err := diskFreeAndUsedPercent(backupDir)
	if err != nil {
		// Free-space check unavailable on this platform/filesystem: don't block backups.
		return false, ""
	}
	threshold := thresholdPercent
	if threshold <= 0 || threshold > 100 {
		threshold = 90
	}

	var mostRecentSize int64
	if fulls, lerr := listFullBackups(backupDir); lerr == nil && len(fulls) > 0 {
		mostRecentSize = fulls[0].size
	}
	insufficientFree := mostRecentSize > 0 && free < uint64(2*mostRecentSize)

	if !insufficientFree && usedPercent <= threshold {
		return false, ""
	}

	reason := fmt.Sprintf("disk usage %d%% exceeds threshold %d%% (free=%d bytes)", usedPercent, threshold, free)
	if logMgr != nil {
		logMgr.WriteAuditEvent("", "backup.skipped_disk_full", "backup", "error", "failure", "", map[string]any{
			"free_bytes":         free,
			"disk_usage_percent": usedPercent,
			"threshold_percent":  threshold,
		})
	}
	return true, reason
}

// formatByteSize renders a byte count as a human-readable string (e.g. "4.2 MB").
func formatByteSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// notifyBackupComplete sends the AI.md PART 17 backup_complete email when the
// backup_complete event is enabled. backupFile must exist on disk so its size
// can be read; failures to stat it are logged but never block the caller.
func notifyBackupComplete(cfg *config.AppConfig, emailMgr *email.EmailManager, projectName, backupFile string) {
	if emailMgr == nil || !emailMgr.IsEnabled() || !cfg.Server.Notifications.Email.Events.BackupComplete {
		return
	}
	size := ""
	if info, err := os.Stat(backupFile); err == nil {
		size = formatByteSize(info.Size())
	}
	sendOperatorEmail(cfg, emailMgr, "backup_complete", map[string]string{
		"app_name": projectName,
		"app_url":  cfg.Server.BaseURL,
		"filename": filepath.Base(backupFile),
		"size":     size,
		"time":     time.Now().Format(time.RFC3339),
	})
}

// notifyBackupFailed sends the AI.md PART 17 backup_failed email when the
// backup_failed event is enabled. Reports whether the email was actually
// dispatched so the caller can suppress the scheduler_error email for the
// same execution, per AI.md PART 17's operator notification table.
func notifyBackupFailed(cfg *config.AppConfig, emailMgr *email.EmailManager, projectName string, backupErr error) bool {
	if emailMgr == nil || !emailMgr.IsEnabled() || !cfg.Server.Notifications.Email.Events.BackupFailed {
		return false
	}
	return sendOperatorEmail(cfg, emailMgr, "backup_failed", map[string]string{
		"app_name": projectName,
		"app_url":  cfg.Server.BaseURL,
		"error":    backupErr.Error(),
		"time":     time.Now().Format(time.RFC3339),
	})
}
