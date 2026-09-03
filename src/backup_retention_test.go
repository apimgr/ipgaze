package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/email"
)

func writeBackupFile(t *testing.T, dir, name string, size int, mod time.Time) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, make([]byte, size), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	if err := os.Chtimes(path, mod, mod); err != nil {
		t.Fatalf("chtimes %s: %v", name, err)
	}
	return path
}

func TestListFullBackups(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	writeBackupFile(t, dir, "ipgaze_backup_2026-01-01.tar.gz", 10, now.Add(-48*time.Hour))
	writeBackupFile(t, dir, "ipgaze_backup_2026-01-02_120000.tar.gz.enc", 20, now.Add(-24*time.Hour))
	writeBackupFile(t, dir, "ipgaze-daily.tar.gz", 5, now)
	writeBackupFile(t, dir, "notes.txt", 1, now)

	fulls, err := listFullBackups(dir)
	if err != nil {
		t.Fatalf("listFullBackups: %v", err)
	}
	if len(fulls) != 2 {
		t.Fatalf("expected 2 full backups, got %d", len(fulls))
	}
	if fulls[0].name != "ipgaze_backup_2026-01-02_120000.tar.gz.enc" {
		t.Errorf("expected newest first, got %s", fulls[0].name)
	}
}

func TestListFullBackups_MissingDir(t *testing.T) {
	fulls, err := listFullBackups(filepath.Join(t.TempDir(), "missing"))
	if err != nil {
		t.Fatalf("expected nil error for missing dir, got %v", err)
	}
	if fulls != nil {
		t.Errorf("expected nil slice, got %v", fulls)
	}
}

func TestIsFalseyRetentionValue(t *testing.T) {
	truthy := []string{"0", "false", "No", "NONE", "disable", "Disabled", "off", ""}
	for _, v := range truthy {
		if !isFalseyRetentionValue(v) {
			t.Errorf("expected %q to be falsey", v)
		}
	}
	if isFalseyRetentionValue("50G") {
		t.Error("expected 50G to not be falsey")
	}
}

func TestParseByteSize(t *testing.T) {
	cases := map[string]int64{
		"1024": 1024,
		"1K":   1 << 10,
		"10M":  10 << 20,
		"2G":   2 << 30,
		"1T":   1 << 40,
		"500B": 500,
	}
	for in, want := range cases {
		got, err := parseByteSize(in)
		if err != nil {
			t.Errorf("parseByteSize(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("parseByteSize(%q) = %d, want %d", in, got, want)
		}
	}
	if _, err := parseByteSize("notanumber"); err == nil {
		t.Error("expected error for invalid size")
	}
}

func TestBackupDirSize(t *testing.T) {
	dir := t.TempDir()
	writeBackupFile(t, dir, "a.tar.gz", 100, time.Now())
	writeBackupFile(t, dir, "b.tar.gz", 200, time.Now())
	size, err := backupDirSize(dir)
	if err != nil {
		t.Fatalf("backupDirSize: %v", err)
	}
	if size != 300 {
		t.Errorf("backupDirSize = %d, want 300", size)
	}

	size, err = backupDirSize(filepath.Join(dir, "missing"))
	if err != nil {
		t.Fatalf("backupDirSize missing dir: %v", err)
	}
	if size != 0 {
		t.Errorf("expected 0 for missing dir, got %d", size)
	}
}

func TestParseBackupSizeCap(t *testing.T) {
	dir := t.TempDir()
	writeBackupFile(t, dir, "ipgaze_backup_2026-01-01.tar.gz", 100, time.Now())

	capBytes, ok, err := parseBackupSizeCap("0", dir)
	if err != nil || ok || capBytes != 0 {
		t.Errorf("expected disabled cap for falsey value, got cap=%d ok=%v err=%v", capBytes, ok, err)
	}

	capBytes, ok, err = parseBackupSizeCap("500M", dir)
	if err != nil {
		t.Fatalf("parseBackupSizeCap: %v", err)
	}
	if !ok || capBytes != 500<<20 {
		t.Errorf("expected cap=%d ok=true, got cap=%d ok=%v", 500<<20, capBytes, ok)
	}

	if _, _, err := parseBackupSizeCap("garbage", dir); err == nil {
		t.Error("expected error for invalid size")
	}
}

func TestKeepPeriodic(t *testing.T) {
	fulls := []backupFileInfo{
		{path: "a", mod: time.Date(2026, 1, 4, 0, 0, 0, 0, time.UTC)}, // Sunday
		{path: "b", mod: time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)}, // Saturday
		{path: "c", mod: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}, // Thursday, day 1
	}
	keep := make(map[string]bool)
	keepPeriodic(fulls, keep, 1, func(t time.Time) bool { return t.Weekday() == time.Sunday })
	if !keep["a"] || keep["b"] || keep["c"] {
		t.Errorf("expected only 'a' kept for weekly, got %v", keep)
	}

	keep = make(map[string]bool)
	keepPeriodic(fulls, keep, 0, func(t time.Time) bool { return true })
	if len(keep) != 0 {
		t.Errorf("expected no keeps when n=0, got %v", keep)
	}
}

func TestApplyBackupRetention_MaxBackups(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	names := []string{
		"ipgaze_backup_2026-01-01.tar.gz",
		"ipgaze_backup_2026-01-02.tar.gz",
		"ipgaze_backup_2026-01-03.tar.gz",
		"ipgaze_backup_2026-01-04.tar.gz",
	}
	for i, name := range names {
		writeBackupFile(t, dir, name, 10, now.Add(-time.Duration(len(names)-i)*24*time.Hour))
	}

	applyBackupRetention(dir, config.BackupRetentionConfig{MaxBackups: 2}, nil)

	fulls, err := listFullBackups(dir)
	if err != nil {
		t.Fatalf("listFullBackups: %v", err)
	}
	if len(fulls) != 2 {
		t.Fatalf("expected 2 backups remaining, got %d: %+v", len(fulls), fulls)
	}
	if fulls[0].name != "ipgaze_backup_2026-01-04.tar.gz" || fulls[1].name != "ipgaze_backup_2026-01-03.tar.gz" {
		t.Errorf("expected newest 2 kept, got %s, %s", fulls[0].name, fulls[1].name)
	}
}

func TestApplyBackupRetention_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	applyBackupRetention(dir, config.BackupRetentionConfig{MaxBackups: 1}, nil)
	fulls, err := listFullBackups(dir)
	if err != nil || len(fulls) != 0 {
		t.Fatalf("expected empty dir to remain empty, got %v err=%v", fulls, err)
	}
}

func TestBackupDiskSpaceExceeded_UsesRealFilesystem(t *testing.T) {
	dir := t.TempDir()
	// The real filesystem underlying t.TempDir() should have well under 100%
	// usage in any sane test environment, so this should not skip.
	skip, reason := backupDiskSpaceExceeded(dir, 90, nil)
	if skip {
		t.Errorf("did not expect disk space to be exceeded in test env: %s", reason)
	}
}

func TestBackupDiskSpaceExceeded_InvalidThresholdDefaultsTo90(t *testing.T) {
	dir := t.TempDir()
	skip, _ := backupDiskSpaceExceeded(dir, 0, nil)
	if skip {
		t.Error("did not expect disk space to be exceeded with default threshold")
	}
}

func TestFormatByteSize(t *testing.T) {
	tests := []struct {
		n    int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1 << 20, "1.0 MiB"},
		{1 << 30, "1.0 GiB"},
	}
	for _, tt := range tests {
		if got := formatByteSize(tt.n); got != tt.want {
			t.Errorf("formatByteSize(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

func TestNotifyBackupComplete_NilEmailManager_NoPanic(t *testing.T) {
	dir := t.TempDir()
	f := writeBackupFile(t, dir, "ipgaze_backup_2026-01-01.tar.gz", 100, time.Now())
	cfg := &config.AppConfig{}
	notifyBackupComplete(cfg, nil, "ipgaze", f)
}

func TestNotifyBackupFailed_NilEmailManager_NoPanic(t *testing.T) {
	cfg := &config.AppConfig{}
	notifyBackupFailed(cfg, nil, "ipgaze", errors.New("boom"))
}

func TestNotifyBackupComplete_EventDisabled_DoesNotSend(t *testing.T) {
	dir := t.TempDir()
	f := writeBackupFile(t, dir, "ipgaze_backup_2026-01-01.tar.gz", 100, time.Now())
	m := email.NewEmailManager(email.SMTPConfig{Enabled: true, Host: "smtp.example.invalid", Port: 587}, t.TempDir())
	cfg := &config.AppConfig{}
	cfg.Server.Notifications.Email.Events.BackupComplete = false
	// Should return immediately without attempting to connect (would block/error otherwise).
	notifyBackupComplete(cfg, m, "ipgaze", f)
}

func TestNotifyBackupFailed_EventDisabled_DoesNotSend(t *testing.T) {
	m := email.NewEmailManager(email.SMTPConfig{Enabled: true, Host: "smtp.example.invalid", Port: 587}, t.TempDir())
	cfg := &config.AppConfig{}
	cfg.Server.Notifications.Email.Events.BackupFailed = false
	notifyBackupFailed(cfg, m, "ipgaze", errors.New("boom"))
}
