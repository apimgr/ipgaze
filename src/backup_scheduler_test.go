package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/apimgr/ipgaze/src/config"
	"gopkg.in/yaml.v3"
)

func TestScheduledBackupCreatesVerifiedFullAndIncremental(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	dataDir := filepath.Join(root, "data")
	dbDir := filepath.Join(root, "db")
	backupDir := filepath.Join(root, "backups")
	for _, dir := range []string{configDir, dataDir, dbDir, backupDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("create %s: %v", dir, err)
		}
	}
	cfg := config.DefaultConfig()
	cfg.Server.Database.Driver = "sqlite"
	cfg.Server.Security.EncryptionKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
	writeConfig := func() {
		t.Helper()
		contents, err := yaml.Marshal(cfg)
		if err != nil {
			t.Fatalf("marshal config: %v", err)
		}
		if err := os.WriteFile(filepath.Join(configDir, "server.yml"), contents, 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
	}
	writeConfig()

	t0 := time.Date(2026, 11, 7, 2, 0, 0, 0, time.UTC)
	fullSnapshot, err := prepareScheduledBackupSnapshot(cfg, configDir, dataDir, dbDir, false, false)
	if err != nil {
		t.Fatalf("prepare full snapshot: %v", err)
	}
	fullPath := filepath.Join(backupDir, "ipgaze_backup_2026-11-07.tar.gz")
	if err := maintenanceBackupAtWithSnapshot(cfg, configDir, dataDir, dbDir, fullPath, false, false, false, t0, "", fullSnapshot, nil); err != nil {
		t.Fatalf("create full backup: %v", err)
	}
	fullRaw, err := os.ReadFile(fullPath)
	if err != nil {
		t.Fatalf("read full backup: %v", err)
	}
	fullManifest, err := readBackupManifest(fullRaw)
	if err != nil || fullManifest["type"] != "full" {
		t.Fatalf("full manifest type = %v, err=%v", fullManifest["type"], err)
	}

	cfg.Server.FQDN = "backup.example"
	writeConfig()
	incrementalSnapshot, err := prepareScheduledBackupSnapshot(cfg, configDir, dataDir, dbDir, false, false)
	if err != nil {
		t.Fatalf("prepare incremental snapshot: %v", err)
	}
	incrementalPath := filepath.Join(backupDir, "ipgaze-daily.tar.gz")
	if err := maintenanceBackupAtWithSnapshot(cfg, configDir, dataDir, dbDir, incrementalPath, false, false, false, t0.Add(24*time.Hour), fullPath, incrementalSnapshot, nil); err != nil {
		t.Fatalf("create incremental backup: %v", err)
	}
	incrementalRaw, err := os.ReadFile(incrementalPath)
	if err != nil {
		t.Fatalf("read incremental backup: %v", err)
	}
	incrementalManifest, err := readBackupManifest(incrementalRaw)
	if err != nil {
		t.Fatalf("read incremental manifest: %v", err)
	}
	if incrementalManifest["type"] != "incremental" || incrementalManifest["base_backup"] != filepath.Base(fullPath) {
		t.Fatalf("incremental manifest = %#v", incrementalManifest)
	}
}
