package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestChecksInfoMarshalJSONPreservesCoreAndDatasetOrder(t *testing.T) {
	checks := ChecksInfo{
		Database: "ok", Cache: "ok", Disk: "error", Scheduler: "ok", Tor: "ok", I2P: "error",
		Datasets: []DatasetCheck{
			{Key: "geoip_country", Status: "ok"},
			{Key: "blocklist_ads", Status: "degraded"},
			{Key: "", Status: "ok"},
			{Key: "ignored", Status: "unknown"},
		},
	}
	encoded, err := json.Marshal(checks)
	if err != nil {
		t.Fatal(err)
	}
	body := string(encoded)
	keys := []string{`"database"`, `"cache"`, `"disk"`, `"scheduler"`, `"tor"`, `"i2p"`, `"geoip_country"`, `"blocklist_ads"`}
	last := -1
	for _, key := range keys {
		at := strings.Index(body, key)
		if at <= last {
			t.Fatalf("key %s is missing or out of order in %s", key, body)
		}
		last = at
	}
	if strings.Contains(body, "ignored") {
		t.Fatalf("invalid dataset status was emitted: %s", body)
	}
}

func TestChecksInfoMarshalJSONOmitsDisabledFeatureChecks(t *testing.T) {
	encoded, err := json.Marshal(ChecksInfo{Database: "ok", Cache: "ok", Disk: "ok", Scheduler: "ok"})
	if err != nil {
		t.Fatal(err)
	}
	body := string(encoded)
	if strings.Contains(body, `"tor"`) || strings.Contains(body, `"i2p"`) {
		t.Fatalf("disabled feature checks should be omitted: %s", body)
	}
}
