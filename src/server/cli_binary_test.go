package server

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestScanCLIBinariesRequiresMatchingReleaseMetadata(t *testing.T) {
	dir := t.TempDir()
	filename := "ipgaze-cli-linux-amd64"
	binary := []byte("release binary")
	if err := os.WriteFile(filepath.Join(dir, filename), binary, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "version.txt"), []byte("1.2.3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(binary)
	checksum := hex.EncodeToString(digest[:])
	if err := os.WriteFile(filepath.Join(dir, "sha256.txt"), []byte(checksum+"  "+filename+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := scanCLIBinaries(dir)
	entry, ok := got["linux-amd64"]
	if !ok || entry.Version != "1.2.3" || entry.SHA256 != checksum {
		t.Fatalf("scanCLIBinaries() = %#v, want verified linux-amd64 release", got)
	}

	if err := os.WriteFile(filepath.Join(dir, filename), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := scanCLIBinaries(dir); len(got) != 0 {
		t.Fatalf("scanCLIBinaries() published mismatched binary: %#v", got)
	}
}
