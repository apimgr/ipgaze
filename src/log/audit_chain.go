package log

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const emptyAuditHash = "0000000000000000000000000000000000000000000000000000000000000000"

type auditChainLine struct {
	Prev string `json:"prev"`
}

type auditChainBreak struct {
	filename string
	line     int
	reason   string
}

// loadAuditChain returns the previous hash to use for a new entry and the
// hash of the last current-file line, starting from the retained anchor.
func loadAuditChain(logDir, filename string) (string, string, error) {
	anchor, err := readAuditAnchor(logDir)
	if err != nil {
		anchor = emptyAuditHash
	}
	path := filepath.Join(logDir, filename)
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return anchor, "", nil
		}
		return "", "", err
	}
	defer func() { _ = file.Close() }()
	last := ""
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		digest := sha256.Sum256(line)
		last = fmt.Sprintf("%x", digest)
	}
	if err := scanner.Err(); err != nil {
		return "", "", err
	}
	if last == "" {
		return anchor, "", nil
	}
	return last, last, nil
}

// verifyAuditChainAt returns the first broken line in the active audit file.
func verifyAuditChainAt(logDir, filename string) int {
	line, _ := verifyAuditChainStatus(logDir, filepath.Join(logDir, filename), "")
	return line
}

func verifyAuditChainStatus(logDir, path, expectedLastHash string) (int, string) {
	anchor, anchorErr := readAuditAnchor(logDir)
	anchorPath := filepath.Join(logDir, "audit.anchor")
	_, statErr := os.Stat(anchorPath)
	anchorExists := statErr == nil
	if errors.Is(statErr, os.ErrNotExist) {
		anchorExists = false
	}
	if anchorErr != nil {
		return 1, "anchor_mismatch"
	}
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, ""
		}
		return 1, ""
	}
	defer func() { _ = file.Close() }()
	previous := anchor
	lineNumber := 0
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		lineNumber++
		line := append([]byte(nil), scanner.Bytes()...)
		var entry auditChainLine
		decodeErr := json.Unmarshal(line, &entry)
		if decodeErr != nil || entry.Prev != previous {
			if lineNumber == 1 {
				if decodeErr == nil && !anchorExists && entry.Prev != emptyAuditHash {
					return lineNumber, "anchor_missing"
				}
				if decodeErr == nil && anchorExists {
					return lineNumber, "anchor_mismatch"
				}
			}
			return lineNumber, ""
		}
		digest := sha256.Sum256(line)
		previous = fmt.Sprintf("%x", digest)
	}
	if scanner.Err() != nil {
		return lineNumber + 1, ""
	}
	if expectedLastHash != "" && previous != expectedLastHash {
		if lineNumber == 0 {
			lineNumber = 1
		}
		return lineNumber, ""
	}
	return 0, ""
}

func readAuditAnchor(logDir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(logDir, "audit.anchor"))
	if err != nil {
		if os.IsNotExist(err) {
			return emptyAuditHash, nil
		}
		return "", err
	}
	anchor := strings.TrimSpace(string(data))
	if len(anchor) != 64 {
		return "", fmt.Errorf("invalid audit anchor length")
	}
	for _, char := range anchor {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return "", fmt.Errorf("invalid audit anchor encoding")
		}
	}
	return anchor, nil
}

func writeAuditAnchor(logDir, hash string) error {
	if hash == "" {
		hash = emptyAuditHash
	}
	if len(hash) != 64 {
		return fmt.Errorf("invalid audit hash")
	}
	tmp, err := os.CreateTemp(logDir, ".audit-anchor-*")
	if err != nil {
		return err
	}
	path := tmp.Name()
	defer func() { _ = os.Remove(path) }()
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := fmt.Fprintln(tmp, hash); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(path, filepath.Join(logDir, "audit.anchor"))
}

func markAuditChainBrokenOnce(logDir, filename string, line int) bool {
	marker := filepath.Join(logDir, ".audit_chain_broken")
	want := fmt.Sprintf("%s:%d", filename, line)
	if previous, err := os.ReadFile(marker); err == nil && strings.TrimSpace(string(previous)) == want {
		return false
	}
	tmp, err := os.CreateTemp(logDir, ".audit-chain-warning-*")
	if err != nil {
		return true
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return true
	}
	if _, err := tmp.WriteString(want + "\n"); err != nil {
		_ = tmp.Close()
		return true
	}
	if err := tmp.Close(); err != nil {
		return true
	}
	if err := os.Rename(tmpPath, marker); err != nil {
		return true
	}
	return true
}
