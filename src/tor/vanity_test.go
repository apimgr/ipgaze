package tor

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fixedKeyPair derives a deterministic ed25519 keypair from a fixed seed so
// address derivation can be asserted repeatably.
func fixedKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv
}

func TestOnionAddressFormat(t *testing.T) {
	pub, _ := fixedKeyPair(t)
	addr := OnionAddress(pub)

	if !strings.HasSuffix(addr, ".onion") {
		t.Fatalf("OnionAddress() = %q, want a .onion suffix", addr)
	}
	label := strings.TrimSuffix(addr, ".onion")
	if len(label) != 56 {
		t.Fatalf("onion label %q is %d chars, want 56", label, len(label))
	}
	for _, c := range label {
		if (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7') {
			continue
		}
		t.Fatalf("onion label %q contains non-base32 character %q", label, string(c))
	}
	if addr != OnionAddress(pub) {
		t.Fatal("OnionAddress() is not deterministic for the same key")
	}
}

func TestOnionAddressChecksumAndVersion(t *testing.T) {
	pub, _ := fixedKeyPair(t)
	addr := OnionAddress(pub)

	decoded, err := onionBase32.DecodeString(strings.ToUpper(strings.TrimSuffix(addr, ".onion")))
	if err != nil {
		t.Fatalf("decode onion label: %v", err)
	}
	if len(decoded) != 35 {
		t.Fatalf("decoded address is %d bytes, want 35", len(decoded))
	}
	if !bytes.Equal(decoded[:32], pub) {
		t.Fatal("decoded address does not carry the public key")
	}
	sum := onionChecksum(pub)
	if decoded[32] != sum[0] || decoded[33] != sum[1] {
		t.Fatal("decoded address checksum does not match the SHA3-256 derivation")
	}
	if decoded[34] != onionVersion {
		t.Fatalf("version byte = %#x, want %#x", decoded[34], onionVersion)
	}
}

func TestKeyFileEncoding(t *testing.T) {
	pub, priv := fixedKeyPair(t)

	sec := EncodeSecretKeyFile(priv)
	if len(sec) != 96 {
		t.Fatalf("secret key file is %d bytes, want 96", len(sec))
	}
	if string(trimNUL(sec[:32])) != secretKeyHeader {
		t.Fatalf("secret key header = %q, want %q", trimNUL(sec[:32]), secretKeyHeader)
	}
	// Clamping per Tor's expanded-key format.
	if sec[32]&7 != 0 {
		t.Fatal("expanded secret key low bits are not clamped")
	}
	if sec[95]&128 != 0 || sec[95]&64 == 0 {
		t.Fatal("expanded secret key high bits are not clamped")
	}

	pubFile := EncodePublicKeyFile(pub)
	if len(pubFile) != 64 {
		t.Fatalf("public key file is %d bytes, want 64", len(pubFile))
	}
	if string(trimNUL(pubFile[:32])) != publicKeyHeader {
		t.Fatalf("public key header = %q, want %q", trimNUL(pubFile[:32]), publicKeyHeader)
	}

	decoded, err := DecodePublicKeyFile(pubFile)
	if err != nil {
		t.Fatalf("DecodePublicKeyFile() error = %v", err)
	}
	if OnionAddress(decoded) != OnionAddress(pub) {
		t.Fatal("address re-derived from the public key file does not match")
	}
}

func TestDecodePublicKeyFileRejectsBadInput(t *testing.T) {
	if _, err := DecodePublicKeyFile(make([]byte, 10)); err == nil {
		t.Fatal("DecodePublicKeyFile() accepted a short file")
	}
	bad := make([]byte, 64)
	copy(bad[:32], "== not a tor public key ==")
	if _, err := DecodePublicKeyFile(bad); err == nil {
		t.Fatal("DecodePublicKeyFile() accepted a bad header")
	}
}

func TestWriteKeySetRoundTrip(t *testing.T) {
	pub, priv := fixedKeyPair(t)
	dir := filepath.Join(t.TempDir(), OnionAddress(pub))
	if err := WriteKeySet(dir, pub, priv); err != nil {
		t.Fatalf("WriteKeySet() error = %v", err)
	}

	for _, f := range onionKeyFiles {
		info, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("stat %s: %v", f, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("%s permissions = %o, want 600", f, perm)
		}
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat key dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Fatalf("key dir permissions = %o, want 700", perm)
	}

	hostname, err := os.ReadFile(filepath.Join(dir, "hostname"))
	if err != nil {
		t.Fatalf("read hostname: %v", err)
	}
	if string(hostname) != OnionAddress(pub)+"\n" {
		t.Fatalf("hostname file = %q, want the address plus a newline", hostname)
	}

	pubData, err := os.ReadFile(filepath.Join(dir, "hs_ed25519_public_key"))
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	reDecoded, err := DecodePublicKeyFile(pubData)
	if err != nil {
		t.Fatalf("DecodePublicKeyFile() error = %v", err)
	}
	if OnionAddress(reDecoded) != OnionAddress(pub) {
		t.Fatal("address re-derived from the written public key file does not match")
	}
}

func TestValidateVanityPrefix(t *testing.T) {
	valid := []string{"a", "test", "2345", "abcdef"}
	for _, p := range valid {
		if err := ValidateVanityPrefix(p); err != nil {
			t.Errorf("ValidateVanityPrefix(%q) = %v, want nil", p, err)
		}
	}
	invalid := []string{"", "A", "test1", "with-dash", "hello world", "0", "8", "9", strings.Repeat("a", 57)}
	for _, p := range invalid {
		if err := ValidateVanityPrefix(p); err == nil {
			t.Errorf("ValidateVanityPrefix(%q) = nil, want an error", p)
		}
	}
}

func TestValidateVanityPrefixLengthCap(t *testing.T) {
	if err := ValidateVanityPrefix(strings.Repeat("a", MaxVanityPrefixLen)); err != nil {
		t.Fatalf("a %d-character prefix was rejected: %v", MaxVanityPrefixLen, err)
	}
	err := ValidateVanityPrefix(strings.Repeat("a", MaxVanityPrefixLen+1))
	if err == nil {
		t.Fatalf("a %d-character prefix was accepted, want a rejection", MaxVanityPrefixLen+1)
	}
	// The rejection must point the operator at the external GPU path.
	for _, want := range []string{"mkp224o", "import-keys"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("rejection %q does not mention %q", err, want)
		}
	}
}

func TestDefaultVanityWorkers(t *testing.T) {
	got := DefaultVanityWorkers()
	want := runtime.NumCPU() - 1
	if want < 1 {
		want = 1
	}
	if got != want {
		t.Fatalf("DefaultVanityWorkers() = %d, want %d (logical CPUs - 1, min 1)", got, want)
	}
	if got < 1 {
		t.Fatal("DefaultVanityWorkers() returned less than one worker")
	}
}

func TestStartVanitySearchDefaultsWorkerCount(t *testing.T) {
	m := NewTorManager(TorServiceConfig{DataDir: t.TempDir(), ConfigDir: t.TempDir()})
	// A six-character prefix will not be found during the test; the search is
	// only started so the resolved worker count can be observed.
	if err := m.StartVanitySearch("abcdef", 0); err != nil {
		t.Fatalf("StartVanitySearch() error = %v", err)
	}
	defer m.StopVanitySearch()

	if got := m.VanitySearchStatus().Workers; got != DefaultVanityWorkers() {
		t.Fatalf("default worker count = %d, want %d", got, DefaultVanityWorkers())
	}
}

func TestStopVanitySearchReportsWhetherOneWasRunning(t *testing.T) {
	m := NewTorManager(TorServiceConfig{DataDir: t.TempDir(), ConfigDir: t.TempDir()})

	if m.StopVanitySearch() {
		t.Fatal("StopVanitySearch() reported a running search before any search started")
	}
	if err := m.StartVanitySearch("abcdef", 1); err != nil {
		t.Fatalf("StartVanitySearch() error = %v", err)
	}
	if !m.StopVanitySearch() {
		t.Fatal("StopVanitySearch() did not report the running search")
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if m.VanitySearchStatus().State == VanityStateIdle {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if st := m.VanitySearchStatus(); st.State != VanityStateIdle {
		t.Fatalf("state after stop = %q, want %q", st.State, VanityStateIdle)
	}
	if m.StopVanitySearch() {
		t.Fatal("a second StopVanitySearch() reported a running search")
	}
}

func TestVanitySearchStatusIdleShape(t *testing.T) {
	m := NewTorManager(TorServiceConfig{DataDir: t.TempDir(), ConfigDir: t.TempDir()})
	st := m.VanitySearchStatus()
	if st.State != VanityStateIdle {
		t.Fatalf("state = %q, want %q", st.State, VanityStateIdle)
	}
	if st.Attempts != 0 || st.Rate != 0 || st.ElapsedSeconds != 0 || len(st.Candidates) != 0 {
		t.Fatalf("idle status is not zero-valued: %+v", st)
	}
}

func TestVanitySearchStatusReportsFoundCandidate(t *testing.T) {
	m := NewTorManager(TorServiceConfig{DataDir: t.TempDir(), ConfigDir: t.TempDir()})
	pub, priv := fixedKeyPair(t)
	addr := OnionAddress(pub)
	if err := WriteKeySet(filepath.Join(m.VanityDir(), addr), pub, priv); err != nil {
		t.Fatalf("WriteKeySet() error = %v", err)
	}

	st := m.VanitySearchStatus()
	if st.State != VanityStateFound {
		t.Fatalf("state = %q, want %q", st.State, VanityStateFound)
	}
	if len(st.Candidates) != 1 || st.Candidates[0] != addr {
		t.Fatalf("candidates = %v, want [%s]", st.Candidates, addr)
	}
}

func TestResolveVanityCandidate(t *testing.T) {
	candidates := []string{"abcdefgh.onion", "abcxyz12.onion", "zzz11111.onion"}

	got, err := resolveVanityCandidate("abcdefgh.onion", candidates)
	if err != nil || got != "abcdefgh.onion" {
		t.Fatalf("exact match = (%q, %v), want abcdefgh.onion", got, err)
	}

	got, err = resolveVanityCandidate("abcd", candidates)
	if err != nil || got != "abcdefgh.onion" {
		t.Fatalf("unique prefix = (%q, %v), want abcdefgh.onion", got, err)
	}

	if _, err := resolveVanityCandidate("abc", candidates); err == nil {
		t.Fatal("ambiguous prefix was accepted")
	}
	if _, err := resolveVanityCandidate("nope", candidates); err == nil {
		t.Fatal("non-matching prefix was accepted")
	}
	if _, err := resolveVanityCandidate("", candidates); err == nil {
		t.Fatal("omitted argument was accepted with several candidates present")
	}

	got, err = resolveVanityCandidate("", candidates[:1])
	if err != nil || got != "abcdefgh.onion" {
		t.Fatalf("omitted argument with one candidate = (%q, %v), want abcdefgh.onion", got, err)
	}
}

func TestApplyVanityAddressResolvesPrefix(t *testing.T) {
	m := NewTorManager(TorServiceConfig{DataDir: t.TempDir(), ConfigDir: t.TempDir()})
	if m.IsAvailable() {
		// Applying starts Tor for real; skip rather than bootstrap a circuit.
		t.Skip("tor binary present — the key swap would start a real hidden service")
	}
	pub, priv := fixedKeyPair(t)
	addr := OnionAddress(pub)
	if err := WriteKeySet(filepath.Join(m.VanityDir(), addr), pub, priv); err != nil {
		t.Fatalf("WriteKeySet() error = %v", err)
	}

	// A prefix that matches nothing must be rejected before any key swap.
	if _, err := m.ApplyVanityAddress("zzzzzz"); err == nil {
		t.Fatal("ApplyVanityAddress() accepted a prefix matching no candidate")
	}
	if !hasKeySet(filepath.Join(m.VanityDir(), addr)) {
		t.Fatal("a rejected apply removed the candidate")
	}

	// A unique prefix resolves and the identity lands in the site dir.
	applied, err := m.ApplyVanityAddress(addr[:6])
	if err != nil {
		t.Fatalf("ApplyVanityAddress() error = %v", err)
	}
	if applied != addr {
		t.Fatalf("ApplyVanityAddress() = %q, want %q", applied, addr)
	}
	siteDir := filepath.Join(m.cfg.DataDir, "tor", "site")
	if !hasKeySet(siteDir) {
		t.Fatal("site dir is missing the applied identity files")
	}
	hostname, err := os.ReadFile(filepath.Join(siteDir, "hostname"))
	if err != nil {
		t.Fatalf("read site hostname: %v", err)
	}
	if strings.TrimSpace(string(hostname)) != addr {
		t.Fatalf("site hostname = %q, want %q", strings.TrimSpace(string(hostname)), addr)
	}
	// The applied candidate's staging directory is removed; nothing else is.
	if _, err := os.Stat(filepath.Join(m.VanityDir(), addr)); !os.IsNotExist(err) {
		t.Fatal("applied candidate directory was not removed")
	}
}

func TestVanitySearchFindsCandidate(t *testing.T) {
	m := NewTorManager(TorServiceConfig{DataDir: t.TempDir(), ConfigDir: t.TempDir()})

	if err := m.StartVanitySearch("bad!", 1); err == nil {
		t.Fatal("StartVanitySearch() accepted an invalid prefix")
	}

	if err := m.StartVanitySearch("a", 2); err != nil {
		t.Fatalf("StartVanitySearch() error = %v", err)
	}
	defer m.StopVanitySearch()

	if err := m.StartVanitySearch("a", 1); !errors.Is(err, ErrVanitySearchRunning) {
		t.Fatalf("second StartVanitySearch() = %v, want ErrVanitySearchRunning", err)
	}

	deadline := time.Now().Add(30 * time.Second)
	var found []string
	for time.Now().Before(deadline) {
		found = m.VanityCandidates()
		if len(found) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(found) == 0 {
		t.Fatal("vanity search found no candidate for a single-character prefix within 30s")
	}
	for _, addr := range found {
		if !strings.HasPrefix(addr, "a") {
			t.Fatalf("candidate %q does not match the requested prefix", addr)
		}
		if !hasKeySet(filepath.Join(m.VanityDir(), addr)) {
			t.Fatalf("candidate %q is missing identity files", addr)
		}
	}

	st := m.VanitySearchStatus()
	if st.Prefix != "a" {
		t.Fatalf("VanitySearchStatus().Prefix = %q, want \"a\"", st.Prefix)
	}
	if st.Attempts == 0 {
		t.Fatal("VanitySearchStatus().Attempts = 0, want a positive count")
	}
	if st.State != VanityStateRunning {
		t.Fatalf("VanitySearchStatus().State = %q, want %q", st.State, VanityStateRunning)
	}
	if st.ElapsedSeconds < 0 {
		t.Fatalf("elapsed_seconds = %v, want a non-negative duration", st.ElapsedSeconds)
	}
	// rate is attempts/sec, so it is positive exactly when time has elapsed.
	if st.ElapsedSeconds > 0 && st.Rate <= 0 {
		t.Fatalf("rate = %v after %vs with %d attempts, want a positive rate", st.Rate, st.ElapsedSeconds, st.Attempts)
	}
	if len(st.Candidates) == 0 {
		t.Fatal("VanitySearchStatus().Candidates is empty, want the found addresses")
	}

	m.StopVanitySearch()
	stopDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(stopDeadline) {
		if m.VanitySearchStatus().State != VanityStateRunning {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("vanity search still reports running after StopVanitySearch()")
}

func TestApplyVanityAddressWithoutCandidates(t *testing.T) {
	m := NewTorManager(TorServiceConfig{DataDir: t.TempDir(), ConfigDir: t.TempDir()})
	if _, err := m.ApplyVanityAddress(""); err == nil {
		t.Fatal("ApplyVanityAddress() succeeded with no candidates present")
	}
}

func TestImportKeysRejectsMissingSource(t *testing.T) {
	m := NewTorManager(TorServiceConfig{DataDir: t.TempDir(), ConfigDir: t.TempDir()})
	if _, err := m.ImportKeys(""); err == nil {
		t.Fatal("ImportKeys(\"\") succeeded, want an error")
	}
	if _, err := m.ImportKeys(t.TempDir()); err == nil {
		t.Fatal("ImportKeys() accepted a directory with no key files")
	}
}
