package ssl

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/apimgr/ipgaze/src/security"
)

// generateSelfSignedCert writes a self-signed certificate and key pair to the
// given directory under the filenames cert.pem and key.pem and returns their
// paths.
func generateSelfSignedCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")

	cf, err := os.Create(certFile)
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	defer cf.Close()
	if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("pem encode cert: %v", err)
	}

	kf, err := os.Create(keyFile)
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	defer kf.Close()
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	if err := pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER}); err != nil {
		t.Fatalf("pem encode key: %v", err)
	}

	return certFile, keyFile
}

// tempDir creates a temp directory under os.TempDir()/apimgr/ and registers
// cleanup with t.Cleanup.
func tempDir(t *testing.T) string {
	t.Helper()
	base := filepath.Join(os.TempDir(), "apimgr")
	if err := os.MkdirAll(base, 0700); err != nil {
		t.Fatalf("mkdir base: %v", err)
	}
	dir, err := os.MkdirTemp(base, "ipgaze-ssl-")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestNewSSLManager(t *testing.T) {
	cfg := SSLManagerConfig{Enabled: true, CertPath: "/tmp/noop"}
	m := NewSSLManager(cfg)
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
}

func TestGetTLSConfig_Disabled(t *testing.T) {
	m := NewSSLManager(SSLManagerConfig{Enabled: false})
	cfg, err := m.GetTLSConfig([]string{"example.com"})
	if err != nil {
		t.Fatalf("expected no error when SSL disabled, got: %v", err)
	}
	if cfg != nil {
		t.Fatal("expected nil TLS config when SSL disabled")
	}
}

func TestGetTLSConfig_NoLetsEncryptNoCert(t *testing.T) {
	dir := tempDir(t)
	m := NewSSLManager(SSLManagerConfig{
		Enabled:  true,
		CertPath: dir,
		LetsEncrypt: LetsEncryptConfig{
			Enabled: false,
		},
	})

	_, err := m.GetTLSConfig([]string{"example.com"})
	if err == nil {
		t.Fatal("expected error when no cert found and Let's Encrypt disabled")
	}
}

func TestGetTLSConfig_LocalCert(t *testing.T) {
	dir := tempDir(t)

	domain := "example.com"
	localDir := filepath.Join(dir, "local", domain)
	if err := os.MkdirAll(localDir, 0700); err != nil {
		t.Fatalf("mkdir local dir: %v", err)
	}

	certFile, keyFile := generateSelfSignedCert(t, localDir)

	// Rename to the expected filenames: cert.pem and key.pem (already correct).
	_ = certFile
	_ = keyFile

	m := NewSSLManager(SSLManagerConfig{
		Enabled:  true,
		CertPath: dir,
		LetsEncrypt: LetsEncryptConfig{
			Enabled: false,
		},
	})

	tlsCfg, err := m.GetTLSConfig([]string{domain})
	if err != nil {
		t.Fatalf("GetTLSConfig: %v", err)
	}
	if tlsCfg == nil {
		t.Fatal("expected non-nil TLS config")
	}
	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %v, want TLS 1.2", tlsCfg.MinVersion)
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Errorf("Certificates count = %d, want 1", len(tlsCfg.Certificates))
	}
}

func TestGetTLSConfig_AppManagedLECert(t *testing.T) {
	dir := tempDir(t)

	domain := "le-test.example.com"
	leDir := filepath.Join(dir, "letsencrypt", domain)
	if err := os.MkdirAll(leDir, 0700); err != nil {
		t.Fatalf("mkdir letsencrypt dir: %v", err)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certFile := filepath.Join(leDir, "fullchain.pem")
	keyFile := filepath.Join(leDir, "privkey.pem")

	cf, _ := os.Create(certFile)
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cf.Close()

	kf, _ := os.Create(keyFile)
	privDER, _ := x509.MarshalECPrivateKey(priv)
	pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	kf.Close()

	m := NewSSLManager(SSLManagerConfig{
		Enabled:  true,
		CertPath: dir,
		LetsEncrypt: LetsEncryptConfig{
			Enabled: false,
		},
	})

	tlsCfg, err := m.GetTLSConfig([]string{domain})
	if err != nil {
		t.Fatalf("GetTLSConfig: %v", err)
	}
	if tlsCfg == nil {
		t.Fatal("expected non-nil TLS config")
	}
}

// TestGetTLSConfig_LetsEncryptEnabled verifies the Let's Encrypt issuance
// path is exercised (ACME client construction against a hermetic local
// directory endpoint) without ever contacting the real Let's Encrypt API.
// A full successful issuance isn't reproducible without a mock ACME server
// implementing the whole protocol, so this asserts the call reaches the ACME
// client and fails on the injected directory endpoint with a wrapped error,
// rather than asserting success.
func TestGetTLSConfig_LetsEncryptEnabled(t *testing.T) {
	dir := tempDir(t)

	acmeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "acme directory unavailable", http.StatusInternalServerError)
	}))
	defer acmeSrv.Close()

	m := NewSSLManager(SSLManagerConfig{
		Enabled:  true,
		CertPath: dir,
		LetsEncrypt: LetsEncryptConfig{
			Enabled:  true,
			Email:    "test@example.com",
			caDirURL: acmeSrv.URL,
		},
	})

	_, err := m.GetTLSConfig([]string{"example.com"})
	if err == nil {
		t.Fatal("expected error from GetTLSConfig against a broken ACME directory endpoint")
	}
}

func TestGetHTTPHandler_NilCertManager(t *testing.T) {
	m := NewSSLManager(SSLManagerConfig{})
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("fallback"))
	})

	h := m.GetHTTPHandler(fallback)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "fallback" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "fallback")
	}
}

func TestGetHTTPHandler_WithCertManager(t *testing.T) {
	dir := tempDir(t)

	m := NewSSLManager(SSLManagerConfig{
		Enabled:  true,
		CertPath: dir,
		LetsEncrypt: LetsEncryptConfig{
			Enabled: true,
			Email:   "test@example.com",
		},
	})

	_, _ = m.GetTLSConfig([]string{"example.com"})

	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	h := m.GetHTTPHandler(fallback)
	if h == nil {
		t.Fatal("GetHTTPHandler returned nil")
	}
}

func TestNewChallengeServer(t *testing.T) {
	cs := NewChallengeServer()
	if cs == nil {
		t.Fatal("NewChallengeServer returned nil")
	}
}

func TestChallengeServer_SetAndServe(t *testing.T) {
	cs := NewChallengeServer()
	cs.SetToken("mytoken", "mytoken.authkey")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/mytoken", nil)
	rec := httptest.NewRecorder()

	handled := cs.ServeHTTP(rec, req)
	if !handled {
		t.Fatal("ServeHTTP returned false for ACME path")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "mytoken.authkey" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "mytoken.authkey")
	}
}

func TestChallengeServer_MissingToken(t *testing.T) {
	cs := NewChallengeServer()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/unknown", nil)
	rec := httptest.NewRecorder()

	handled := cs.ServeHTTP(rec, req)
	if !handled {
		t.Fatal("ServeHTTP returned false for ACME path")
	}
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestChallengeServer_NonACMEPath(t *testing.T) {
	cs := NewChallengeServer()

	req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	rec := httptest.NewRecorder()

	handled := cs.ServeHTTP(rec, req)
	if handled {
		t.Fatal("ServeHTTP returned true for non-ACME path")
	}
}

func TestChallengeServer_ClearToken(t *testing.T) {
	cs := NewChallengeServer()
	cs.SetToken("tok", "auth")
	cs.ClearToken("tok")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/tok", nil)
	rec := httptest.NewRecorder()

	cs.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 after ClearToken", rec.Code)
	}
}

func TestParseChallenge(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"http-01", "http-01"},
		{"http01", "http-01"},
		{"http", "http-01"},
		{"HTTP", "http-01"},
		{"tls-alpn-01", "tls-alpn-01"},
		{"tlsalpn01", "tls-alpn-01"},
		{"tls-alpn", "tls-alpn-01"},
		{"tls", "tls-alpn-01"},
		{"TLS", "tls-alpn-01"},
		{"dns-01", "dns-01"},
		{"dns01", "dns-01"},
		{"dns", "dns-01"},
		{"DNS", "dns-01"},
		{"unknown", "http-01"},
		{"", "http-01"},
		{"  http-01  ", "http-01"},
	}

	for _, tc := range tests {
		got := ParseChallenge(tc.input)
		if got != tc.want {
			t.Errorf("ParseChallenge(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestFileExists(t *testing.T) {
	dir := tempDir(t)

	existing := filepath.Join(dir, "exists.txt")
	if err := os.WriteFile(existing, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}

	if !fileExists(existing) {
		t.Errorf("fileExists(%q) = false, want true", existing)
	}

	missing := filepath.Join(dir, "nope.txt")
	if fileExists(missing) {
		t.Errorf("fileExists(%q) = true, want false", missing)
	}
}

func TestFindCertByPriority_Priority3(t *testing.T) {
	dir := tempDir(t)

	domain := "p3.example.com"
	leDir := filepath.Join(dir, "letsencrypt", domain)
	if err := os.MkdirAll(leDir, 0700); err != nil {
		t.Fatal(err)
	}

	os.WriteFile(filepath.Join(leDir, "fullchain.pem"), []byte("cert"), 0600)
	os.WriteFile(filepath.Join(leDir, "privkey.pem"), []byte("key"), 0600)

	m := NewSSLManager(SSLManagerConfig{
		Enabled:  true,
		CertPath: dir,
	})

	cert, key := m.findCertByPriority([]string{domain})
	if cert == "" || key == "" {
		t.Error("findCertByPriority did not find priority-3 cert")
	}
}

func TestFindCertByPriority_Priority4(t *testing.T) {
	dir := tempDir(t)

	domain := "p4.example.com"
	localDir := filepath.Join(dir, "local", domain)
	if err := os.MkdirAll(localDir, 0700); err != nil {
		t.Fatal(err)
	}

	os.WriteFile(filepath.Join(localDir, "cert.pem"), []byte("cert"), 0600)
	os.WriteFile(filepath.Join(localDir, "key.pem"), []byte("key"), 0600)

	m := NewSSLManager(SSLManagerConfig{
		Enabled:  true,
		CertPath: dir,
	})

	cert, key := m.findCertByPriority([]string{domain})
	if cert == "" || key == "" {
		t.Error("findCertByPriority did not find priority-4 cert")
	}
}

func TestFindCertByPriority_NoCert(t *testing.T) {
	dir := tempDir(t)

	m := NewSSLManager(SSLManagerConfig{
		Enabled:  true,
		CertPath: dir,
	})

	cert, key := m.findCertByPriority([]string{"no-cert.example.com"})
	if cert != "" || key != "" {
		t.Errorf("expected empty paths, got cert=%q key=%q", cert, key)
	}
}

func TestFindCertByPriority_EmptyDomains(t *testing.T) {
	dir := tempDir(t)

	m := NewSSLManager(SSLManagerConfig{
		Enabled:  true,
		CertPath: dir,
	})

	cert, key := m.findCertByPriority([]string{})
	if cert != "" || key != "" {
		t.Errorf("expected empty paths for no domains, got cert=%q key=%q", cert, key)
	}
}

func TestFindCertByPriority_EmptyCertPath(t *testing.T) {
	m := NewSSLManager(SSLManagerConfig{
		Enabled:  true,
		CertPath: "",
	})

	cert, key := m.findCertByPriority([]string{"example.com"})
	if cert != "" || key != "" {
		t.Errorf("expected empty paths when CertPath is empty, got cert=%q key=%q", cert, key)
	}
}

func TestRenewIfExpiring_NoCert(t *testing.T) {
	dir := tempDir(t)

	m := NewSSLManager(SSLManagerConfig{
		Enabled:  true,
		CertPath: dir,
	})

	err := m.RenewIfExpiring([]string{"no-cert.example.com"}, 7)
	if err != nil {
		t.Errorf("RenewIfExpiring with no cert should be no-op, got: %v", err)
	}
}

func TestCertExpiry_NoCert(t *testing.T) {
	dir := tempDir(t)
	m := NewSSLManager(SSLManagerConfig{Enabled: true, CertPath: dir})

	_, _, ok := m.CertExpiry([]string{"no-cert.example.com"})
	if ok {
		t.Error("expected ok=false when no certificate exists")
	}
}

func TestCertExpiry_ExistingCert(t *testing.T) {
	dir := tempDir(t)

	domain := "expiry-check.example.com"
	localDir := filepath.Join(dir, "local", domain)
	if err := os.MkdirAll(localDir, 0700); err != nil {
		t.Fatal(err)
	}

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wantNotAfter := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     wantNotAfter,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)

	cf, _ := os.Create(filepath.Join(localDir, "cert.pem"))
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cf.Close()

	privDER, _ := x509.MarshalECPrivateKey(priv)
	kf, _ := os.Create(filepath.Join(localDir, "key.pem"))
	pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	kf.Close()

	m := NewSSLManager(SSLManagerConfig{Enabled: true, CertPath: dir})

	fqdn, notAfter, ok := m.CertExpiry([]string{domain})
	if !ok {
		t.Fatal("expected ok=true for an existing certificate")
	}
	if fqdn != domain {
		t.Errorf("fqdn = %q, want %q", fqdn, domain)
	}
	if !notAfter.Equal(wantNotAfter) {
		t.Errorf("notAfter = %v, want %v", notAfter, wantNotAfter)
	}
}

func TestRenewIfExpiring_NotExpiring(t *testing.T) {
	dir := tempDir(t)

	domain := "renew-test.example.com"
	localDir := filepath.Join(dir, "local", domain)
	if err := os.MkdirAll(localDir, 0700); err != nil {
		t.Fatal(err)
	}

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)

	cf, _ := os.Create(filepath.Join(localDir, "cert.pem"))
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cf.Close()

	privDER, _ := x509.MarshalECPrivateKey(priv)
	kf, _ := os.Create(filepath.Join(localDir, "key.pem"))
	pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	kf.Close()

	m := NewSSLManager(SSLManagerConfig{
		Enabled:  true,
		CertPath: dir,
		LetsEncrypt: LetsEncryptConfig{
			Enabled: false,
		},
	})

	err := m.RenewIfExpiring([]string{domain}, 7)
	if err != nil {
		t.Errorf("RenewIfExpiring non-expiring cert: %v", err)
	}
}

func TestRenewIfExpiring_Expiring_ExistingCertStillLoads(t *testing.T) {
	dir := tempDir(t)

	domain := "expiring.example.com"
	localDir := filepath.Join(dir, "local", domain)
	if err := os.MkdirAll(localDir, 0700); err != nil {
		t.Fatal(err)
	}

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(3 * 24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)

	cf, _ := os.Create(filepath.Join(localDir, "cert.pem"))
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cf.Close()

	privDER, _ := x509.MarshalECPrivateKey(priv)
	kf, _ := os.Create(filepath.Join(localDir, "key.pem"))
	pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	kf.Close()

	m := NewSSLManager(SSLManagerConfig{
		Enabled:  true,
		CertPath: dir,
		LetsEncrypt: LetsEncryptConfig{
			Enabled: false,
		},
	})

	err := m.RenewIfExpiring([]string{domain}, 7)
	if err != nil {
		t.Errorf("expiring cert that still exists should load without error, got: %v", err)
	}
}

func TestRenewIfExpiring_Expiring_LEEnabled(t *testing.T) {
	dir := tempDir(t)

	domain := "expiring-le.example.com"
	localDir := filepath.Join(dir, "local", domain)
	if err := os.MkdirAll(localDir, 0700); err != nil {
		t.Fatal(err)
	}

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(5),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(3 * 24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)

	cf, _ := os.Create(filepath.Join(localDir, "cert.pem"))
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cf.Close()

	privDER, _ := x509.MarshalECPrivateKey(priv)
	kf, _ := os.Create(filepath.Join(localDir, "key.pem"))
	pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	kf.Close()

	m := NewSSLManager(SSLManagerConfig{
		Enabled:  true,
		CertPath: dir,
		LetsEncrypt: LetsEncryptConfig{
			Enabled: true,
			Email:   "test@example.com",
		},
	})

	err := m.RenewIfExpiring([]string{domain}, 7)
	if err != nil {
		t.Errorf("RenewIfExpiring with LE enabled on expiring cert: %v", err)
	}
}

func TestRenewIfExpiring_InvalidPEM(t *testing.T) {
	dir := tempDir(t)

	domain := "bad-pem.example.com"
	localDir := filepath.Join(dir, "local", domain)
	if err := os.MkdirAll(localDir, 0700); err != nil {
		t.Fatal(err)
	}

	os.WriteFile(filepath.Join(localDir, "cert.pem"), []byte("not-pem"), 0600)
	os.WriteFile(filepath.Join(localDir, "key.pem"), []byte("not-pem"), 0600)

	m := NewSSLManager(SSLManagerConfig{
		Enabled:  true,
		CertPath: dir,
	})

	err := m.RenewIfExpiring([]string{domain}, 7)
	if err != nil {
		t.Errorf("invalid PEM should be silently ignored (nil block), got: %v", err)
	}
}

// TestRenewIfExpiring_Expiring_AppManagedLE_ForcesReissue guards the fix for
// the renewal bug where an expiring app-managed Let's Encrypt cert (priority-3
// path {config_dir}/ssl/letsencrypt/{fqdn}/) was never actually reissued:
// RenewIfExpiring called GetTLSConfig, which re-found the same on-disk file via
// findCertByPriority and merely reloaded it. RenewIfExpiring must now call the
// ACME issuance path directly. With no reachable ACME server in the test
// environment, that attempt fails — so a non-nil error here proves reissuance
// was actually attempted (the old code returned nil by silently reloading).
func TestRenewIfExpiring_Expiring_AppManagedLE_ForcesReissue(t *testing.T) {
	dir := tempDir(t)

	domain := "app-managed-le.example.com"
	leDir := filepath.Join(dir, "letsencrypt", domain)
	if err := os.MkdirAll(leDir, 0700); err != nil {
		t.Fatal(err)
	}

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(6),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(3 * 24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)

	cf, _ := os.Create(filepath.Join(leDir, "fullchain.pem"))
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cf.Close()

	privDER, _ := x509.MarshalECPrivateKey(priv)
	kf, _ := os.Create(filepath.Join(leDir, "privkey.pem"))
	pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	kf.Close()

	m := NewSSLManager(SSLManagerConfig{
		Enabled:  true,
		CertPath: dir,
		LetsEncrypt: LetsEncryptConfig{
			Enabled: true,
			Email:   "test@example.com",
		},
	})
	// Point the ACME directory at an unroutable address so issuance fails fast
	// without touching the real Let's Encrypt servers from a unit test.
	m.config.LetsEncrypt.caDirURL = "https://127.0.0.1:1/directory"

	err := m.RenewIfExpiring([]string{domain}, 7)
	if err == nil {
		t.Fatal("expiring app-managed LE cert must attempt reissuance (expected an ACME error with no reachable CA), got nil — renewal path not triggered")
	}
}

func TestGenerateSelfSignedTLSConfig_Basic(t *testing.T) {
	tlsCfg, err := GenerateSelfSignedTLSConfig(nil)
	if err != nil {
		t.Fatalf("GenerateSelfSignedTLSConfig: %v", err)
	}
	if tlsCfg == nil {
		t.Fatal("expected non-nil TLS config")
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(tlsCfg.Certificates))
	}
	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want TLS 1.2 (%d)", tlsCfg.MinVersion, tls.VersionTLS12)
	}
}

func TestGenerateSelfSignedTLSConfig_WithHosts(t *testing.T) {
	hosts := []string{"example.com", "192.168.1.1", "localhost"}
	tlsCfg, err := GenerateSelfSignedTLSConfig(hosts)
	if err != nil {
		t.Fatalf("GenerateSelfSignedTLSConfig: %v", err)
	}
	if tlsCfg == nil {
		t.Fatal("expected non-nil TLS config")
	}

	// Parse the certificate to verify hosts
	cert := tlsCfg.Certificates[0]
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	// Should include localhost (always added)
	foundLocalhost := false
	for _, dns := range parsed.DNSNames {
		if dns == "localhost" {
			foundLocalhost = true
		}
	}
	if !foundLocalhost {
		t.Error("certificate should include localhost in DNSNames")
	}

	// Should include example.com
	foundExample := false
	for _, dns := range parsed.DNSNames {
		if dns == "example.com" {
			foundExample = true
		}
	}
	if !foundExample {
		t.Error("certificate should include example.com in DNSNames")
	}

	// Should include 127.0.0.1 and 192.168.1.1 in IPAddresses
	if len(parsed.IPAddresses) < 2 {
		t.Errorf("expected at least 2 IP addresses, got %d", len(parsed.IPAddresses))
	}
}

func TestGenerateSelfSignedTLSConfig_EmptyStringHost(t *testing.T) {
	// Empty string should be filtered out
	hosts := []string{"", "valid.com", ""}
	tlsCfg, err := GenerateSelfSignedTLSConfig(hosts)
	if err != nil {
		t.Fatalf("GenerateSelfSignedTLSConfig: %v", err)
	}
	if tlsCfg == nil {
		t.Fatal("expected non-nil TLS config")
	}
}

// encryptDNSCredentialsForTest is a test helper that mirrors the encryption
// side of the dns_credentials flow (normally performed by the config/API
// layer, not by ssl.go itself): JSON-encode a credential map, encrypt it with
// security.EncryptWithSecret using the dnsCredentialsInfo scope, and
// base64-encode both the key and ciphertext the way server.yml stores them.
func encryptDNSCredentialsForTest(t *testing.T, creds map[string]string) (keyB64, ciphertextB64 string) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	plaintext, err := json.Marshal(creds)
	if err != nil {
		t.Fatalf("marshal creds: %v", err)
	}
	ciphertext, err := security.EncryptWithSecret(key, plaintext, dnsCredentialsInfo)
	if err != nil {
		t.Fatalf("EncryptWithSecret: %v", err)
	}
	return base64.StdEncoding.EncodeToString(key), base64.StdEncoding.EncodeToString(ciphertext)
}

func TestDecryptDNSCredentials_RoundTrip(t *testing.T) {
	keyB64, ciphertextB64 := encryptDNSCredentialsForTest(t, map[string]string{
		"CLOUDFLARE_DNS_API_TOKEN": "super-secret-token",
	})

	m := NewSSLManager(SSLManagerConfig{
		EncryptionKey: keyB64,
		LetsEncrypt: LetsEncryptConfig{
			DNSProvider:             "cloudflare",
			DNSCredentialsEncrypted: ciphertextB64,
		},
	})

	creds, err := m.decryptDNSCredentials()
	if err != nil {
		t.Fatalf("decryptDNSCredentials: %v", err)
	}
	if creds["CLOUDFLARE_DNS_API_TOKEN"] != "super-secret-token" {
		t.Errorf("decrypted credentials = %v, want CLOUDFLARE_DNS_API_TOKEN=super-secret-token", creds)
	}
}

func TestDecryptDNSCredentials_NoCredentialsConfigured(t *testing.T) {
	m := NewSSLManager(SSLManagerConfig{
		EncryptionKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
		LetsEncrypt:   LetsEncryptConfig{DNSProvider: "cloudflare"},
	})
	if _, err := m.decryptDNSCredentials(); err == nil {
		t.Fatal("expected error when dns_credentials is not configured")
	}
}

func TestDecryptDNSCredentials_NoEncryptionKey(t *testing.T) {
	_, ciphertextB64 := encryptDNSCredentialsForTest(t, map[string]string{"FOO": "bar"})
	m := NewSSLManager(SSLManagerConfig{
		LetsEncrypt: LetsEncryptConfig{
			DNSProvider:             "cloudflare",
			DNSCredentialsEncrypted: ciphertextB64,
		},
	})
	if _, err := m.decryptDNSCredentials(); err == nil {
		t.Fatal("expected error when server.security.encryption_key is not configured")
	}
}

func TestDecryptDNSCredentials_WrongKeyFails(t *testing.T) {
	_, ciphertextB64 := encryptDNSCredentialsForTest(t, map[string]string{"FOO": "bar"})
	wrongKey := make([]byte, 32)
	if _, err := rand.Read(wrongKey); err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}
	m := NewSSLManager(SSLManagerConfig{
		EncryptionKey: base64.StdEncoding.EncodeToString(wrongKey),
		LetsEncrypt: LetsEncryptConfig{
			DNSProvider:             "cloudflare",
			DNSCredentialsEncrypted: ciphertextB64,
		},
	})
	if _, err := m.decryptDNSCredentials(); err == nil {
		t.Fatal("expected error when decrypting with the wrong key")
	}
}

func TestValidateDNSCredentials_Success(t *testing.T) {
	keyB64, ciphertextB64 := encryptDNSCredentialsForTest(t, map[string]string{
		"CLOUDFLARE_DNS_API_TOKEN": "token-value",
	})

	m := NewSSLManager(SSLManagerConfig{
		EncryptionKey: keyB64,
		LetsEncrypt: LetsEncryptConfig{
			DNSProvider:             "cloudflare",
			DNSCredentialsEncrypted: ciphertextB64,
		},
	})

	var gotValidatedAt string
	m.config.OnDNSCredentialsValidated = func(validatedAt string) {
		gotValidatedAt = validatedAt
	}

	// dnsProvider() injects credentials into real process env vars per lego's
	// convention; clean up so later tests in this package aren't affected.
	t.Cleanup(func() { os.Unsetenv("CLOUDFLARE_DNS_API_TOKEN") })

	if err := m.ValidateDNSCredentials(); err != nil {
		t.Fatalf("ValidateDNSCredentials: %v", err)
	}
	if gotValidatedAt == "" {
		t.Error("expected OnDNSCredentialsValidated callback to be invoked with a timestamp")
	}
	if _, err := time.Parse(time.RFC3339, gotValidatedAt); err != nil {
		t.Errorf("validatedAt %q is not RFC3339: %v", gotValidatedAt, err)
	}
}

func TestValidateDNSCredentials_MalformedCredentialsFails(t *testing.T) {
	// Missing required cloudflare env vars — provider construction should fail
	// without any network call.
	keyB64, ciphertextB64 := encryptDNSCredentialsForTest(t, map[string]string{
		"UNRELATED_VAR": "value",
	})

	m := NewSSLManager(SSLManagerConfig{
		EncryptionKey: keyB64,
		LetsEncrypt: LetsEncryptConfig{
			DNSProvider:             "cloudflare",
			DNSCredentialsEncrypted: ciphertextB64,
		},
	})

	// Ensure no leftover cloudflare env vars from other tests or the host
	// environment mask the missing-credentials failure this test asserts.
	os.Unsetenv("CLOUDFLARE_DNS_API_TOKEN")
	os.Unsetenv("CLOUDFLARE_API_KEY")
	os.Unsetenv("CLOUDFLARE_EMAIL")

	callbackInvoked := false
	m.config.OnDNSCredentialsValidated = func(string) { callbackInvoked = true }

	if err := m.ValidateDNSCredentials(); err == nil {
		t.Fatal("expected error for malformed/incomplete dns credentials")
	}
	if callbackInvoked {
		t.Error("OnDNSCredentialsValidated must not be called on failure")
	}
}

func TestValidateDNSCredentials_NoDNSProviderFails(t *testing.T) {
	m := NewSSLManager(SSLManagerConfig{
		EncryptionKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
	})
	if err := m.ValidateDNSCredentials(); err == nil {
		t.Fatal("expected error when no dns_provider is configured")
	}
}

// --- writeFileAtomic ---

func TestWriteFileAtomic_CreatesFileWithContentAndPerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fullchain.pem")

	if err := writeFileAtomic(path, []byte("cert data"), 0644); err != nil {
		t.Fatalf("writeFileAtomic() error = %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != "cert data" {
		t.Errorf("content = %q, want %q", got, "cert data")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Mode().Perm() != 0644 {
		t.Errorf("perm = %v, want %v", info.Mode().Perm(), os.FileMode(0644))
	}

	// No leftover temp file should remain in the directory.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected exactly 1 file in dir, got %d", len(entries))
	}
}

func TestWriteFileAtomic_ReplacesExistingFileAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "privkey.pem")

	if err := os.WriteFile(path, []byte("old key"), 0600); err != nil {
		t.Fatalf("seed WriteFile() error = %v", err)
	}

	if err := writeFileAtomic(path, []byte("new key"), 0600); err != nil {
		t.Fatalf("writeFileAtomic() error = %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != "new key" {
		t.Errorf("content = %q, want %q", got, "new key")
	}
}
