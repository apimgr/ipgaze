package ssl

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"

	"github.com/apimgr/ipgaze/src/security"
)

// dnsCredentialsInfo is the HKDF "info" string scoping DNS credential encryption,
// keeping it distinct from other uses of server.security.encryption_key.
const dnsCredentialsInfo = "dns_credentials"

// Config holds SSL/TLS configuration
type SSLManagerConfig struct {
	Enabled     bool
	CertPath    string
	LetsEncrypt LetsEncryptConfig
	// EncryptionKey is the base64-encoded 32-byte AES-256-GCM key (server.security.encryption_key)
	// used to decrypt DNSCredentialsEncrypted at the point of use, per AI.md PART 11/PART 15.
	EncryptionKey string
	// OnDNSCredentialsValidated is called with an RFC3339 timestamp after a successful
	// DNS-01 credential validation, so the caller can persist dns_credentials.validated_at.
	OnDNSCredentialsValidated func(validatedAt string)
}

// LetsEncryptConfig holds Let's Encrypt settings
type LetsEncryptConfig struct {
	Enabled bool
	Email   string
	Staging bool
	// Challenge selects the ACME challenge type: "http-01" (default), "tls-alpn-01", or "dns-01".
	Challenge string
	// DNSProvider is the lego DNS provider name (e.g. "cloudflare", "route53", "digitalocean"),
	// used only when Challenge is "dns-01". See https://go-acme.github.io/lego/dns/ for the full list.
	DNSProvider string
	// DNSCredentialsEncrypted is the base64-encoded AES-256-GCM ciphertext of the JSON-encoded
	// provider credential map, decrypted at the point of use and never cached longer than
	// necessary. Used only when Challenge is "dns-01". Per AI.md PART 15.
	DNSCredentialsEncrypted string
	// caDirURL overrides the ACME directory URL when set, bypassing the Staging/Production
	// selection below. Unexported: internal test seam only, never populated from config/CLI/env.
	caDirURL string
}

// Manager handles SSL/TLS certificates
type SSLManager struct {
	config          SSLManagerConfig
	challengeServer *ChallengeServer
	mu              sync.RWMutex
}

// NewSSLManager creates a new SSL manager
func NewSSLManager(cfg SSLManagerConfig) *SSLManager {
	return &SSLManager{
		config:          cfg,
		challengeServer: NewChallengeServer(),
	}
}

// GetTLSConfig returns TLS configuration for the server.
// Certificate lookup follows the priority order from AI.md PART 15:
//  1. /etc/letsencrypt/live/domain/     (literal "domain" — certbot shared setup)
//  2. /etc/letsencrypt/live/{fqdn}/     (FQDN-named certbot directory)
//  3. {config_dir}/ssl/letsencrypt/{fqdn}/ (app-managed Let's Encrypt certs)
//  4. {config_dir}/ssl/local/{fqdn}/    (user-provided certs, no auto-renewal)
//  5. Request new cert via Let's Encrypt if enabled
func (m *SSLManager) GetTLSConfig(domains []string) (*tls.Config, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.config.Enabled {
		return nil, nil
	}

	// Walk the 4-step priority lookup before requesting a new cert.
	if cert, key := m.findCertByPriority(domains); cert != "" && key != "" {
		log.Printf("Using existing certificate: %s", cert)
		tlsCert, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate: %w", err)
		}
		return &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
		}, nil
	}

	// No existing cert found — request via Let's Encrypt if enabled.
	if m.config.LetsEncrypt.Enabled {
		return m.getLetsEncryptTLSConfig(domains)
	}

	return nil, fmt.Errorf("no certificates available and Let's Encrypt not enabled")
}

// getLetsEncryptTLSConfig runs the ACME issuance flow (via obtainLetsEncryptCert)
// and loads the resulting certificate. Certificates are stored under
// {config_dir}/ssl/letsencrypt/{fqdn}/ per AI.md PART 15 (priority-3 lookup path).
func (m *SSLManager) getLetsEncryptTLSConfig(domains []string) (*tls.Config, error) {
	certPath, keyPath, err := m.obtainLetsEncryptCert(domains)
	if err != nil {
		return nil, err
	}
	tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load issued certificate: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// obtainLetsEncryptCert runs the ACME issuance flow via go-acme/lego, using the
// configured challenge type (http-01, tls-alpn-01, or dns-01) per AI.md PART 15,
// and writes the resulting certificate to {config_dir}/ssl/letsencrypt/{fqdn}/.
func (m *SSLManager) obtainLetsEncryptCert(domains []string) (certPath, keyPath string, err error) {
	if len(domains) == 0 {
		return "", "", fmt.Errorf("no domains configured for Let's Encrypt")
	}

	accountKey, err := m.loadOrCreateAccountKey()
	if err != nil {
		return "", "", err
	}

	user := &acmeUser{
		email:        m.config.LetsEncrypt.Email,
		registration: m.loadRegistration(),
		key:          accountKey,
	}

	legoCfg := lego.NewConfig(user)
	legoCfg.Certificate.KeyType = certcrypto.EC256
	switch {
	case m.config.LetsEncrypt.caDirURL != "":
		legoCfg.CADirURL = m.config.LetsEncrypt.caDirURL
	case m.config.LetsEncrypt.Staging:
		legoCfg.CADirURL = lego.LEDirectoryStaging
	default:
		legoCfg.CADirURL = lego.LEDirectoryProduction
	}

	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return "", "", fmt.Errorf("lego client: %w", err)
	}

	if ParseChallenge(m.config.LetsEncrypt.Challenge) == "dns-01" {
		if err := m.ValidateDNSCredentials(); err != nil {
			return "", "", fmt.Errorf("dns-01 credential validation failed: %w", err)
		}
	}

	closeChallenge, err := m.setChallengeProvider(client)
	if err != nil {
		return "", "", err
	}
	defer closeChallenge()

	if user.registration == nil {
		reg, regErr := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if regErr != nil {
			return "", "", fmt.Errorf("acme registration: %w", regErr)
		}
		user.registration = reg
		if saveErr := m.saveRegistration(reg); saveErr != nil {
			log.Printf("SSL: failed to persist ACME registration: %v", saveErr)
		}
	}

	certs, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	})
	if err != nil {
		return "", "", fmt.Errorf("obtain certificate: %w", err)
	}

	outDir := filepath.Join(m.config.CertPath, "letsencrypt", domains[0])
	if err := os.MkdirAll(outDir, 0700); err != nil {
		return "", "", fmt.Errorf("create cert dir: %w", err)
	}
	certPath = filepath.Join(outDir, "fullchain.pem")
	keyPath = filepath.Join(outDir, "privkey.pem")
	if err := writeFileAtomic(certPath, certs.Certificate, 0644); err != nil {
		return "", "", fmt.Errorf("write fullchain: %w", err)
	}
	if err := writeFileAtomic(keyPath, certs.PrivateKey, 0600); err != nil {
		return "", "", fmt.Errorf("write privkey: %w", err)
	}

	return certPath, keyPath, nil
}

// writeFileAtomic writes data to a temp file in the same directory as path,
// then renames it into place. This ensures a concurrent reader (e.g. the
// HTTPS server's certificate reload watcher) never observes a partially
// written fullchain.pem/privkey.pem, and a crash mid-write never leaves a
// truncated cert/key file live — only the old file or the new one, never a
// half-written one.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// setChallengeProvider wires the configured challenge type into the lego client.
// For http-01 and tls-alpn-01 it stands up a temporary listener on the
// validation port (:80 / :443) for the duration of the issuance call, since
// GetTLSConfig runs before the real HTTP/HTTPS servers bind those ports. The
// returned func tears the temporary listener down; callers must defer it.
func (m *SSLManager) setChallengeProvider(client *lego.Client) (func(), error) {
	switch ParseChallenge(m.config.LetsEncrypt.Challenge) {
	case "dns-01":
		provider, err := m.dnsProvider()
		if err != nil {
			return nil, err
		}
		if err := client.Challenge.SetDNS01Provider(provider); err != nil {
			return nil, fmt.Errorf("dns-01 provider: %w", err)
		}
		return func() {}, nil

	case "tls-alpn-01":
		provider := newTLSALPNProvider()
		listener, err := net.Listen("tcp", ":443")
		if err != nil {
			return nil, fmt.Errorf("tls-alpn-01: listen :443: %w", err)
		}
		srv := &http.Server{TLSConfig: provider.tlsConfig()}
		go func() {
			_ = srv.ServeTLS(listener, "", "")
		}()
		if err := client.Challenge.SetTLSALPN01Provider(provider); err != nil {
			srv.Close()
			return nil, fmt.Errorf("tls-alpn-01 provider: %w", err)
		}
		return func() { srv.Close() }, nil

	default:
		listener, err := net.Listen("tcp", ":80")
		if err != nil {
			return nil, fmt.Errorf("http-01: listen :80: %w", err)
		}
		srv := &http.Server{Handler: m.GetHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}))}
		go func() {
			_ = srv.Serve(listener)
		}()
		if err := client.Challenge.SetHTTP01Provider(newHTTP01Provider(m.challengeServer)); err != nil {
			srv.Close()
			return nil, fmt.Errorf("http-01 provider: %w", err)
		}
		return func() { srv.Close() }, nil
	}
}

// decryptDNSCredentials decrypts DNSCredentialsEncrypted at the point of use with
// server.security.encryption_key (AES-256-GCM via HKDF-SHA256), returning the
// plaintext provider credential map. The decrypted map must never be cached or
// persisted — callers use it immediately and let it fall out of scope.
func (m *SSLManager) decryptDNSCredentials() (map[string]string, error) {
	encrypted := strings.TrimSpace(m.config.LetsEncrypt.DNSCredentialsEncrypted)
	if encrypted == "" {
		return nil, fmt.Errorf("dns-01 challenge selected but no dns_credentials configured")
	}
	keyB64 := strings.TrimSpace(m.config.EncryptionKey)
	if keyB64 == "" {
		return nil, fmt.Errorf("server.security.encryption_key is not configured; cannot decrypt dns_credentials")
	}
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("decode server.security.encryption_key: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, fmt.Errorf("decode dns_credentials.credentials_encrypted: %w", err)
	}
	plaintext, err := security.DecryptWithSecret(key, ciphertext, dnsCredentialsInfo)
	if err != nil {
		return nil, fmt.Errorf("decrypt dns_credentials: %w", err)
	}
	var creds map[string]string
	if err := json.Unmarshal(plaintext, &creds); err != nil {
		return nil, fmt.Errorf("parse decrypted dns_credentials: %w", err)
	}
	return creds, nil
}

// ReencryptDNSCredentialsEncrypted decrypts encryptedB64 (server.security.encryption_key
// -encrypted DNS-01 provider credentials) with oldKey and re-encrypts the same
// plaintext under newKey, returning the new base64 ciphertext. Used by
// `--maintenance secret rotate encryption_key` (AI.md PART 11 "Secret Rotation")
// to re-encrypt at-rest data under the freshly rotated key. Returns ("", nil)
// if encryptedB64 is empty (nothing configured yet).
func ReencryptDNSCredentialsEncrypted(encryptedB64 string, oldKey, newKey []byte) (string, error) {
	encryptedB64 = strings.TrimSpace(encryptedB64)
	if encryptedB64 == "" {
		return "", nil
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedB64)
	if err != nil {
		return "", fmt.Errorf("decode dns_credentials.credentials_encrypted: %w", err)
	}
	plaintext, err := security.DecryptWithSecret(oldKey, ciphertext, dnsCredentialsInfo)
	if err != nil {
		return "", fmt.Errorf("decrypt dns_credentials with previous key: %w", err)
	}
	sealed, err := security.EncryptWithSecret(newKey, plaintext, dnsCredentialsInfo)
	if err != nil {
		return "", fmt.Errorf("re-encrypt dns_credentials: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// ValidateDNSCredentials decrypts the configured DNS-01 credentials and attempts to
// construct the lego DNS provider, catching malformed or missing fields without
// performing any network calls. On success it invokes OnDNSCredentialsValidated
// with the current time (RFC3339) so the caller can persist dns_credentials.validated_at.
// Called on startup (if dns_provider + dns_credentials are configured) and before
// every certificate request, per AI.md PART 15.
func (m *SSLManager) ValidateDNSCredentials() error {
	if _, err := m.dnsProvider(); err != nil {
		return err
	}
	if m.config.OnDNSCredentialsValidated != nil {
		m.config.OnDNSCredentialsValidated(time.Now().UTC().Format(time.RFC3339))
	}
	return nil
}

// dnsProvider builds a lego DNS-01 challenge provider from the configured
// provider name, decrypting DNSCredentialsEncrypted and injecting the result as
// environment variables per lego's per-provider configuration convention
// (e.g. CLOUDFLARE_API_TOKEN). This is the generic "all lego-supported providers"
// wiring — no per-provider Go code is needed beyond lego's own provider registry.
func (m *SSLManager) dnsProvider() (challenge.Provider, error) {
	name := strings.TrimSpace(m.config.LetsEncrypt.DNSProvider)
	if name == "" {
		return nil, fmt.Errorf("dns-01 challenge selected but no dns_provider configured")
	}
	creds, err := m.decryptDNSCredentials()
	if err != nil {
		return nil, err
	}
	for key, value := range creds {
		if err := os.Setenv(key, value); err != nil {
			return nil, fmt.Errorf("set env %s for dns provider %s: %w", key, name, err)
		}
	}
	// lego's provider constructors read their config from the environment
	// only during construction (via env.Get()/NewDefaultConfig()), so the
	// decrypted credentials are no longer needed afterward. Unset them
	// immediately so they are never left sitting in the process environment,
	// honoring decryptDNSCredentials' "never cached/persisted" contract.
	defer func() {
		for key := range creds {
			os.Unsetenv(key)
		}
	}()
	provider, err := dns.NewDNSChallengeProviderByName(name)
	if err != nil {
		return nil, fmt.Errorf("dns provider %q: %w", name, err)
	}
	return provider, nil
}

// acmeDir returns {config_dir}/ssl/letsencrypt/account/, where the ACME
// account private key and registration resource are persisted so the same
// account is reused across renewals instead of re-registering every time.
func (m *SSLManager) acmeDir() string {
	return filepath.Join(m.config.CertPath, "letsencrypt", "account")
}

// loadOrCreateAccountKey loads the persisted ACME account key, generating and
// persisting a new ECDSA P-256 key on first use.
func (m *SSLManager) loadOrCreateAccountKey() (*ecdsa.PrivateKey, error) {
	dir := m.acmeDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("acme account dir: %w", err)
	}

	keyPath := filepath.Join(dir, "account.key")
	if data, err := os.ReadFile(keyPath); err == nil {
		if block, _ := pem.Decode(data); block != nil {
			if key, parseErr := x509.ParseECPrivateKey(block.Bytes); parseErr == nil {
				return key, nil
			}
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate acme account key: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal acme account key: %w", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600); err != nil {
		return nil, fmt.Errorf("write acme account key: %w", err)
	}
	return key, nil
}

// loadRegistration loads a persisted ACME registration resource, if any.
func (m *SSLManager) loadRegistration() *registration.Resource {
	data, err := os.ReadFile(filepath.Join(m.acmeDir(), "registration.json"))
	if err != nil {
		return nil
	}
	var reg registration.Resource
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil
	}
	return &reg
}

// saveRegistration persists the ACME registration resource for reuse across renewals.
func (m *SSLManager) saveRegistration(reg *registration.Resource) error {
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal acme registration: %w", err)
	}
	return os.WriteFile(filepath.Join(m.acmeDir(), "registration.json"), data, 0600)
}

// acmeUser implements lego's registration.User interface.
type acmeUser struct {
	email        string
	registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// http01Provider adapts ChallengeServer to lego's challenge.Provider interface.
type http01Provider struct {
	cs *ChallengeServer
}

func newHTTP01Provider(cs *ChallengeServer) *http01Provider {
	return &http01Provider{cs: cs}
}

func (p *http01Provider) Present(_, token, keyAuth string) error {
	p.cs.SetToken(token, keyAuth)
	return nil
}

func (p *http01Provider) CleanUp(_, token, _ string) error {
	p.cs.ClearToken(token)
	return nil
}

// tlsALPNProvider adapts lego's tlsalpn01 challenge cert generation to the
// challenge.Provider interface, serving the validation cert via a temporary
// TLS listener on :443 during certificate issuance.
type tlsALPNProvider struct {
	mu    sync.RWMutex
	certs map[string]*tls.Certificate
}

func newTLSALPNProvider() *tlsALPNProvider {
	return &tlsALPNProvider{certs: make(map[string]*tls.Certificate)}
}

func (p *tlsALPNProvider) Present(domain, _, keyAuth string) error {
	cert, err := tlsalpn01.ChallengeCert(domain, keyAuth)
	if err != nil {
		return fmt.Errorf("tls-alpn-01: build challenge cert: %w", err)
	}
	p.mu.Lock()
	p.certs[domain] = cert
	p.mu.Unlock()
	return nil
}

func (p *tlsALPNProvider) CleanUp(domain, _, _ string) error {
	p.mu.Lock()
	delete(p.certs, domain)
	p.mu.Unlock()
	return nil
}

func (p *tlsALPNProvider) tlsConfig() *tls.Config {
	return &tls.Config{
		NextProtos: []string{tlsalpn01.ACMETLS1Protocol},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			p.mu.RLock()
			defer p.mu.RUnlock()
			cert, ok := p.certs[hello.ServerName]
			if !ok {
				return nil, fmt.Errorf("no tls-alpn-01 challenge certificate for %s", hello.ServerName)
			}
			return cert, nil
		},
	}
}

// GetHTTPHandler returns an HTTP handler that serves ACME HTTP-01 challenge
// responses (if any are pending), falling back to fallback otherwise.
func (m *SSLManager) GetHTTPHandler(fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.challengeServer.ServeHTTP(w, r) {
			return
		}
		fallback.ServeHTTP(w, r)
	})
}

// findCertByPriority checks all 4 certificate locations in the priority order
// defined by AI.md PART 15 "Certificate Lookup Order":
//  1. /etc/letsencrypt/live/domain/       (literal "domain" — certbot shared setup)
//  2. /etc/letsencrypt/live/{fqdn}/       (FQDN-named certbot directory)
//  3. {config_dir}/ssl/letsencrypt/{fqdn}/ (app-managed LE; fullchain.pem + privkey.pem)
//  4. {config_dir}/ssl/local/{fqdn}/      (user-provided; cert.pem + key.pem)
func (m *SSLManager) findCertByPriority(domains []string) (certPath, keyPath string) {
	// Priority 1: /etc/letsencrypt/live/domain/ (literal "domain" directory).
	cert := "/etc/letsencrypt/live/domain/fullchain.pem"
	key := "/etc/letsencrypt/live/domain/privkey.pem"
	if fileExists(cert) && fileExists(key) {
		return cert, key
	}

	// Priority 2: /etc/letsencrypt/live/{fqdn}/ for each domain.
	for _, domain := range domains {
		cert = filepath.Join("/etc/letsencrypt/live", domain, "fullchain.pem")
		key = filepath.Join("/etc/letsencrypt/live", domain, "privkey.pem")
		if fileExists(cert) && fileExists(key) {
			return cert, key
		}
	}

	// Priority 3: {config_dir}/ssl/letsencrypt/{fqdn}/ (app-managed LE certs).
	if m.config.CertPath != "" {
		for _, domain := range domains {
			cert = filepath.Join(m.config.CertPath, "letsencrypt", domain, "fullchain.pem")
			key = filepath.Join(m.config.CertPath, "letsencrypt", domain, "privkey.pem")
			if fileExists(cert) && fileExists(key) {
				return cert, key
			}
		}
	}

	// Priority 4: {config_dir}/ssl/local/{fqdn}/ (user-provided certs, no auto-renewal).
	if m.config.CertPath != "" {
		for _, domain := range domains {
			cert = filepath.Join(m.config.CertPath, "local", domain, "cert.pem")
			key = filepath.Join(m.config.CertPath, "local", domain, "key.pem")
			if fileExists(cert) && fileExists(key) {
				return cert, key
			}
		}
	}

	return "", ""
}

// ChallengeServer handles ACME HTTP-01 challenges
type ChallengeServer struct {
	tokens map[string]string
	mu     sync.RWMutex
}

// NewChallengeServer creates a challenge server
func NewChallengeServer() *ChallengeServer {
	return &ChallengeServer{
		tokens: make(map[string]string),
	}
}

// SetToken sets a challenge token
func (cs *ChallengeServer) SetToken(token, auth string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.tokens[token] = auth
}

// ClearToken removes a challenge token
func (cs *ChallengeServer) ClearToken(token string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	delete(cs.tokens, token)
}

// ServeHTTP handles ACME challenge requests
func (cs *ChallengeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
		return false
	}

	token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
	cs.mu.RLock()
	auth, ok := cs.tokens[token]
	cs.mu.RUnlock()

	if !ok {
		http.NotFound(w, r)
		return true
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(auth))
	return true
}

// ParseChallenge parses challenge type from string
func ParseChallenge(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "http-01", "http01", "http":
		return "http-01"
	case "tls-alpn-01", "tlsalpn01", "tls-alpn", "tls":
		return "tls-alpn-01"
	case "dns-01", "dns01", "dns":
		return "dns-01"
	default:
		return "http-01"
	}
}

// CertExpiry reads the currently active certificate (via the same priority
// lookup RenewIfExpiring uses) and returns its subject FQDN and NotAfter
// time. Callers use this after RenewIfExpiring to tell whether the on-disk
// certificate is still within the expiry window (renewal didn't happen —
// e.g. Let's Encrypt disabled or a priority-4 local cert) or now expires
// further out (an actual renewal took place), per AI.md PART 17's
// ssl_expiring/ssl_renewed notifications. ok is false when no cert exists yet.
func (m *SSLManager) CertExpiry(domains []string) (fqdn string, notAfter time.Time, ok bool) {
	certPath, _ := m.findCertByPriority(domains)
	if certPath == "" {
		return "", time.Time{}, false
	}
	data, err := os.ReadFile(certPath)
	if err != nil {
		return "", time.Time{}, false
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", time.Time{}, false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", time.Time{}, false
	}
	subject := cert.Subject.CommonName
	if len(cert.DNSNames) > 0 {
		subject = cert.DNSNames[0]
	}
	return subject, cert.NotAfter, true
}

// RenewIfExpiring checks certificate expiry and renews if within daysBeforeExpiry days.
// It is a no-op if no certificate has been provisioned yet.
func (m *SSLManager) RenewIfExpiring(domains []string, daysBeforeExpiry int) error {
	certPath, _ := m.findCertByPriority(domains)
	if certPath == "" {
		return nil
	}
	data, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	if time.Until(cert.NotAfter) > time.Duration(daysBeforeExpiry)*24*time.Hour {
		return nil
	}

	// The certificate is within the renewal window. Per AI.md PART 15's
	// certificate-ownership table, the app auto-renews ONLY certificates it
	// manages under {config_dir}/ssl/letsencrypt/{fqdn}/. Certbot-managed
	// (/etc/letsencrypt/live/**) and user-managed ({config_dir}/ssl/local/**)
	// certificates are renewed out-of-band and must never be reissued here.
	appManagedPrefix := filepath.Join(m.config.CertPath, "letsencrypt") + string(os.PathSeparator)
	if !m.config.LetsEncrypt.Enabled || !strings.HasPrefix(certPath, appManagedPrefix) {
		return nil
	}

	// Force a fresh ACME issuance. GetTLSConfig cannot renew here: it calls
	// findCertByPriority, which still finds the existing (near-expiry) file on
	// disk and short-circuits to reloading it, so it would never re-obtain
	// while the old cert is present. Call obtainLetsEncryptCert directly to
	// overwrite the app-managed cert in place with a freshly issued one.
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, _, err := m.obtainLetsEncryptCert(domains); err != nil {
		return fmt.Errorf("renew app-managed certificate for %v: %w", domains, err)
	}
	return nil
}

// GenerateSelfSignedTLSConfig generates an in-memory ECDSA P-256 self-signed
// certificate for development/local mode per AI.md PART 15.
// The cert is valid for 1 year and covers the provided hostnames + localhost + 127.0.0.1.
func GenerateSelfSignedTLSConfig(hosts []string) (*tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("self-signed: generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("self-signed: serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"ipgaze (self-signed)"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Always include localhost and 127.0.0.1 for local dev
	tmpl.DNSNames = append(tmpl.DNSNames, "localhost")
	tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" && h != "localhost" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("self-signed: create cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("self-signed: marshal key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})

	tlsCert, err := tls.X509KeyPair(certPEM, privPEM)
	if err != nil {
		return nil, fmt.Errorf("self-signed: load pair: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
