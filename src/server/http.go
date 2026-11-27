package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apimgr/ipgaze/src/blocklist"
	"github.com/apimgr/ipgaze/src/common/httputil"
	"github.com/apimgr/ipgaze/src/common/i18n"
	"github.com/apimgr/ipgaze/src/common/theme"
	"github.com/apimgr/ipgaze/src/config"
	dbstore "github.com/apimgr/ipgaze/src/db"
	"github.com/apimgr/ipgaze/src/email"
	"github.com/apimgr/ipgaze/src/iputil/geo"
	applog "github.com/apimgr/ipgaze/src/log"
	"github.com/apimgr/ipgaze/src/netutil"
	"github.com/apimgr/ipgaze/src/pgp"
	"github.com/apimgr/ipgaze/src/scheduler"
	"github.com/apimgr/ipgaze/src/security"
	"github.com/apimgr/ipgaze/src/server/handler"
	"github.com/apimgr/ipgaze/src/server/model"
	"github.com/apimgr/ipgaze/src/server/service"
	"github.com/apimgr/ipgaze/src/swagger"
	"github.com/apimgr/ipgaze/src/threat"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/cors"
)

const (
	jsonMediaType = "application/json"
	textMediaType = "text/plain"
	// defaultLogoURL is the project default branding logo, used when the
	// operator has not set server.branding.logo in server.yml.
	defaultLogoURL = "https://avatars.githubusercontent.com/u/126880?v=4"
)

// cliVersionEntry holds a platform-specific CLI binary version and its SHA-256 digest.
// Used in the /api/autodiscover response (AI.md PART 32).
type cliVersionEntry struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// Server holds the HTTP server's request-scoped dependencies: the trusted
// reverse-DNS and port-probe hooks, GeoIP reader, response
// cache, templates, and the resolved runtime configuration.
type Server struct {
	LookupAddr func(net.IP) (string, error)
	LookupPort func(net.IP, uint64) error
	BaseURL    string
	// DataDir is the runtime data directory; used for serving CLI binaries (AI.md PART 32).
	DataDir string
	// ConfigDir is the runtime config directory; used to locate the PGP keypair
	// at {config_dir}/security/pgp.pub.asc (AI.md PART 11 "GPG Keypair Management").
	ConfigDir string
	cache     *Cache
	gr        geo.Reader
	ipService *service.IPLookupService
	// ipServiceOnce guards lazy creation of ipService so concurrent first
	// requests do not race on the pointer write (all Set*/config wiring runs
	// at startup before any request, so a one-time init is sufficient).
	ipServiceOnce sync.Once
	cfg           interface{}
	// config is the typed application config, set via SetConfig.
	config *config.AppConfig
	// configManager exposes restart-required file changes through health status.
	configManager *config.ConfigManager
	// router holds the chi.Router for debug route inspection.
	router chi.Router
	// apiOperationIDs identifies documented API operations registered by the
	// active route table, for MCP tool discovery and llms.txt endpoint listing.
	apiOperationIDs map[string]struct{}
	// apiRoutes contains the handler-bearing route values mounted by the active
	// router. Documentation and discovery receive snapshots of these same values.
	routesMu        sync.RWMutex
	activeAPIRoutes []swagger.Route
	// handlerMu protects the active request handler while a file-backed config
	// change rebuilds middleware and routes. Requests already in flight finish
	// on the previous handler before the swap proceeds.
	handlerMu     sync.RWMutex
	activeHandler http.Handler
	// sched holds the scheduler for /debug/scheduler status.
	sched *scheduler.Scheduler
	// sqlDB holds the database connection for /debug/db stats.
	sqlDB              *dbstore.Store
	PagesHandler       *handler.PagesHandler
	SpecialHandler     *handler.SpecialHandler
	HealthHandler      *handler.HealthHandler
	CacheHandler       *handler.CacheHandler
	SSLEnabled         bool
	SwaggerHandler     http.HandlerFunc
	SwaggerJSONHandler http.HandlerFunc
	GraphQLHandler     http.HandlerFunc
	// Health check info per PART 16
	StartTime time.Time
	Version   string
	CommitID  string
	// BuildDate is the compile-time build timestamp (ldflag main.BuildDate),
	// threaded into HealthHandler/PagesHandler for footer/health display (AI.md
	// "Footer Customization" -> {build_datetime}).
	BuildDate string
	Mode      string
	// TorStatus reports Tor availability/running state; nil means Tor not
	// configured or binary not found (AI.md PART 31, "Footer Customization").
	TorStatus handler.TorStatusProvider
	// I2PStatus reports I2P eepsite availability/running state; nil means I2P
	// disabled or no provider found (AI.md PART 31.2, opt-in).
	I2PStatus handler.I2PStatusProvider
	// TorControl is the live Tor manager driving the INTERNAL /server/tor/*
	// control channel (AI.md PART 31.1). Nil means the control channel is not
	// available and its routes answer 404 like any unknown path.
	TorControl TorController
	// HealthzRootEnabled controls whether /healthz root alias is registered.
	// Per AI.md PART 13: optional, gated by server.healthz.root.enabled config.
	HealthzRootEnabled bool
	// Metrics configuration
	metricsEnabled bool
	metricsConfig  config.MetricsConfig
	// Middleware components
	// maintenance holds the read-only maintenance flag and its operator
	// guidance (AI.md PART 12 "Maintenance Mode").
	maintenance maintenanceState
	// reportLimiter caps the unauthenticated browser-report endpoints per
	// source IP (AI.md PART 11 "Reports Endpoint"); nil means unlimited.
	reportLimiter       *ReportRateLimiter
	rateLimiter         *RateLimiter
	allowlistLookup     *AllowlistLookup
	blocklistLookup     *blocklist.Lookup
	threatLookup        *threat.Lookup
	geoipDenyCountries  []string
	geoipAllowCountries []string
	// operatorTokenHash is the SHA-256 hash of server.token, cached at startup.
	// Per AI.md PART 11: hash is never written to DB; raw token is never stored beyond config file.
	operatorTokenHash [32]byte
	// hasOperatorToken indicates whether a non-empty operator token was configured.
	hasOperatorToken bool
	// trust is the trusted-proxy resolver; caches DNS and auto-trusts the listen /24.
	trust *netutil.TrustResolver
	// publicIP is the cached external public IP of this server, refreshed every 12h
	// by the public_ip_refresh scheduler task (AI.md PART 18).
	publicIP   string
	publicIPMu sync.RWMutex
	// logManager writes to per-category log files (AI.md PART 11).
	logManager *applog.Manager
	// emailMgr sends contact-form/notification email once SMTP is configured
	// (AI.md PART 12); nil means email delivery is disabled.
	emailMgr *email.EmailManager
	// HostIPv4 is the host's public IPv4 address, set via HOST_IPV4 env var.
	// Used in HTML template curl examples when the server is behind NAT (e.g. containers).
	// Must be a valid IPv4 address; empty means use r.Host.
	HostIPv4 string
	// HostIPv6 is the host's public IPv6 address, set via HOST_IPV6 env var.
	// Used in HTML template curl examples when the server is behind NAT (e.g. containers).
	// Must be a valid IPv6 address; empty means use r.Host.
	HostIPv6 string
	// reqStats tracks always-on request counters for the healthz stats block (PART 13).
	reqStats *requestStats
	// cacheBackend is the configured cache.Cache used for the checks.cache probe (PART 9/13).
	cacheBackend cacheBackendPinger
	// diskUsageFunc reports free bytes and used-percent for DataDir, used for checks.disk (PART 13).
	diskUsageFunc func(path string) (uint64, int, error)
	// brandingCache holds the locally-fetched/cached branding logo served at
	// /branding/logo, so the page never hotlinks the remote logo URL
	// directly (AI.md "Branding & SEO" → "Remote URL Fetching").
	brandingCache *brandingLogoCache
}

// cacheBackendPinger is satisfied by cache.Cache (and test stubs); it is the
// minimal surface the health handler needs to probe the configured cache backend.
type cacheBackendPinger interface {
	Ping(ctx context.Context) error
}

// AssetStamp returns the {project_version}-{short_commit} cache-busting
// stamp appended to every static asset URL as "?v=" (AI.md PART 9 "Asset
// Version-Busting (REQUIRED)"). CommitID is already the short hash
// (git rev-parse --short HEAD), matching {short_commit}.
func (s *Server) AssetStamp() string {
	return s.Version + "-" + s.CommitID
}

func (s *Server) themeCSSHandler() http.HandlerFunc {
	css := theme.CSSVariables()
	stamp := s.AssetStamp()
	etag := `"` + stamp + `"`
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		if r.URL.Query().Get("v") == stamp {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") == etag || r.Header.Get("If-None-Match") == "*" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = io.WriteString(w, css)
	}
}

// versionCookieName is the build-stamp cookie used by applyVersionPurge
// (AI.md PART 9 "Version-Change Purge (Clear-Site-Data)").
const versionCookieName = "ipgaze_build"

// applyVersionPurge implements AI.md PART 9's "Version-Change Purge
// (Clear-Site-Data)": recovery for a browser that already cached HTML or a
// service worker from an older build. If the request's ipgaze_build cookie
// disagrees with the running AssetStamp, the response is told to evict the
// HTTP cache, Cache API entries, and service workers in one shot — "cookies"
// is deliberately never included, since that would also destroy the
// owner_token cookie and cookie-stored preferences (theme, language,
// consent). The cookie is always reset to the current stamp in the same
// response, so the purge is naturally one-shot; a first-ever visit (no
// cookie) never purges. Call only from HTML response paths — never for
// static, API, or /sw.js/manifest.json responses.
func applyVersionPurge(w http.ResponseWriter, r *http.Request, stamp string) {
	if r.Method != http.MethodGet {
		return
	}
	destPresent := r.Header.Get("Sec-Fetch-Dest") != ""
	modePresent := r.Header.Get("Sec-Fetch-Mode") != ""
	if destPresent || modePresent {
		if r.Header.Get("Sec-Fetch-Dest") != "document" || r.Header.Get("Sec-Fetch-Mode") != "navigate" {
			return
		}
	}
	if c, err := r.Cookie(versionCookieName); err == nil && c.Value != "" && c.Value != stamp {
		w.Header().Set("Clear-Site-Data", `"cache", "storage"`)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     versionCookieName,
		Value:    stamp,
		Path:     "/",
		MaxAge:   31536000,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// SetLogManager sets the per-category log file manager.
// Must be called before Handler() to activate file-based logging.
func (s *Server) SetLogManager(lm *applog.Manager) {
	s.logManager = lm
}

// SetEmailManager sets the SMTP email manager used to deliver contact-form
// and other outbound email (AI.md PART 12). Pass nil to disable email
// delivery (webhook-only dispatch still applies).
func (s *Server) SetEmailManager(m *email.EmailManager) {
	s.emailMgr = m
}

// SetConfig sets the configuration for the server.
// Also stores a typed reference when cfg is *config.AppConfig.
func (s *Server) SetConfig(cfg interface{}) {
	s.cfg = cfg
	if c, ok := cfg.(*config.AppConfig); ok {
		s.config = c
		// The browser-report endpoints are unauthenticated, so their per-IP
		// ceiling must exist as soon as config is known (AI.md PART 11
		// "Reports Endpoint" -> "Rate-limit per-IP to prevent flooding").
		if s.reportLimiter != nil {
			s.reportLimiter.Stop()
		}
		s.reportLimiter = NewReportRateLimiter(c.Web.Reports.RateLimitPerMinute, c.Web.Reports.RateLimitPerIPBurst)
	}
}

// SetConfigManager wires the file watcher so health responses can report
// settings that remain pending until restart.
func (s *Server) SetConfigManager(manager *config.ConfigManager) {
	s.configManager = manager
}

// ReloadRuntimeConfig applies a validated file-backed config snapshot and
// rebuilds the request handler so new requests use the updated middleware and
// route configuration. The lock lets in-flight requests finish on the prior
// snapshot before the new one becomes active.
func (s *Server) ReloadRuntimeConfig(cfg *config.AppConfig, baseURL string) {
	s.handlerMu.Lock()
	defer s.handlerMu.Unlock()
	s.SetConfig(cfg)
	s.BaseURL = baseURL
	s.HealthzRootEnabled = cfg.Server.Healthz.Root.Enabled
	s.SetOperatorToken(cfg.Server.Token)
	s.SetMetricsConfig(cfg.Server.Metrics)
	s.SetGeoIPCountries(cfg.Server.GeoIP.ResolvedDenyCountries(), cfg.Server.GeoIP.ResolvedAllowCountries())
	allowlistEntries := make([]AllowlistEntry, 0, len(cfg.Server.Security.Allowlist))
	for _, entry := range cfg.Server.Security.Allowlist {
		allowlistEntries = append(allowlistEntries, AllowlistEntry{CIDR: entry.CIDR, Description: entry.Description})
	}
	s.SetAllowlist(NewAllowlistLookup(allowlistEntries))
	s.activeHandler = s.buildHandler()
}

// SetPublicIP stores the server's cached external public IP.
// Called by the public_ip_refresh scheduler task (AI.md PART 18).
func (s *Server) SetPublicIP(ip string) {
	s.publicIPMu.Lock()
	s.publicIP = ip
	s.publicIPMu.Unlock()
}

// PublicIP returns the cached external public IP of this server.
func (s *Server) PublicIP() string {
	s.publicIPMu.RLock()
	defer s.publicIPMu.RUnlock()
	return s.publicIP
}

// RefreshPublicIP fetches the server's external public IP and caches it.
// Used as the task body for the public_ip_refresh scheduler task (AI.md PART 18).
func (s *Server) RefreshPublicIP() error {
	ip, err := netutil.FetchPublicIP()
	if err != nil {
		return err
	}
	s.SetPublicIP(ip)
	return nil
}

// SetMetricsConfig configures the metrics endpoint set per AI.md PART 20.
// A zero Loki block is filled in with the spec defaults so a config written by
// an older build still serves bounded Loki streams.
func (s *Server) SetMetricsConfig(cfg config.MetricsConfig) {
	if cfg.Loki.MaxEntries <= 0 {
		cfg.Loki.MaxEntries = 1000
	}
	if cfg.Loki.MaxAge == "" {
		cfg.Loki.MaxAge = "1h"
	}
	s.metricsEnabled = cfg.Enabled
	s.metricsConfig = cfg
}

// SetOperatorToken caches the SHA-256 hash of the raw operator token in memory.
// Per AI.md PART 11: the hash is never written to the DB; the raw token is never stored.
// Call once at startup, after config is loaded and before Handler() is called.
func (s *Server) SetOperatorToken(rawToken string) {
	if rawToken == "" {
		s.hasOperatorToken = false
		s.operatorTokenHash = [32]byte{}
		return
	}
	s.hasOperatorToken = true
	s.operatorTokenHash = sha256.Sum256([]byte(rawToken))
}

// ValidateOperatorToken returns true when the raw inbound token matches the cached
// operator token hash. Uses crypto/subtle.ConstantTimeCompare to prevent timing oracles.
func (s *Server) ValidateOperatorToken(rawToken string) bool {
	if !s.hasOperatorToken {
		return false
	}
	inboundHash := sha256.Sum256([]byte(rawToken))
	return subtle.ConstantTimeCompare(inboundHash[:], s.operatorTokenHash[:]) == 1
}

// ValidateAPIToken accepts the configured operator token or an active owner token.
func (s *Server) ValidateAPIToken(rawToken string) bool {
	if s.ValidateOperatorToken(rawToken) {
		return true
	}
	if s.sqlDB == nil || len(rawToken) != len("own_")+32 || !strings.HasPrefix(rawToken, "own_") {
		return false
	}
	for _, char := range rawToken[len("own_"):] {
		isLower := char >= 'a' && char <= 'z'
		isUpper := char >= 'A' && char <= 'Z'
		isDigit := char >= '0' && char <= '9'
		if !isLower && !isUpper && !isDigit {
			return false
		}
	}
	tokenID, ownerID, ok := s.findOwnerToken(rawToken)
	if !ok {
		return false
	}
	s.sqlDB.MarkOwnerUsage(tokenID, ownerID, time.Now())
	return true
}

// findOwnerToken resolves an active owner token by its non-secret prefix, then
// compares the stored SHA-256 digest to the inbound digest in constant time.
func (s *Server) findOwnerToken(rawToken string) (tokenID string, ownerID string, ok bool) {
	if s.sqlDB == nil || len(rawToken) != len("own_")+32 || !strings.HasPrefix(rawToken, "own_") {
		return "", "", false
	}
	rows, err := s.sqlDB.Query(`SELECT id, owner_id, token_hash FROM api_tokens WHERE token_prefix = ? AND owner_id <> 'system' AND revoked_at IS NULL
		AND (expires_at IS NULL OR expires_at > strftime('%s', 'now'))`, rawToken[:12])
	if err != nil {
		return "", "", false
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			tokenID, ownerID, ok = "", "", false
		}
	}()
	inboundHash := sha256.Sum256([]byte(rawToken))
	for rows.Next() {
		var storedHash string
		if rows.Scan(&tokenID, &ownerID, &storedHash) != nil {
			return "", "", false
		}
		expectedHash, decodeErr := hex.DecodeString(storedHash)
		if decodeErr == nil && len(expectedHash) == len(inboundHash) && subtle.ConstantTimeCompare(expectedHash, inboundHash[:]) == 1 {
			return tokenID, ownerID, true
		}
	}
	return "", "", false
}

func (s *Server) auditRejectedCLIToken(r *http.Request, rawToken string) {
	if r == nil || s.logManager == nil || !httputil.IsOurCliClient(r.UserAgent()) {
		return
	}
	details := map[string]any{"path": sanitizeLogValue(r.URL.Path)}
	if rawToken != "" {
		hash := sha256.Sum256([]byte(rawToken))
		details["token_fingerprint"] = hex.EncodeToString(hash[:6])
	}
	s.logManager.WriteAudit(applog.AuditEvent{
		Event: "cli.token_rejected", Source: "cli", Category: "cli", Severity: "warn", Result: "failure",
		Actor: applog.AuditActor{Type: "cli", IP: s.authClientIP(r)}, Details: details,
	})
}

// SetAllowlist configures the IP allowlist. Allowlisted IPs bypass blocklist,
// rate limiting, and GeoIP country blocking.
func (s *Server) SetAllowlist(al *AllowlistLookup) {
	s.allowlistLookup = al
}

// SetBlocklistLookup attaches the pre-loaded blocklist for IP blocking.
func (s *Server) SetBlocklistLookup(bl *blocklist.Lookup) {
	s.blocklistLookup = bl
}

// SetThreatLookup attaches the threat intelligence lookup for VPN/proxy/Tor detection.
// Must be called before the first request or after initIPService to take effect.
func (s *Server) SetThreatLookup(tl *threat.Lookup) {
	s.threatLookup = tl
	if s.ipService != nil {
		s.ipService.SetThreatLookup(tl)
	}
}

// SetRateLimiter attaches the rate limiter for the middleware chain.
func (s *Server) SetRateLimiter(rl *RateLimiter) {
	if s.rateLimiter != nil && s.rateLimiter != rl {
		s.rateLimiter.Stop()
	}
	s.rateLimiter = rl
	if rl != nil {
		if counter, ok := s.cacheBackend.(rateLimitWindowCounter); ok && counter.SupportsRateLimitWindow() {
			rl.SetWindowCounter(counter)
		}
		rl.SetDB(s.sqlDB)
		rl.SetTokenIdentityResolver(func(rawToken string, strict bool) (string, bool) {
			if s.ValidateOperatorToken(rawToken) {
				hash := sha256.Sum256([]byte(rawToken))
				return "token:" + hex.EncodeToString(hash[:]), true
			}
			if s.sqlDB == nil {
				return "", false
			}
			hash := sha256.Sum256([]byte(rawToken))
			_, ownerID, ok := s.findOwnerToken(rawToken)
			if !ok {
				return "", false
			}
			if strict {
				return "owner:" + ownerID, true
			}
			return "token:" + hex.EncodeToString(hash[:]), true
		})
	}
}

// StopRateLimiter flushes buffered rate-limit counters after HTTP requests
// have drained and before the database store is closed.
func (s *Server) StopRateLimiter() {
	if s != nil && s.rateLimiter != nil {
		s.rateLimiter.Stop()
	}
}

// SetGeoIPCountries configures country-level blocking.
// deny and allow are ISO 3166-1 alpha-2 codes. If both are set, allow wins.
func (s *Server) SetGeoIPCountries(deny, allow []string) {
	s.geoipDenyCountries = deny
	s.geoipAllowCountries = allow
}

// SetHostIPs stores the server's public IPv4 and IPv6 addresses for HTML template curl examples.
// ipv4 must be a valid IPv4 address; ipv6 must be a valid IPv6 address.
// Invalid values are silently ignored (empty string kept).
func (s *Server) SetHostIPs(ipv4, ipv6 string) {
	if ip := net.ParseIP(ipv4); ip != nil && ip.To4() != nil {
		s.HostIPv4 = ipv4
	}
	if ip := net.ParseIP(ipv6); ip != nil && ip.To4() == nil && len(ip) == net.IPv6len {
		s.HostIPv6 = ipv6
	}
}

// SetScheduler attaches the scheduler for /debug/scheduler status endpoint.
func (s *Server) SetScheduler(sched *scheduler.Scheduler) {
	s.sched = sched
}

// SetDB attaches the SQL database connection for /debug/db stats endpoint.
func (s *Server) SetDB(db *dbstore.Store) {
	s.sqlDB = db
	if s.rateLimiter != nil {
		s.rateLimiter.SetDB(db)
	}
}

// SetCacheBackend attaches the configured cache for the health probe and, when
// supported, the distributed sliding-window rate limiter (AI.md PART 9/12/13).
func (s *Server) SetCacheBackend(c cacheBackendPinger) {
	s.cacheBackend = c
	if s.rateLimiter != nil {
		counter, _ := c.(rateLimitWindowCounter)
		s.rateLimiter.SetWindowCounter(counter)
	}
}

// SetDiskUsageFunc attaches the platform disk-space helper (see
// src/disk_space_unix.go / src/disk_space_other.go) so /server/healthz can
// report checks.disk (AI.md PART 13).
func (s *Server) SetDiskUsageFunc(fn func(path string) (uint64, int, error)) {
	s.diskUsageFunc = fn
}

// SetTorStatus attaches the Tor manager (or a test stub) so /server/healthz
// and the site footer can report Tor availability/running state and onion
// address (AI.md PART 31, "Footer Customization").
func (s *Server) SetTorStatus(ts handler.TorStatusProvider) {
	s.TorStatus = ts
}

// SetI2PStatus attaches the I2P manager (or a test stub) so /server/healthz
// and the site footer can report I2P eepsite availability/running state and
// .b32.i2p address (AI.md PART 31.2, opt-in).
func (s *Server) SetI2PStatus(is handler.I2PStatusProvider) {
	s.I2PStatus = is
}

// NewHTTPServer creates a new Server with the given geo-IP reader and response cache.
func NewHTTPServer(db geo.Reader, cache *Cache) *Server {
	return &Server{
		cache:     cache,
		gr:        db,
		StartTime: time.Now(),
		reqStats:  newRequestStats(),
		// ipService is created lazily on first use via ensureIPService, once
		// LookupAddr and all Set* wiring have been applied at startup.
		// brandingCache is allocated here (not lazily per-request in
		// brandingLogoHandler) so concurrent requests never race on
		// initializing the Server.brandingCache pointer field.
		brandingCache: newBrandingLogoCache(),
	}
}

// ensureIPService creates the IPLookupService exactly once with the current
// LookupAddr, safe for concurrent callers on the request path.
func (s *Server) ensureIPService() {
	s.ipServiceOnce.Do(func() {
		s.ipService = service.NewIPLookupService(s.gr, s.cache, s.LookupAddr)
		if s.threatLookup != nil {
			s.ipService.SetThreatLookup(s.threatLookup)
		}
	})
}

// LookupIP resolves GeoIP/ASN/hostname/threat info for ip. Shared by REST
// handlers (via newResponse) and the GraphQL resolvers (see main.go GraphQL
// wiring) so both interfaces run through one code path.
func (s *Server) LookupIP(ip net.IP) (model.IPLookupResponse, error) {
	s.ensureIPService()
	return s.ipService.Lookup(ip)
}

// RequestIP extracts the caller's IP from r the same way REST handlers do.
// allowOverride permits the "?ip=" query parameter override (used by /json,
// GraphQL myIP); pass false to require the detected connection IP (used by
// /port/{port}, GraphQL checkPort).
func (s *Server) RequestIP(r *http.Request, allowOverride bool) (net.IP, error) {
	return ipFromRequestWithResolver(r, allowOverride, s.getTrust())
}

// CheckPort attempts a live TCP connection to ip:port, matching /port/{port}.
// Returns an error only when port lookups are not enabled on this server;
// an unreachable port is reported as reachable=false with a nil error.
func (s *Server) CheckPort(ip net.IP, port uint64) (bool, error) {
	if s.LookupPort == nil {
		return false, fmt.Errorf("port lookups are not enabled")
	}
	err := s.LookupPort(ip, port)
	return err == nil, nil
}

func (s *Server) newResponse(r *http.Request) (model.IPLookupResponse, error) {
	ip, err := s.RequestIP(r, true)
	if err != nil {
		return model.IPLookupResponse{}, err
	}
	response, err := s.LookupIP(ip)
	if err != nil {
		return model.IPLookupResponse{}, err
	}
	// UserAgent is not cached — always derived from the current request.
	response.UserAgent = userAgentFromRequest(r)
	// Flag genuine Tor hidden-service visits (Host matches the .onion address)
	// so API/CLI/HTML consumers know IP above is only the local loopback Tor's
	// ADD_ONION forwarding delivers, not the visitor's real address (AI.md
	// PART 31/12 — hidden-service circuits never carry a real client IP).
	if netutil.IsTorRequest(r, s.getTrust()) {
		isTorHS := true
		response.IsTorHiddenService = &isTorHS
	}
	return response, nil
}

func (s *Server) newPortResponse(r *http.Request) (model.PortResponse, error) {
	lastElement := filepath.Base(r.URL.Path)
	port, err := strconv.ParseUint(lastElement, 10, 16)
	if err != nil || port < 1 || port > 65535 {
		return model.PortResponse{Port: port}, fmt.Errorf("invalid port: %s", lastElement)
	}
	ip, err := s.RequestIP(r, false)
	if err != nil {
		return model.PortResponse{Port: port}, err
	}
	reachable, err := s.CheckPort(ip, port)
	if err != nil {
		return model.PortResponse{Port: port}, err
	}
	return model.PortResponse{
		IP:        ip,
		Port:      port,
		Reachable: reachable,
	}, nil
}

// CLIHandler writes the requester's IP address as a single plain-text line,
// the echoip-compatible response for CLI user agents.
func (s *Server) CLIHandler(w http.ResponseWriter, r *http.Request) *appError {
	ip, err := ipFromRequestWithResolver(r, true, s.getTrust())
	if err != nil {
		return badRequest(err).WithMessage(i18n.T(r.Context(), "errors.bad_request")).AsJSON()
	}
	_, _ = fmt.Fprintln(w, ip.String())
	return nil
}

// CLICountryHandler writes the requester's country name as plain text.
func (s *Server) CLICountryHandler(w http.ResponseWriter, r *http.Request) *appError {
	response, err := s.newResponse(r)
	if err != nil {
		return badRequest(err).WithMessage(i18n.T(r.Context(), "errors.bad_request")).AsJSON()
	}
	_, _ = fmt.Fprintln(w, response.Country)
	return nil
}

// CLICountryISOHandler writes the requester's ISO 3166-1 country code as
// plain text.
func (s *Server) CLICountryISOHandler(w http.ResponseWriter, r *http.Request) *appError {
	response, err := s.newResponse(r)
	if err != nil {
		return badRequest(err).WithMessage(i18n.T(r.Context(), "errors.bad_request")).AsJSON()
	}
	_, _ = fmt.Fprintln(w, response.CountryISO)
	return nil
}

// CLICityHandler writes the requester's city name as plain text.
func (s *Server) CLICityHandler(w http.ResponseWriter, r *http.Request) *appError {
	response, err := s.newResponse(r)
	if err != nil {
		return badRequest(err).WithMessage(i18n.T(r.Context(), "errors.bad_request")).AsJSON()
	}
	_, _ = fmt.Fprintln(w, response.City)
	return nil
}

// CLICoordinatesHandler writes the requester's latitude,longitude pair as
// plain text.
func (s *Server) CLICoordinatesHandler(w http.ResponseWriter, r *http.Request) *appError {
	response, err := s.newResponse(r)
	if err != nil {
		return badRequest(err).WithMessage(i18n.T(r.Context(), "errors.bad_request")).AsJSON()
	}
	_, _ = fmt.Fprintf(w, "%s\n", formatCoordinatePair(response.Latitude, response.Longitude))
	return nil
}

// CLIASNHandler writes the requester's autonomous system number as plain
// text.
func (s *Server) CLIASNHandler(w http.ResponseWriter, r *http.Request) *appError {
	response, err := s.newResponse(r)
	if err != nil {
		return badRequest(err).WithMessage(i18n.T(r.Context(), "errors.bad_request")).AsJSON()
	}
	_, _ = fmt.Fprintf(w, "%s\n", response.ASN)
	return nil
}

// CLIASNOrgHandler writes the requester's autonomous system organization as
// plain text.
func (s *Server) CLIASNOrgHandler(w http.ResponseWriter, r *http.Request) *appError {
	response, err := s.newResponse(r)
	if err != nil {
		return badRequest(err).WithMessage(i18n.T(r.Context(), "errors.bad_request")).AsJSON()
	}
	_, _ = fmt.Fprintf(w, "%s\n", response.ASNOrg)
	return nil
}

// JSONHandler writes the full IP lookup response as indented JSON.
func (s *Server) JSONHandler(w http.ResponseWriter, r *http.Request) *appError {
	response, err := s.newResponse(r)
	if err != nil {
		return badRequest(err).WithMessage(i18n.T(r.Context(), "errors.bad_request")).AsJSON()
	}
	b, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return internalServerError(err).AsJSON()
	}
	w.Header().Set("Content-Type", jsonMediaType)
	// Write errors are unrecoverable once headers are sent; log is not actionable here.
	w.Write(b)            //nolint:errcheck
	w.Write([]byte("\n")) //nolint:errcheck
	return nil
}

// PortHandler probes a TCP port on the requester's address and writes the
// reachability result as JSON.
func (s *Server) PortHandler(w http.ResponseWriter, r *http.Request) *appError {
	response, err := s.newPortResponse(r)
	if err != nil {
		return badRequest(err).WithMessage(i18n.T(r.Context(), "errors.bad_request")).AsJSON()
	}
	b, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return internalServerError(err).AsJSON()
	}
	w.Header().Set("Content-Type", jsonMediaType)
	// Write errors are unrecoverable once headers are sent; log is not actionable here.
	w.Write(b)            //nolint:errcheck
	w.Write([]byte("\n")) //nolint:errcheck
	return nil
}

// DefaultHandler renders the landing page as HTML. Client-type dispatch happens
// before it, in rootHandler and ipLookupNegotiated.
func (s *Server) DefaultHandler(w http.ResponseWriter, r *http.Request) *appError {
	response, err := s.newResponse(r)
	if err != nil {
		return badRequest(err).WithMessage(i18n.T(r.Context(), "errors.bad_request"))
	}
	// The landing page extends the shared layout like every other page
	// (AI.md PART 16: "Every page template MUST include header, nav, and
	// footer partials. No page may define its own."), so it clones the same
	// layout+partials tree the page renderer uses and parses index.tmpl's
	// title/meta/body_attrs/content blocks on top.
	t, err := buildBaseTemplate(s.AssetStamp()).Clone()
	if err != nil {
		return internalServerError(err)
	}
	t, err = t.ParseFS(templateFS, "template/index.tmpl")
	if err != nil {
		return internalServerError(err)
	}
	jsonBytes, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return internalServerError(err)
	}

	if s.PagesHandler == nil {
		return internalServerError(fmt.Errorf("pages handler not initialized"))
	}
	// PageData carries everything the shared layout and its partials need —
	// theme, language/direction, canonical URL, robots directive, CSRF token,
	// nav, footer branding, consent banner and announcements. Building it from
	// the same source every other page uses is what keeps the landing page in
	// sync with them instead of re-deriving a narrower subset here.
	pd := s.PagesHandler.NewPageData(r)
	// logoURL is the locally-served, cached branding logo (AI.md "Branding &
	// SEO" → "Remote URL Fetching") — never the raw remote URL. The actual
	// remote fetch/fallback/re-fetch logic lives in brandingLogoHandler.
	logoURL := "/branding/logo"
	var data = struct {
		handler.PageData
		model.IPLookupResponse
		BoxLatTop    float64
		BoxLatBottom float64
		BoxLonLeft   float64
		BoxLonRight  float64
		JSON         string
		Port         bool
		HostIPv4     string
		HostIPv6     string
		// Sponsor gates the hosting-sponsor box shown next to the IP display.
		Sponsor bool
		// LogoURL is the configured branding logo (AI.md "Branding & SEO");
		// falls back to the project default avatar when unset.
		LogoURL string
	}{
		pd,
		response,
		response.Latitude + 0.05,
		response.Latitude - 0.05,
		response.Longitude - 0.05,
		response.Longitude + 0.05,
		string(jsonBytes),
		s.LookupPort != nil,
		s.HostIPv4,
		s.HostIPv6,
		true,
		logoURL,
	}
	var body bytes.Buffer
	if err := t.ExecuteTemplate(&body, "base", &data); err != nil {
		return internalServerError(err)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// HTML documents are always fetched fresh (AI.md PART 9 "HTTP Cache
	// Headers") — the versioned static assets the page references are what
	// gets the long-lived cache instead. The ETag still lets an intermediary
	// that ignores no-store revalidate against the current build.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("ETag", `"`+s.AssetStamp()+`"`)
	// Version-change purge (AI.md PART 9): evict a stale browser cache/service
	// worker in one shot when the client's build cookie disagrees with this build.
	applyVersionPurge(w, r, s.AssetStamp())
	_, _ = w.Write(body.Bytes())
	return nil
}

// ipLookupNegotiated serves GET /{ip} as a frontend route under the AI.md
// PART 14 "Smart Content Negotiation" rules: our CLI client receives JSON so it
// can render its own TUI, browsers (graphical and text-mode) receive the
// rendered page, and non-interactive HTTP tools receive the echoip-compatible
// plain-text address.
func (s *Server) ipLookupNegotiated(ip net.IP) appHandler {
	return func(w http.ResponseWriter, r *http.Request) *appError {
		// Pin the lookup to the requested address — both newResponse and
		// ipFromRequest resolve an explicit target from the `ip` query
		// parameter, so the downstream handlers need no other change.
		q := r.URL.Query()
		q.Set("ip", ip.String())
		r.URL.RawQuery = q.Encode()

		switch detectClientType(r) {
		case "json":
			return s.JSONHandler(w, r)
		case "text":
			return s.CLIHandler(w, r)
		default:
			return s.DefaultHandler(w, r)
		}
	}
}

// IPLookupHandler handles /{ip}/json requests, which always answer JSON
// regardless of client type because the format is named in the path.
// Only the first path segment is parsed as the IP; any suffix is ignored.
func (s *Server) IPLookupHandler(w http.ResponseWriter, r *http.Request) *appError {
	// Extract the first path segment; strip brackets for IPv6 literals.
	path := strings.TrimPrefix(r.URL.Path, "/")
	ipPart, _, _ := strings.Cut(path, "/")
	ipStr := strings.Trim(ipPart, "[]")

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return badRequest(fmt.Errorf("invalid IP address")).WithMessage(i18n.T(r.Context(), "errors.bad_request")).AsJSON()
	}

	s.ensureIPService()
	response, err := s.ipService.Lookup(ip)
	if err != nil {
		return internalServerError(err).AsJSON()
	}

	b, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return internalServerError(err).AsJSON()
	}

	w.Header().Set("Content-Type", jsonMediaType)
	// Write errors are unrecoverable once headers are sent; log is not actionable here.
	w.Write(b)            //nolint:errcheck
	w.Write([]byte("\n")) //nolint:errcheck
	return nil
}

// API v1 handlers - these wrap existing handlers for the /api/v1 prefix
func (s *Server) APIV1InfoHandler(w http.ResponseWriter, r *http.Request) *appError {
	return s.JSONHandler(w, r)
}

// APIV1IPHandler serves GET /api/v1/ip, the JSON-route mirror of the
// plain-text CLI IP response.
func (s *Server) APIV1IPHandler(w http.ResponseWriter, r *http.Request) *appError {
	return s.CLIHandler(w, r)
}

// APIV1IPLookupHandler serves GET /api/v1/ip/{ip}, returning the full lookup
// response for an explicitly supplied address.
func (s *Server) APIV1IPLookupHandler(w http.ResponseWriter, r *http.Request) *appError {
	// Extract IP from /api/v1/ip/{ip}
	ipStr := strings.TrimPrefix(r.URL.Path, "/api/v1/ip/")
	ipStr = strings.Trim(ipStr, "[]")

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return badRequest(fmt.Errorf("invalid IP address")).WithMessage(i18n.T(r.Context(), "errors.bad_request")).AsJSON()
	}

	// Create a modified request to use the IP
	r.URL.RawQuery = "ip=" + ip.String()
	return s.JSONHandler(w, r)
}

// APIV1CountryHandler is the API mirror of the web /country route. Unlike the
// web route it content-negotiates, because AI.md PART 14 requires /api/**
// to answer JSON by default and reserve raw text for text clients.
func (s *Server) APIV1CountryHandler(w http.ResponseWriter, r *http.Request) *appError {
	response, err := s.newResponse(r)
	if err != nil {
		return badRequest(err).WithMessage(i18n.T(r.Context(), "errors.bad_request")).AsJSON()
	}
	return writeAPIScalar(w, r, "v1_country", response.Country)
}

// APIV1CityHandler is the API mirror of the web /city route.
func (s *Server) APIV1CityHandler(w http.ResponseWriter, r *http.Request) *appError {
	response, err := s.newResponse(r)
	if err != nil {
		return badRequest(err).WithMessage(i18n.T(r.Context(), "errors.bad_request")).AsJSON()
	}
	return writeAPIScalar(w, r, "v1_city", response.City)
}

// APIV1ASNHandler is the API mirror of the web /asn route.
func (s *Server) APIV1ASNHandler(w http.ResponseWriter, r *http.Request) *appError {
	response, err := s.newResponse(r)
	if err != nil {
		return badRequest(err).WithMessage(i18n.T(r.Context(), "errors.bad_request")).AsJSON()
	}
	return writeAPIScalar(w, r, "v1_asn", response.ASN)
}

// writeAPIScalar emits a single lookup value under the /api/** rules of AI.md
// PART 14: JSON by default, raw text for a `.txt` request, an Accept of
// text/plain, or a non-interactive client.
func writeAPIScalar(w http.ResponseWriter, r *http.Request, operationID, value string) *appError {
	if apiResponseFormat(r) == "text" {
		route, ok := swagger.RouteForOperationID(operationID)
		if !ok || route.Primary == "" {
			return internalServerError(fmt.Errorf("text route %s has no primary field", operationID)).AsJSON()
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintln(w, value)
		return nil
	}
	route, ok := swagger.RouteForOperationID(operationID)
	if !ok || route.Primary == "" {
		return internalServerError(fmt.Errorf("API route %s has no primary field", operationID)).AsJSON()
	}
	b, err := json.MarshalIndent(map[string]string{route.Primary: value}, "", "  ")
	if err != nil {
		return internalServerError(err).AsJSON()
	}
	w.Header().Set("Content-Type", jsonMediaType)
	// Write errors are unrecoverable once headers are sent; log is not actionable here.
	w.Write(b)            //nolint:errcheck
	w.Write([]byte("\n")) //nolint:errcheck
	return nil
}

// APIV1CountryISOHandler is the API mirror of the web /country-iso route.
func (s *Server) APIV1CountryISOHandler(w http.ResponseWriter, r *http.Request) *appError {
	response, err := s.newResponse(r)
	if err != nil {
		return badRequest(err).WithMessage(i18n.T(r.Context(), "errors.bad_request")).AsJSON()
	}
	return writeAPIScalar(w, r, "v1_country_iso", response.CountryISO)
}

// APIV1CoordinatesHandler is the API mirror of the web /coordinates route.
func (s *Server) APIV1CoordinatesHandler(w http.ResponseWriter, r *http.Request) *appError {
	response, err := s.newResponse(r)
	if err != nil {
		return badRequest(err).WithMessage(i18n.T(r.Context(), "errors.bad_request")).AsJSON()
	}
	return writeAPIScalar(w, r, "v1_coordinates", formatCoordinatePair(response.Latitude, response.Longitude))
}

// APIV1ASNOrgHandler is the API mirror of the web /asn-org route.
func (s *Server) APIV1ASNOrgHandler(w http.ResponseWriter, r *http.Request) *appError {
	response, err := s.newResponse(r)
	if err != nil {
		return badRequest(err).WithMessage(i18n.T(r.Context(), "errors.bad_request")).AsJSON()
	}
	return writeAPIScalar(w, r, "v1_asn_org", response.ASNOrg)
}

// getTrust returns the TrustResolver, creating a nil-safe fallback if not yet wired.
// The resolver is pre-built by main.go and set via SetTrust. This fallback exists only for
// code paths that may run before full initialisation (tests, benchmarks).
func (s *Server) getTrust() *netutil.TrustResolver {
	if s.trust != nil {
		return s.trust
	}
	if s.config == nil {
		return netutil.NewTrustResolver(config.TrustedProxiesConfig{}, "")
	}
	tr := netutil.NewTrustResolver(s.config.Server.TrustedProxies, "")
	if s.TorStatus != nil && s.TorStatus.IsAvailable() && s.TorStatus.IsRunning() {
		tr.OnionAddress = s.TorStatus.GetHostname()
	}
	return tr
}

// SetTrust wires the pre-built TrustResolver into the server.
// Must be called before Handler() to ensure DNS caching and listen-CIDR auto-trust are active.
func (s *Server) SetTrust(tr *netutil.TrustResolver) {
	s.trust = tr
}

// Handler builds and activates the fully wired router, then returns a stable
// dispatcher that can serve the replacement handler after a graceful reload.
func (s *Server) Handler() http.Handler {
	s.handlerMu.Lock()
	s.activeHandler = s.buildHandler()
	s.handlerMu.Unlock()
	return http.HandlerFunc(s.serveActiveHandler)
}

func (s *Server) serveActiveHandler(w http.ResponseWriter, r *http.Request) {
	s.handlerMu.RLock()
	defer s.handlerMu.RUnlock()
	if s.activeHandler == nil {
		writeNegotiatedError(w, r, http.StatusServiceUnavailable, "", i18n.T(r.Context(), "errors.server_error"))
		return
	}
	s.activeHandler.ServeHTTP(w, r)
}

// buildHandler creates the full router and middleware stack from the active
// config snapshot. Callers hold handlerMu while invoking it.
func (s *Server) buildHandler() http.Handler {
	r := NewChiRouter()

	// Initialize templates (if using embedded)
	if err := InitTemplates(); err != nil {
		detail := "server template initialization failed: " + err.Error()
		log.Printf("%s", detail)
		if s.logManager != nil {
			s.logManager.WriteError("error", detail)
		}
	}

	// Middleware chain per AI.md PART 16:
	// 0. Recover → 1. URLNormalize → 2. RequestID → 3. PathSecurity → 4. SecurityHeaders →
	// 5. Allowlist → 6. Blocklist → 7. RateLimit → 8. GeoIP →
	// 9. Auth (N/A — public API, no auth) → 10. Logging
	// + Metrics, Lang, CSRF follow Logging
	// Recover is outermost so it catches a panic anywhere downstream (AI.md
	// PART 9 backend guaranteed-response rule — the mirror of the service
	// worker's guaranteed-Response rule).
	r.Use(StripI2PHeadersMiddleware)
	r.Use(RecoverMiddleware(s.logManager))
	// AI.md PART 11 classifies GET and HEAD together as the read endpoint class,
	// and RFC 9110 requires every general-purpose server to answer HEAD wherever
	// it answers GET. chi matches methods exactly, so without this a HEAD on a
	// GET-only route returns 405 instead of the GET response's headers.
	r.Use(chimiddleware.GetHead)
	r.Use(URLNormalizeMiddleware)
	r.Use(RequestIDMiddleware)
	r.Use(PathSecurityMiddleware)
	maxBody := int64(0)
	if s.config != nil {
		maxBody = parseByteSize(s.config.Server.Limits.MaxBodySize)
		if maxBody > 0 {
			r.Use(BodyLimitMiddleware(maxBody))
		}
	}
	r.Use(SecurityHeadersMiddleware(SecurityHeaderConfigFromApp(s.config), s.SSLEnabled, s.config != nil && s.config.IsDebug()))
	r.Use(OnionLocationMiddleware(s.resolveOnionAddress))
	r.Use(ClientIPMiddleware(s.getTrust()))
	r.Use(AllowlistMiddleware(s.allowlistLookup))
	limits := DefaultRateLimitConfig()
	if s.rateLimiter != nil {
		limits = s.rateLimiter.config
	}
	var rateLimiterAlertCallback func(string)
	if s.rateLimiter != nil {
		rateLimiterAlertCallback = s.rateLimiter.OnBlocked
	}
	policy := AbusePolicyFromConfig(s.config, limits)
	r.Use(AbuseMiddleware(s.sqlDB, policy, s.getTrust(), s.allowlistLookup, s.logManager, rateLimiterAlertCallback))
	r.Use(BlocklistMiddleware(s.blocklistLookup, s.logManager, maxBody))
	if s.rateLimiter != nil {
		r.Use(RateLimitMiddleware(s.rateLimiter))
	}
	r.Use(s.MaintenanceMiddleware)
	r.Use(GeoIPMiddleware(s.gr, s.geoipDenyCountries, s.geoipAllowCountries))
	r.Use(LoggingMiddleware(s.getTrust(), s.logManager, s.config != nil && s.config.IsDebug()))
	r.Use(s.debugBodyLoggingMiddleware)
	r.Use(s.metricsMiddleware)
	r.Use(s.statsMiddleware)
	r.Use(LangMiddleware)
	// CSRF protection per AI.md PART 16: double-submit cookie pattern, exempt API webhooks.
	csrfCfg := DefaultCSRFConfig()
	if s.config != nil {
		csrfCfg = csrfConfigFrom(s.config.Server.CSRF)
	}
	r.Use(CSRFMiddleware(csrfCfg, s.SSLEnabled, s.logManager))
	if s.config != nil {
		r.Use(CompressionMiddleware(s.config.Server.Compression))
	}

	// Special files (PWA, robots, security)
	if s.SpecialHandler == nil {
		s.SpecialHandler = handler.NewSpecialHandler("")
	}
	// Embed the running build's commit into the service worker cache name
	// (AI.md PART 16 "Cache Versioning & Updates") so browsers reliably
	// detect deploys instead of requiring a manual cache clear.
	if s.SpecialHandler.CommitID == "" {
		s.SpecialHandler.CommitID = s.CommitID
	}
	// Wire the full build stamp so /sw.js and /manifest.json carry the same
	// no-cache + build-stamp ETag as every other cacheable response (AI.md
	// PART 9 "HTTP Cache Headers").
	if s.SpecialHandler.AssetStamp == "" {
		s.SpecialHandler.AssetStamp = s.AssetStamp()
	}
	// Wire Tor runtime identity and the configured Tor-only contact into SpecialHandler.
	if s.SpecialHandler.OnionAddress == "" && s.TorStatus != nil && s.TorStatus.IsAvailable() && s.TorStatus.IsRunning() {
		s.SpecialHandler.OnionAddress = s.TorStatus.GetHostname()
	}
	if s.config != nil {
		s.SpecialHandler.TorContactEmail = s.config.Server.Tor.ContactEmail
		s.SpecialHandler.ContactFormDisabled = !s.config.Pages.Contact.Enabled
	}
	// Wire the PGP keypair (AI.md PART 11 "GPG Keypair Management") into SpecialHandler
	// so SecurityTxtHandler can emit the Encryption: line and PGPKeyHandler can serve the key.
	if s.config != nil {
		site := strings.TrimSpace(s.config.Server.BaseURL)
		if site == "" && strings.TrimSpace(s.config.Server.FQDN) != "" {
			site = "https://" + strings.TrimSpace(s.config.Server.FQDN)
		}
		if site != "" {
			s.SpecialHandler.OfficialSite = strings.TrimRight(site, "/")
		}
		s.SpecialHandler.SecurityContact = config.ResolveContactRole(s.config, "security").Email
		s.SpecialHandler.SecurityReportURL = "https://github.com/apimgr/ipgaze/security/advisories/new"
		s.SpecialHandler.PublishPGPKey = s.config.Web.Security.PublishPGPKey
		s.SpecialHandler.PGPPublicKeyPath = filepath.Join(s.ConfigDir, "security", "pgp.pub.asc")
	}
	if s.sqlDB != nil {
		s.SpecialHandler.SecurityID = func() (string, error) {
			return security.CurrentSecurityID(s.sqlDB, time.Now())
		}
		s.SpecialHandler.PGPFingerprint = func() string {
			record, err := pgp.ActiveRecord(s.sqlDB)
			if err != nil || record == nil {
				return ""
			}
			return record.Fingerprint
		}
	}
	// Wire the per-AI-crawler robots.txt policy (AI.md PART 14 "robots.txt" ->
	// "AI Crawler Rules") so RobotsTxtHandler emits a Disallow stanza per denied bot.
	if s.config != nil {
		s.SpecialHandler.AIBots = s.config.Web.Robots.AIBots
	}
	// The generated robots.txt must carry a "Sitemap:" line (AI.md PART 16
	// "robots.txt"), built request-aware and suppressed when the sitemap is
	// disabled and /sitemap.xml therefore 404s.
	s.SpecialHandler.Trust = s.getTrust()
	if s.config != nil {
		s.SpecialHandler.SitemapEnabled = s.config.Server.SEO.Sitemap.Enabled
	}
	// Health check per PART 16
	if s.HealthHandler == nil {
		s.HealthHandler = handler.NewHealthHandler(s.Version, s.CommitID, s.BuildDate, s.Mode, s.StartTime)
		s.HealthHandler.DBRequired = true
		s.HealthHandler.SchedulerRequired = true
		s.HealthHandler.DiskRequired = true
	}
	if s.configManager != nil {
		s.HealthHandler.PendingRestart = func() (bool, []string) {
			return s.configManager.PendingRestart(), s.configManager.RestartSettings()
		}
	}
	// Wire live subsystem probes for /server/healthz checks/stats (AI.md PART 13).
	s.HealthHandler.DB = s.sqlDB
	s.HealthHandler.TorStatus = s.TorStatus
	s.HealthHandler.I2PStatus = s.I2PStatus
	if s.sched != nil {
		s.HealthHandler.Scheduler = s.sched
	}
	// Maintenance mode surfaces as health status "maintenance" (AI.md PART 12/13).
	s.HealthHandler.MaintenanceActive = s.MaintenanceActive
	s.StartMaintenanceMonitor()
	s.HealthHandler.DiskPath = s.DataDir
	s.HealthHandler.DiskUsage = s.diskUsageFunc
	if s.cacheBackend != nil {
		s.HealthHandler.CachePing = s.cacheBackend.Ping
	}
	s.HealthHandler.Stats = s.HealthStats
	// Project identity and GeoIP status for the health response (AI.md PART 13:
	// project.* from branding config, features.geoip from cfg.GeoIP.Enabled).
	if s.config != nil {
		s.HealthHandler.ProjectName = s.config.Server.Branding.Title
		s.HealthHandler.ProjectTagline = s.config.Server.Branding.Tagline
		s.HealthHandler.ProjectDescription = s.config.Server.Branding.Description
		s.HealthHandler.GeoIPEnabled = s.config.Server.GeoIP.Enabled
	}

	// Initialize CacheHandler if not already set
	if s.CacheHandler == nil {
		s.CacheHandler = handler.NewCacheHandler(s.cache)
	}

	// PUBLIC /server/* routes (per AI.md PART 17 - Standard Pages)
	if s.PagesHandler == nil {
		s.PagesHandler = handler.NewPagesHandler(s.Version, s.BuildDate, s.getTrust(), NewPageRenderer(s.AssetStamp()))
	}
	// Inject the single theme-detection implementation (theme.go) so
	// NewPageData resolves the theme cookie the same way DefaultHandler
	// does, without src/server/handler importing src/server (see theme.go
	// doc comment on DetectTheme for the import-cycle rationale).
	s.PagesHandler.DetectTheme = DetectTheme
	s.PagesHandler.RouteMatch = func(method, path string) bool {
		return r.Match(chi.NewRouteContext(), method, path)
	}
	// Inject the single theme-validation implementation (theme.go) so the
	// preferences import endpoint validates the theme query param against
	// the exact same enum DetectTheme/ServerPreferencesUpdateHandler use (see theme.go doc
	// comment on ValidateTheme for the import-cycle rationale).
	s.PagesHandler.ValidateTheme = ValidateTheme
	// Inject the context-aware CSRF token resolver (middleware_csrf.go) so
	// NewPageData's server-rendered forms (nav.tmpl's no-JS theme fallback,
	// contact.tmpl, privacy.tmpl) get a valid token even on a visitor's very
	// first request — CSRFMiddleware mints and stores that token in the
	// request context because the csrf_token cookie it also sets on this
	// same response hasn't round-tripped to the browser yet, so reading only
	// r.Cookie() (the prior behavior) left the token empty and made every
	// first-visit no-JS form submission fail CSRF validation.
	s.PagesHandler.CSRFToken = func(r *http.Request) string {
		return GetCSRFToken(r, "csrf_token")
	}
	if s.config != nil {
		s.PagesHandler.WebUI = &s.config.Web.UI
		s.PagesHandler.Privacy = &s.config.Server.Privacy
		s.PagesHandler.Config = s.config
	}
	s.PagesHandler.TorStatus = s.TorStatus
	s.PagesHandler.I2PStatus = s.I2PStatus
	s.PagesHandler.EmailMgr = s.emailMgr
	s.PagesHandler.DB = s.sqlDB
	s.PagesHandler.CommitID = s.CommitID
	if s.ConfigDir != "" {
		s.PagesHandler.PGPPublicKeyPath = filepath.Join(s.ConfigDir, "security", "pgp.pub.asc")
	}
	s.PagesHandler.SecurityLogger = func(message, ip string) {
		if s.logManager != nil {
			s.logManager.WriteSecurity(message, ip)
		}
	}
	s.PagesHandler.TokenAuditLogger = func(event, source, ownerID, prefix string) {
		if s.logManager != nil {
			s.logManager.WriteAudit(applog.AuditEvent{
				Event: event, Source: source, Category: "auth", Severity: "info", Result: "success",
				Target:  &applog.AuditTarget{Type: "owner", ID: ownerID},
				Details: map[string]any{"token_prefix": prefix, "source": source},
			})
		}
	}
	s.PagesHandler.TokenOwnerRevokeLogger = func(source, ownerID, prefix string, tokens, resources int64) {
		if s.logManager != nil {
			s.logManager.WriteAudit(applog.AuditEvent{
				Event: "token.revoked", Source: source, Category: "auth", Severity: "info", Result: "success",
				Target:  &applog.AuditTarget{Type: "owner", ID: ownerID},
				Details: map[string]any{"token_prefix": prefix, "source": source, "scope": "owner", "tokens": tokens, "resources": resources},
			})
		}
	}
	s.PagesHandler.TokenRestoreFailed = func(r *http.Request) {
		if s.rateLimiter != nil {
			s.rateLimiter.RecordAuthFailure(s.authClientIP(r))
		}
		if s.logManager != nil {
			s.logManager.WriteAuthFailure(sanitizeLogValue(s.authClientIP(r)), sanitizeLogValue(r.URL.Path), "invalid_token")
		}
	}
	s.PagesHandler.TokenRejected = s.auditRejectedCLIToken
	s.PagesHandler.ValidateBearerToken = s.ValidateAPIToken
	s.PagesHandler.MCPTools = func(r *http.Request) []handler.MCPToolDescription {
		return s.registeredMCPTools(r)
	}
	if s.SpecialHandler != nil {
		s.PagesHandler.PGPKeyAvailable = s.SpecialHandler.PGPKeyAvailable
		s.PagesHandler.PGPFingerprint = s.SpecialHandler.PGPFingerprint
	}
	// Wire healthz template renderer — must happen after PagesHandler is set up.
	s.HealthHandler.Render = NewPageRenderer(s.AssetStamp())
	s.HealthHandler.PageDataFunc = s.PagesHandler.NewPageData
	// Wire the themed error-page renderer (AI.md PART 16 "Error Pages (MUST
	// Match Theme)") — must happen after PagesHandler is set up, mirrors the
	// DetectTheme/HealthHandler.Render injection above; see error.go.
	errorPageExecute = NewTemplateExecutor(s.AssetStamp())
	// appHandler is a bare function type with no server state, so the log
	// Manager for error.log's 5xx records is injected the same way
	// (AI.md PART 11 "Log Files").
	SetErrorLogManager(s.logManager)
	errorPageData = s.PagesHandler.NewPageData
	errorPageAssetStamp = s.AssetStamp()
	// /api/autodiscover — unversioned; returns server info, cli_versions, cli_min_version (AI.md PART 32)

	// API v1 routes
	mcpHandler := s.MCPHandler()
	r.Route("/api/v1", func(r chi.Router) {
		// A `.txt` suffix on ANY /api/v1 route forces plain text (AI.md PART 14
		// "Content Negotiation Priority"); the middleware strips it before
		// routing so no endpoint needs a second registration.
		r.Use(APITextSuffixMiddleware)
		versionHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// AI.md PART 14: every success response uses the canonical
			// {"ok":true,"data":...} envelope — no endpoint may invent its own shape.
			handler.SendAPIResponseOK(w, model.VersionResponse{
				Version: s.Version,
				Commit:  s.CommitID,
				Date:    s.BuildDate,
			}, nil)
		})
		routes := s.apiRoutes(versionHandler, mcpHandler)
		s.routesMu.Lock()
		s.activeAPIRoutes = append([]swagger.Route(nil), routes...)
		s.routesMu.Unlock()
		s.apiOperationIDs = make(map[string]struct{})
		for _, route := range routes {
			if route.Handler == nil || !strings.HasPrefix(route.Path, "/api/v1") {
				continue
			}
			s.apiOperationIDs[route.OperationID] = struct{}{}
			if route.RuntimeAlias && route.Path != route.RuntimePath {
				continue
			}
			routePath := route.RuntimePath
			if routePath == "" {
				routePath = route.Path
			}
			routePath = strings.TrimPrefix(routePath, "/api/v1")
			if routePath == "" {
				routePath = "/"
			}
			if route.OperationID == "v1Mcp" {
				r.Handle(routePath, route.Handler)
			} else {
				r.Method(route.Method, routePath, route.Handler)
			}
		}
		if s.SpecialHandler != nil {
			s.SpecialHandler.APIV1OperationIDs = s.apiOperationIDs
			s.SpecialHandler.APIV1Routes = append([]swagger.Route(nil), routes...)
		}
	})
	// Mount every handler-bearing root and server route from the same registry
	// values used by API documentation and discovery.
	for _, route := range s.RegisteredAPIRoutes() {
		if route.Handler == nil || strings.HasPrefix(route.Path, "/api/v1") || strings.HasPrefix(route.Path, "/debug/") {
			continue
		}
		routePath := route.RuntimePath
		if routePath == "" {
			routePath = route.Path
		}
		if strings.HasPrefix(route.Path, "/server/tor/") && route.Internal {
			r.Handle(route.Path, route.Handler)
		} else if route.OperationID == "mcpRootAlias" {
			r.Handle(routePath, route.Handler)
		} else {
			r.Method(route.Method, routePath, route.Handler)
		}
	}

	// Store router for /debug/routes inspection, then register debug routes.
	s.router = r
	s.registerDebugRoutes(r, s.RegisteredAPIRoutes())

	// IP lookup catch-all for /{ip} requests
	// Handles IPv4 like /8.8.8.8 and IPv6 like /2001:4860:4860::8888
	r.NotFound(s.ipLookupOrNotFound())

	// Apply CORS middleware per AI.md spec
	// Uses github.com/rs/cors with configuration from server.yml.
	// When tor.onion_address is set it is added to the allow-list automatically (AI.md PART 12).
	var h http.Handler = r
	corsOrigin := config.GetCORS()
	explicitOrigins := map[string]struct{}{}
	allowedOrigins := map[string]struct{}{}
	learnedOrigins := &sync.Map{}
	for _, origin := range strings.Split(corsOrigin, ",") {
		origin = strings.TrimSpace(origin)
		if origin != "" && origin != "*" {
			explicitOrigins[origin] = struct{}{}
			allowedOrigins[origin] = struct{}{}
		}
	}
	corsOpts := cors.Options{
		AllowedMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		// Explicit enumeration per AI.md PART 16 -> "CORS Headers": a "*" wildcard
		// does not cover Authorization and is invalid when credentials are allowed.
		AllowedHeaders: []string{
			"Content-Type", "Accept", "X-Requested-With", "Authorization",
			"X-API-Key", "X-Api-Key", "API-Key", "ApiKey",
			"X-Auth-Token", "X-Access-Token", "X-Token", "Token",
			"X-CSRF-Token", "X-XSRF-Token", "X-Session-ID",
			"X-Service-Token", "X-Internal-Token",
		},
		// 24 hours preflight cache per AI.md spec
		MaxAge: config.GetCORSMaxAge(),
	}
	if corsOrigin == "*" {
		corsOpts.AllowedOrigins = []string{"*"}
		corsOpts.AllowCredentials = false
	} else if corsOrigin != "" {
		corsOpts.AllowedOrigins = strings.Split(corsOrigin, ",")
		corsOpts.AllowCredentials = config.GetCORSAllowCredentials()
		corsOpts.AllowOriginFunc = func(origin string) bool {
			if _, ok := allowedOrigins[origin]; ok {
				return true
			}
			_, ok := learnedOrigins.Load(origin)
			return ok
		}
	}
	// Automatically add the Tor onion origin when the hidden service is running.
	// Wildcard already covers all origins; only append for explicit allow-lists or when
	// no CORS config is set (corsOrigin == "") so the onion browser fetch is not blocked.
	// Read the live Tor address from TorStatus rather than configuration.
	// above for why that field is never populated.
	onionHostname := ""
	if s.TorStatus != nil && s.TorStatus.IsAvailable() && s.TorStatus.IsRunning() {
		onionHostname = s.TorStatus.GetHostname()
	}
	if onionHostname != "" && corsOrigin != "*" {
		onionOrigin := "http://" + onionHostname
		corsOpts.AllowedOrigins = append(corsOpts.AllowedOrigins, onionOrigin)
		allowedOrigins[onionOrigin] = struct{}{}
		corsOrigin = "tor-enabled"
	}
	// Automatically add the I2P eepsite origin when the eepsite is running,
	// mirroring the Tor onion origin handling above (AI.md PART 31.2).
	i2pHostname := ""
	if s.I2PStatus != nil && s.I2PStatus.IsAvailable() && s.I2PStatus.IsRunning() {
		i2pHostname = s.I2PStatus.GetHostname()
	}
	if i2pHostname != "" && corsOrigin != "*" {
		i2pOrigin := "http://" + i2pHostname
		corsOpts.AllowedOrigins = append(corsOpts.AllowedOrigins, i2pOrigin)
		allowedOrigins[i2pOrigin] = struct{}{}
		corsOrigin = "overlay-enabled"
	}
	if corsOrigin != "" {
		corsHandler := cors.New(corsOpts).Handler(h)
		if corsOpts.AllowOriginFunc != nil {
			corsHandler = learnTrustedProxyCORSOrigins(corsHandler, s.getTrust(), learnedOrigins)
		}
		if corsOpts.AllowCredentials {
			h = restrictCORSCredentials(explicitOrigins, learnedOrigins, corsHandler)
		} else {
			h = corsHandler
		}
	}

	return h
}

func learnTrustedProxyCORSOrigins(next http.Handler, trust *netutil.TrustResolver, learned *sync.Map) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimSpace(os.Getenv("DOMAIN")) == "" && trust != nil && trust.IsTrustedPeer(r) {
			if origin := trustedProxyOrigin(r); origin != "" {
				learned.Store(origin, struct{}{})
			}
		}
		next.ServeHTTP(w, r)
	})
}

func trustedProxyOrigin(r *http.Request) string {
	hostHeader := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Host"), ",")[0])
	if hostHeader == "" {
		return ""
	}
	if strings.ContainsAny(hostHeader, "/\\@ \t\r\n") {
		return ""
	}
	scheme := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]))
	if scheme != "http" && scheme != "https" {
		scheme = "https"
	}
	forwardedHost := hostHeader
	if host, port, err := net.SplitHostPort(hostHeader); err == nil {
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return ""
		}
		defaultPort := scheme == "http" && port == "80" || scheme == "https" && port == "443"
		if defaultPort {
			forwardedHost = host
		} else {
			forwardedHost = net.JoinHostPort(strings.ToLower(host), port)
		}
	} else if strings.Contains(hostHeader, ":") && !strings.HasPrefix(hostHeader, "[") {
		return ""
	}
	if forwardedHost == "" {
		return ""
	}
	return scheme + "://" + strings.ToLower(forwardedHost)
}

func restrictCORSCredentials(explicitOrigins map[string]struct{}, learnedOrigins *sync.Map, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, explicitlyAllowed := explicitOrigins[r.Header.Get("Origin")]
		if _, learned := learnedOrigins.Load(r.Header.Get("Origin")); learned {
			explicitlyAllowed = true
		}
		next.ServeHTTP(&corsCredentialsWriter{ResponseWriter: w, allow: explicitlyAllowed}, r)
	})
}

type corsCredentialsWriter struct {
	http.ResponseWriter
	allow bool
	wrote bool
}

func (w *corsCredentialsWriter) WriteHeader(status int) {
	if w.wrote {
		return
	}
	w.wrote = true
	if !w.allow {
		w.Header().Del("Access-Control-Allow-Credentials")
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *corsCredentialsWriter) Write(data []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}

func (w *corsCredentialsWriter) Flush() {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *corsCredentialsWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("response writer does not support hijacking")
	}
	return hijacker.Hijack()
}

func (w *corsCredentialsWriter) Push(target string, options *http.PushOptions) error {
	pusher, ok := w.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return pusher.Push(target, options)
}

func (w *corsCredentialsWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// rootHandler dispatches GET / under the AI.md PART 14 "Smart Content
// Negotiation" rules: our CLI client receives JSON, browsers (graphical and
// text-mode) receive the rendered page, and non-interactive HTTP tools receive
// the echoip-compatible plain-text address.
func (s *Server) rootHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch detectClientType(r) {
		case "json":
			appHandlerToHTTP(s.JSONHandler)(w, r)
		case "text":
			appHandlerToHTTP(s.CLIHandler)(w, r)
		default:
			appHandlerToHTTP(s.DefaultHandler)(w, r)
		}
	}
}

// scanCLIBinaries scans the operator-provisioned release artifacts and
// publishes only binaries whose listed SHA-256 matches their contents.
func scanCLIBinaries(binDir string) map[string]cliVersionEntry {
	result := make(map[string]cliVersionEntry)
	if binDir == "" {
		return result
	}
	versionData, err := os.ReadFile(filepath.Join(binDir, "version.txt"))
	if err != nil {
		return result
	}
	version := strings.TrimSpace(strings.SplitN(string(versionData), "\n", 2)[0])
	if version == "" {
		return result
	}
	checksumData, err := os.ReadFile(filepath.Join(binDir, "sha256.txt"))
	if err != nil {
		return result
	}
	checksums := make(map[string]string)
	for _, line := range strings.Split(string(checksumData), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			checksums[strings.TrimPrefix(fields[len(fields)-1], "*")] = fields[0]
		}
	}
	entries, err := os.ReadDir(binDir)
	if err != nil {
		return result
	}
	const prefix = "ipgaze-cli-"
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		// Strip prefix and optional ".exe" suffix to get the "{os}-{arch}" key.
		key := strings.TrimPrefix(name, prefix)
		key = strings.TrimSuffix(key, ".exe")
		if key == "" || !strings.Contains(key, "-") {
			continue
		}
		sum, sumErr := sha256File(filepath.Join(binDir, name))
		if sumErr != nil {
			continue
		}
		expected, ok := checksums[name]
		if !ok || !strings.EqualFold(expected, sum) {
			log.Printf("WARN: CLI binary %s omitted from autodiscover: SHA-256 missing or does not match sha256.txt", name)
			continue
		}
		result[key] = cliVersionEntry{Version: version, SHA256: sum}
	}
	return result
}

// cliBinaryDir resolves the configured release directory, defaulting to
// {data_dir}/cli as prescribed by AI.md PART 32.
func (s *Server) cliBinaryDir() string {
	dir := ""
	if s.config != nil {
		dir = strings.TrimSpace(s.config.Server.CLI.BinaryDownload.Dir)
	}
	if dir == "" {
		dir = filepath.Join(s.DataDir, "cli")
	} else {
		dir = strings.ReplaceAll(dir, "{data_dir}", s.DataDir)
	}
	return filepath.Clean(dir)
}

// sha256File computes the hex-encoded SHA-256 digest of the file at path.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open: %w", err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// autodiscoverHandler returns the public discovery document required by AI.md PART 13 and PART 32.
func (s *Server) autodiscoverHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type autodiscoverData struct {
			Name          string                     `json:"name"`
			Version       string                     `json:"version"`
			API           map[string]string          `json:"api"`
			URLs          []string                   `json:"urls"`
			Onion         string                     `json:"onion,omitempty"`
			I2P           string                     `json:"i2p,omitempty"`
			CLIVersions   map[string]cliVersionEntry `json:"cli_versions"`
			CLIMinVersion string                     `json:"cli_min_version"`
		}
		type autodiscoverEnvelope struct {
			OK   bool             `json:"ok"`
			Data autodiscoverData `json:"data"`
		}

		// BuildURL resolves proto/fqdn/port via the full priority chain (AI.md PART 12 → Resolution Order):
		// priority 0 = Tor onion match, then reverse-proxy headers, then DOMAIN env, etc.
		baseURL := netutil.BuildURL(r, s.getTrust(), "")

		resp := autodiscoverEnvelope{OK: true, Data: autodiscoverData{
			Name:    "ipgaze",
			Version: s.Version,
			API:     map[string]string{"current_version": "v1"},
			URLs:    []string{baseURL},
			// Scan the provisioned CLI release artifacts on each request so changes
			// to the directory are reflected without restarting the server.
			CLIVersions: scanCLIBinaries(s.cliBinaryDir()),
			// CLIMinVersion from config (AI.md PART 32 — config-driven, not hardcoded)
			CLIMinVersion: "",
		}}
		if s.config != nil {
			resp.Data.CLIMinVersion = s.config.Server.Update.CLIMinVersion
			if s.config.Server.Tor.Expose && s.TorStatus != nil && s.TorStatus.IsAvailable() && s.TorStatus.IsRunning() {
				resp.Data.Onion = s.TorStatus.GetHostname()
			}
			if s.config.Server.I2P.Expose && s.I2PStatus != nil && s.I2PStatus.IsAvailable() && s.I2PStatus.IsRunning() {
				resp.Data.I2P = s.I2PStatus.GetHostname()
			}
		}

		data, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			detectedLang := i18n.DetectLocale(r)
			// AI.md 24407/24415: 500 is a theme-required error page.
			writeNegotiatedError(w, r, http.StatusInternalServerError, "", i18n.T(i18n.WithLang(r.Context(), detectedLang), "errors.server_error"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		// Write errors are unrecoverable once headers are sent; log is not actionable here.
		w.Write(data)         //nolint:errcheck
		w.Write([]byte("\n")) //nolint:errcheck
	}
}

// cliBinaryDownloadHandler serves CLI binaries from the data directory.
// Endpoint: GET /cli/binaries/{project_name}-cli-{os}-{arch}
// Public by default; set cli.binary_download.require_auth: true in server.yml, which
// mounts RequireOperatorToken in front of this route (see registerRoutes) so the
// bearer-token check runs in constant time and is padded to the failed-auth floor.
// Streams the operator-provisioned binary from {data_dir}/cli/{filename}.
func (s *Server) cliBinaryDownloadHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract filename from URL (chi wildcard is everything after /cli/binaries/)
		filename := filepath.Base(r.URL.Path)
		// Every rejection below is content-negotiated: this route is reachable by
		// ordinary browser navigation, and AI.md 24407 requires the themed error
		// page for 400/404/500 (24411/24414/24415) rather than http.Error's bare
		// unstyled body.
		if filename == "" || filename == "." || filename == "/" {
			writeNegotiatedError(w, r, http.StatusNotFound, "", i18n.T(r.Context(), "errors.not_found"))
			return
		}

		// Reject path traversal
		if strings.Contains(filename, "..") || strings.ContainsAny(filename, "/\\") {
			writeNegotiatedError(w, r, http.StatusBadRequest, "", i18n.T(r.Context(), "errors.invalid_format"))
			return
		}
		if !strings.HasPrefix(filename, "ipgaze-cli-") {
			writeNegotiatedError(w, r, http.StatusNotFound, "", i18n.T(r.Context(), "errors.not_found"))
			return
		}
		platform := strings.TrimPrefix(filename, "ipgaze-cli-")
		platform = strings.TrimSuffix(platform, ".exe")
		if _, published := scanCLIBinaries(s.cliBinaryDir())[platform]; !published {
			writeNegotiatedError(w, r, http.StatusNotFound, "", i18n.T(r.Context(), "errors.not_found"))
			return
		}

		binPath := filepath.Join(s.cliBinaryDir(), filename)

		f, err := os.Open(binPath)
		if err != nil {
			if os.IsNotExist(err) {
				writeNegotiatedError(w, r, http.StatusNotFound, "", i18n.T(r.Context(), "errors.not_found"))
				return
			}
			writeNegotiatedError(w, r, http.StatusInternalServerError, "", i18n.T(r.Context(), "errors.server_error"))
			return
		}
		defer func() { _ = f.Close() }()

		fi, err := f.Stat()
		if err != nil {
			writeNegotiatedError(w, r, http.StatusInternalServerError, "", i18n.T(r.Context(), "errors.server_error"))
			return
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		// Quote the filename so a name containing a quote or separator cannot
		// break out of the header parameter.
		w.Header().Set("Content-Disposition", "attachment; filename="+strconv.Quote(filename))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", fi.Size()))
		// Detect OS from filename suffix to set correct MIME
		if strings.HasSuffix(filename, ".exe") {
			w.Header().Set("Content-Type", "application/vnd.microsoft.portable-executable")
		}

		if _, err := io.Copy(w, f); err != nil {
			// Write error after headers are sent; nothing actionable
			return
		}
		clientIP := ""
		if ip, ipErr := s.RequestIP(r, false); ipErr == nil {
			clientIP = ip.String()
		}
		if s.logManager != nil {
			platform := strings.TrimPrefix(filename, "ipgaze-cli-")
			platform = strings.TrimSuffix(platform, ".exe")
			version := ""
			if versionData, readErr := os.ReadFile(filepath.Join(s.cliBinaryDir(), "version.txt")); readErr == nil {
				version = strings.TrimSpace(strings.SplitN(string(versionData), "\n", 2)[0])
			}
			s.logManager.WriteAudit(applog.AuditEvent{
				Event: "cli.update_started", Source: "cli", Category: "cli", Severity: "info", Result: "success",
				Actor:   applog.AuditActor{Type: "client", IP: clientIP},
				Target:  &applog.AuditTarget{Type: "cli_binary", ID: filename},
				Details: map[string]any{"os_arch": platform, "version": version, "client_ip": clientIP},
			})
		}
	}
}

// maxReportBodyBytes caps how much of a browser report is read. Reports are
// unauthenticated and browser-generated, so the body is untrusted input and an
// unbounded read is a memory DOS.
const maxReportBodyBytes = 16 << 10

// securityEventForReport maps a report endpoint to its security.log event name.
// CSP violations carry the name AI.md PART 11 mandates; the remaining Reporting
// API groups follow the same "security.{type}_report" shape.
func securityEventForReport(reportType string) string {
	if reportType == "csp" {
		return "security.csp_violation"
	}
	return "security." + reportType + "_report"
}

// reportsHandler returns an http.HandlerFunc that accepts CSP/NEL/browser reports.
// Per AI.md PART 11 "Reports Endpoint": accept both the legacy
// application/csp-report and the Reporting API application/reports+json bodies,
// log each to security.log, rate-limit per source IP so a hostile page cannot
// flood the log, and answer 204 No Content so the browser stops retrying.
// The report body is never echoed back — it is entirely user-controlled.
func (s *Server) reportsHandler(reportType string) http.HandlerFunc {
	event := securityEventForReport(reportType)
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := s.authClientIP(r)
		if s.reportLimiter != nil && !s.reportLimiter.Allow(clientIP) {
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}

		// Read a bounded prefix of the body, then drain and close so the
		// connection can be reused regardless of how large the report was.
		var body []byte
		if r.Body != nil {
			body, _ = io.ReadAll(io.LimitReader(r.Body, maxReportBodyBytes))
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
		}

		// sanitizeLogValue strips control characters and truncates, so a
		// crafted report cannot forge extra security.log lines.
		if s.logManager != nil {
			s.logManager.WriteSecurity(event+" "+sanitizeLogValue(string(body)), clientIP)
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// ipLookupOrNotFound handles unmatched routes.
// Implements echoip-compatible routes: /{ip}, /{ip}/json, /{ip}/{field}.
func (s *Server) ipLookupOrNotFound() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			appHandlerToHTTP(appHandler(NotFoundHandler))(w, r)
			return
		}

		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			appHandlerToHTTP(appHandler(NotFoundHandler))(w, r)
			return
		}

		// Split into {ipPart}[/{suffix}]
		ipPart, suffix, _ := strings.Cut(path, "/")

		// IP path segment must contain "." (IPv4) or ":" (IPv6)
		if !strings.Contains(ipPart, ".") && !strings.Contains(ipPart, ":") {
			appHandlerToHTTP(appHandler(NotFoundHandler))(w, r)
			return
		}

		ip := net.ParseIP(strings.Trim(ipPart, "[]"))
		if ip == nil {
			appHandlerToHTTP(appHandler(NotFoundHandler))(w, r)
			return
		}

		switch suffix {
		case "json":
			// /{ip}/json → full JSON response, format named in the path
			appHandlerToHTTP(s.IPLookupHandler)(w, r)
		case "":
			// /{ip} → frontend route, AI.md PART 14 smart detection
			appHandlerToHTTP(s.ipLookupNegotiated(ip))(w, r)
		default:
			// /{ip}/{field} → specific field as plain text
			appHandlerToHTTP(s.ipLookupFieldHandler(ip, suffix))(w, r)
		}
	}
}

// ipLookupFieldHandler returns a handler that looks up a specific GeoIP field for ip.
// Implements the echoip-compatible /{ip}/{field} route.
func (s *Server) ipLookupFieldHandler(ip net.IP, field string) appHandler {
	return func(w http.ResponseWriter, r *http.Request) *appError {
		s.ensureIPService()
		response, err := s.ipService.Lookup(ip)
		if err != nil {
			return internalServerError(err).AsJSON()
		}

		var val string
		switch field {
		case "ip":
			val = response.IP.String()
		case "ip_decimal":
			if response.IPDecimal != nil {
				val = response.IPDecimal.String()
			}
		case "country":
			val = response.Country
		case "country_iso":
			val = response.CountryISO
		case "region_name":
			val = response.RegionName
		case "region_code":
			val = response.RegionCode
		case "city":
			val = response.City
		case "zip_code":
			val = response.PostalCode
		case "time_zone":
			val = response.Timezone
		case "asn":
			val = response.ASN
		case "asn_org":
			val = response.ASNOrg
		case "hostname":
			val = response.Hostname
		case "latitude":
			val = formatCoordinate(response.Latitude)
		case "longitude":
			val = formatCoordinate(response.Longitude)
		default:
			return badRequest(fmt.Errorf("unknown field: %s", field)).
				WithMessage(i18n.T(r.Context(), "errors.not_found")).AsJSON()
		}

		// Return empty-string fields as 404 — GeoIP may not cover the IP
		if val == "" {
			return badRequest(fmt.Errorf("field %s not available for IP %s", field, ip)).
				WithMessage(i18n.T(r.Context(), "errors.not_found")).AsJSON()
		}

		_, _ = fmt.Fprintln(w, val)
		return nil
	}
}

// csrfConfigFrom converts a config.CSRFConfig (YAML-sourced) to the server's CSRFConfig.
// The "secure" string field maps to *bool: "auto" → nil, "true" → &true, "false" → &false.
func csrfConfigFrom(c config.CSRFConfig) CSRFConfig {
	def := DefaultCSRFConfig()
	cfg := CSRFConfig{
		Enabled:     c.Enabled,
		TokenLength: c.TokenLength,
		CookieName:  c.CookieName,
		HeaderName:  c.HeaderName,
		// FormField is not operator-configurable per AI.md PART 16's schema
		// (only cookie_name/header_name are) — it must stay the spec's fixed
		// "csrf_token" name to match the hardcoded hidden input in
		// contact.tmpl. Reusing c.CookieName here (a copy-paste of the line
		// above) silently desynced the two whenever an operator customized
		// cookie_name, breaking the no-JS contact form.
		FormField:   def.FormField,
		SameSite:    http.SameSiteStrictMode,
		ExemptPaths: append(def.ExemptPaths, c.ExemptPaths...),
	}
	switch c.Secure {
	case "true":
		v := true
		cfg.Secure = &v
	case "false":
		v := false
		cfg.Secure = &v
	default:
		// "auto" or empty: nil means auto-detect from TLS state
		cfg.Secure = nil
	}
	return cfg
}
