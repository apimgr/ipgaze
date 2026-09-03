package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"database/sql"

	"github.com/apimgr/ipgaze/src/blocklist"
	"github.com/apimgr/ipgaze/src/common/i18n"
	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/email"
	"github.com/apimgr/ipgaze/src/iputil/geo"
	applog "github.com/apimgr/ipgaze/src/log"
	"github.com/apimgr/ipgaze/src/netutil"
	"github.com/apimgr/ipgaze/src/scheduler"
	"github.com/apimgr/ipgaze/src/server/handler"
	"github.com/apimgr/ipgaze/src/server/model"
	"github.com/apimgr/ipgaze/src/server/service"
	"github.com/apimgr/ipgaze/src/threat"
	"github.com/go-chi/chi/v5"
	"github.com/rs/cors"
)

const (
	jsonMediaType = "application/json"
	textMediaType = "text/plain"
	// defaultLogoURL is the project default branding logo, used when the
	// operator has not set server.branding.logo_url in server.yml.
	defaultLogoURL = "https://avatars.githubusercontent.com/u/126880?v=4"
)

// cliVersionEntry holds a platform-specific CLI binary version and its SHA-256 digest.
// Used in the /api/autodiscover response (AI.md PART 32).
type cliVersionEntry struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

type Server struct {
	IPHeaders  []string
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
	// router holds the chi.Router for debug route inspection.
	router chi.Router
	// sched holds the scheduler for /debug/scheduler status.
	sched *scheduler.Scheduler
	// sqlDB holds the database connection for /debug/db stats.
	sqlDB              *sql.DB
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
	s.rateLimiter = rl
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
func (s *Server) SetDB(db *sql.DB) {
	s.sqlDB = db
}

// SetCacheBackend attaches the configured application cache.Cache backend
// (Valkey/Redis, Memcache, memory, or noop) so /server/healthz can probe it
// via checks.cache (AI.md PART 9/13). A nil backend leaves the check reporting
// "ok" (nothing to probe).
func (s *Server) SetCacheBackend(c cacheBackendPinger) {
	s.cacheBackend = c
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
	return ipFromRequest(s.IPHeaders, r, allowOverride, s.getTrust().IsTrustedPeer(r))
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

func (s *Server) CLIHandler(w http.ResponseWriter, r *http.Request) *appError {
	ip, err := ipFromRequest(s.IPHeaders, r, true, s.getTrust().IsTrustedPeer(r))
	if err != nil {
		return badRequest(err).WithMessage(i18n.T(r.Context(), "errors.bad_request")).AsJSON()
	}
	fmt.Fprintln(w, ip.String())
	return nil
}

func (s *Server) CLICountryHandler(w http.ResponseWriter, r *http.Request) *appError {
	response, err := s.newResponse(r)
	if err != nil {
		return badRequest(err).WithMessage(i18n.T(r.Context(), "errors.bad_request")).AsJSON()
	}
	fmt.Fprintln(w, response.Country)
	return nil
}

func (s *Server) CLICountryISOHandler(w http.ResponseWriter, r *http.Request) *appError {
	response, err := s.newResponse(r)
	if err != nil {
		return badRequest(err).WithMessage(i18n.T(r.Context(), "errors.bad_request")).AsJSON()
	}
	fmt.Fprintln(w, response.CountryISO)
	return nil
}

func (s *Server) CLICityHandler(w http.ResponseWriter, r *http.Request) *appError {
	response, err := s.newResponse(r)
	if err != nil {
		return badRequest(err).WithMessage(i18n.T(r.Context(), "errors.bad_request")).AsJSON()
	}
	fmt.Fprintln(w, response.City)
	return nil
}

func (s *Server) CLICoordinatesHandler(w http.ResponseWriter, r *http.Request) *appError {
	response, err := s.newResponse(r)
	if err != nil {
		return badRequest(err).WithMessage(i18n.T(r.Context(), "errors.bad_request")).AsJSON()
	}
	fmt.Fprintf(w, "%s,%s\n", formatCoordinate(response.Latitude), formatCoordinate(response.Longitude))
	return nil
}

func (s *Server) CLIASNHandler(w http.ResponseWriter, r *http.Request) *appError {
	response, err := s.newResponse(r)
	if err != nil {
		return badRequest(err).WithMessage(i18n.T(r.Context(), "errors.bad_request")).AsJSON()
	}
	fmt.Fprintf(w, "%s\n", response.ASN)
	return nil
}

func (s *Server) CLIASNOrgHandler(w http.ResponseWriter, r *http.Request) *appError {
	response, err := s.newResponse(r)
	if err != nil {
		return badRequest(err).WithMessage(i18n.T(r.Context(), "errors.bad_request")).AsJSON()
	}
	fmt.Fprintf(w, "%s\n", response.ASNOrg)
	return nil
}

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
	if err := t.ExecuteTemplate(w, "base", &data); err != nil {
		return internalServerError(err)
	}
	return nil
}

// IPLookupHandler handles /{ip} and /{ip}/json requests.
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

func (s *Server) APIV1IPHandler(w http.ResponseWriter, r *http.Request) *appError {
	return s.CLIHandler(w, r)
}

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
	return writeAPIScalar(w, r, "country", response.Country)
}

// APIV1CityHandler is the API mirror of the web /city route.
func (s *Server) APIV1CityHandler(w http.ResponseWriter, r *http.Request) *appError {
	response, err := s.newResponse(r)
	if err != nil {
		return badRequest(err).WithMessage(i18n.T(r.Context(), "errors.bad_request")).AsJSON()
	}
	return writeAPIScalar(w, r, "city", response.City)
}

// APIV1ASNHandler is the API mirror of the web /asn route.
func (s *Server) APIV1ASNHandler(w http.ResponseWriter, r *http.Request) *appError {
	response, err := s.newResponse(r)
	if err != nil {
		return badRequest(err).WithMessage(i18n.T(r.Context(), "errors.bad_request")).AsJSON()
	}
	return writeAPIScalar(w, r, "asn", response.ASN)
}

// writeAPIScalar emits a single lookup value under the /api/** rules of AI.md
// PART 14: JSON by default, raw text for a `.txt` request, an Accept of
// text/plain, or a non-interactive client.
func writeAPIScalar(w http.ResponseWriter, r *http.Request, field, value string) *appError {
	if detectClientType(r) == "text" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, value)
		return nil
	}
	b, err := json.MarshalIndent(map[string]string{field: value}, "", "  ")
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
	return writeAPIScalar(w, r, "country_iso", response.CountryISO)
}

// APIV1CoordinatesHandler is the API mirror of the web /coordinates route.
func (s *Server) APIV1CoordinatesHandler(w http.ResponseWriter, r *http.Request) *appError {
	response, err := s.newResponse(r)
	if err != nil {
		return badRequest(err).WithMessage(i18n.T(r.Context(), "errors.bad_request")).AsJSON()
	}
	coordinates := formatCoordinate(response.Latitude) + "," + formatCoordinate(response.Longitude)
	return writeAPIScalar(w, r, "coordinates", coordinates)
}

// APIV1ASNOrgHandler is the API mirror of the web /asn-org route.
func (s *Server) APIV1ASNOrgHandler(w http.ResponseWriter, r *http.Request) *appError {
	response, err := s.newResponse(r)
	if err != nil {
		return badRequest(err).WithMessage(i18n.T(r.Context(), "errors.bad_request")).AsJSON()
	}
	return writeAPIScalar(w, r, "asn_org", response.ASNOrg)
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
	tr.OnionAddress = s.config.Tor.OnionAddress
	return tr
}

// SetTrust wires the pre-built TrustResolver into the server.
// Must be called before Handler() to ensure DNS caching and listen-CIDR auto-trust are active.
func (s *Server) SetTrust(tr *netutil.TrustResolver) {
	s.trust = tr
}

func (s *Server) Handler() http.Handler {
	r := NewChiRouter()

	// Initialize templates (if using embedded)
	_ = InitTemplates()

	// Middleware chain per AI.md PART 16:
	// 0. Recover → 1. URLNormalize → 2. RequestID → 3. PathSecurity → 4. SecurityHeaders →
	// 5. Allowlist → 6. Blocklist → 7. RateLimit → 8. GeoIP →
	// 9. Auth (N/A — public API, no auth) → 10. Logging
	// + Metrics, Lang, CSRF follow Logging
	// Recover is outermost so it catches a panic anywhere downstream (AI.md
	// PART 9 backend guaranteed-response rule — the mirror of the service
	// worker's guaranteed-Response rule).
	r.Use(RecoverMiddleware(s.logManager))
	r.Use(URLNormalizeMiddleware)
	r.Use(RequestIDMiddleware)
	r.Use(PathSecurityMiddleware)
	r.Use(SecurityHeadersMiddleware(SecurityHeaderConfigFromApp(s.config), s.SSLEnabled, s.config != nil && s.config.IsDebug()))
	r.Use(OnionLocationMiddleware(s.resolveOnionAddress))
	r.Use(ClientIPMiddleware(s.getTrust()))
	r.Use(AllowlistMiddleware(s.allowlistLookup))
	r.Use(BlocklistMiddleware(s.blocklistLookup, s.logManager))
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
		csrfCfg = csrfConfigFrom(s.config.Web.CSRF)
	}
	r.Use(CSRFMiddleware(csrfCfg, s.SSLEnabled, s.logManager))

	// Static files (embedded) - serve under /static/ prefix.
	// Cache-Control per AI.md PART 9 "Asset Version-Busting (REQUIRED)":
	// a request whose "?v=" matches the running build's AssetStamp is this
	// exact release's bytes and can be cached for a year as immutable; any
	// other request (no stamp, or an old release's stamp) must always
	// revalidate, so an update is never masked by a stale cache.
	r.Get("/static/*", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Query().Get("v") == s.AssetStamp() {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("ETag", `"`+s.AssetStamp()+`"`)
		}
		http.StripPrefix("/static/", StaticHandler()).ServeHTTP(w, req)
	})

	// Branding logo — fetched/cached server-side and served locally so the
	// page never hotlinks a remote URL directly (AI.md "Branding & SEO").
	r.Get("/branding/logo", s.brandingLogoHandler())

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
	// Wire Tor config into SpecialHandler so SecurityTxtHandler can serve the Tor variant.
	// Read the hostname live from TorStatus (same source healthz/PagesHandler use), not
	// s.config.Tor.OnionAddress — that field is never assigned anywhere once the hidden
	// service actually starts, so it is permanently empty regardless of timing.
	if s.SpecialHandler.OnionAddress == "" && s.TorStatus != nil && s.TorStatus.IsAvailable() && s.TorStatus.IsRunning() {
		s.SpecialHandler.OnionAddress = s.TorStatus.GetHostname()
	}
	if s.config != nil {
		s.SpecialHandler.TorContactEmail = s.config.Tor.ContactEmail
	}
	// Wire the PGP keypair (AI.md PART 11 "GPG Keypair Management") into SpecialHandler
	// so SecurityTxtHandler can emit the Encryption: line and PGPKeyHandler can serve the key.
	if s.config != nil {
		s.SpecialHandler.SecurityContact = s.config.Web.Security.Contact
		s.SpecialHandler.PublishPGPKey = s.config.Web.Security.PublishPGPKey
		s.SpecialHandler.PGPPublicKeyPath = filepath.Join(s.ConfigDir, "security", "pgp.pub.asc")
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
	r.Get("/robots.txt", s.SpecialHandler.RobotsTxtHandler)
	// Every project must serve a dynamically generated sitemap (AI.md PART 24
	// "Sitemap.xml"); HEAD is registered so crawlers can probe it cheaply.
	r.Get("/sitemap.xml", s.sitemapHandler())
	r.Head("/sitemap.xml", s.sitemapHandler())
	r.Get("/security.txt", s.SpecialHandler.SecurityTxtHandler)
	r.Get("/.well-known/security.txt", s.SpecialHandler.SecurityTxtHandler)
	r.Get("/.well-known/pgp-key.asc", s.SpecialHandler.PGPKeyHandler)
	r.Get("/llms.txt", s.SpecialHandler.LLMsTxtHandler)
	r.Get("/.well-known/llms.txt", s.SpecialHandler.LLMsTxtHandler)
	// GET and HEAD are the only valid methods for /.well-known/** and anything
	// else must be 405 (AI.md PART 14 "Well-Known Namespace Contract"). chi
	// answers 405 for unregistered methods on a known path, so registering HEAD
	// explicitly is what keeps it out of that bucket; net/http suppresses the
	// body for HEAD, so the GET handlers can be reused verbatim.
	r.Head("/.well-known/security.txt", s.SpecialHandler.SecurityTxtHandler)
	r.Head("/.well-known/pgp-key.asc", s.SpecialHandler.PGPKeyHandler)
	r.Head("/.well-known/llms.txt", s.SpecialHandler.LLMsTxtHandler)
	r.Get("/manifest.json", s.SpecialHandler.ManifestHandler)
	r.Get("/sw.js", s.SpecialHandler.ServiceWorkerHandler)
	r.Get("/offline.html", s.SpecialHandler.OfflineHandler)

	// i18n locale files — served from embedded binary for WebUI JavaScript
	// GET /locales/{lang}.json — returns the JSON translation file for the given locale
	r.Get("/locales/{lang}.json", func(w http.ResponseWriter, req *http.Request) {
		lang := chi.URLParam(req, "lang")
		data, err := i18n.LocaleJSON(lang)
		if err != nil {
			detectedLang := i18n.DetectLocale(req)
			http.Error(w, i18n.T(i18n.WithLang(req.Context(), detectedLang), "errors.not_found"), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		// Write errors are unrecoverable once headers are sent; log is not actionable here.
		w.Write(data) //nolint:errcheck
	})

	// Metrics endpoint set per AI.md PART 20: /server/metrics, the versioned and
	// unversioned API aliases, and the root alias — all one shared handler.
	if s.metricsEnabled {
		handler.RegisterMetricsRoutes(r, s.metricsConfig, "ipgaze")
	}

	// INTERNAL Tor control channel (AI.md PART 31.1) — loopback-gated, never
	// documented or advertised, registered at the same tier as /server/metrics.
	s.registerTorControlRoutes(r)

	// Health check per PART 16
	if s.HealthHandler == nil {
		s.HealthHandler = handler.NewHealthHandler(s.Version, s.CommitID, s.BuildDate, s.Mode, s.StartTime)
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
	r.Get("/server/healthz", s.HealthHandler.HealthzHandler)
	// /healthz is an optional root-level alias — only registered when explicitly enabled.
	// Per AI.md PART 13: gated by server.healthz.root.enabled config.
	if s.HealthzRootEnabled {
		r.Get("/healthz", s.HealthHandler.HealthzHandler)
	}

	// Initialize CacheHandler if not already set
	if s.CacheHandler == nil {
		s.CacheHandler = handler.NewCacheHandler(s.cache)
	}

	// OpenAPI/Swagger routes (if handler is set)
	if s.SwaggerHandler != nil {
		r.Get("/server/docs/swagger", s.SwaggerHandler)
	}
	if s.SwaggerJSONHandler != nil {
		// unversioned API alias — always JSON, never the interactive UI
		r.Get("/api/swagger", s.SwaggerJSONHandler)
	}

	// GraphQL routes (if handler is set)
	if s.GraphQLHandler != nil {
		r.Get("/server/docs/graphql", s.GraphQLHandler)
		r.Post("/server/docs/graphql", s.GraphQLHandler)
		// unversioned API aliases — same handler, never redirect
		r.Get("/api/graphql", s.GraphQLHandler)
		r.Post("/api/graphql", s.GraphQLHandler)
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
	r.Get("/server", s.PagesHandler.ServerRedirectHandler)
	r.Get("/server/about", s.PagesHandler.ServerAboutHandler)
	r.Get("/server/help", s.PagesHandler.ServerHelpHandler)
	r.Get("/server/privacy", s.PagesHandler.ServerPrivacyHandler)
	r.Get("/server/contact", s.PagesHandler.ServerContactHandler)
	r.Post("/server/contact", s.PagesHandler.ServerContactHandler)
	r.Get("/server/terms", s.PagesHandler.ServerTermsHandler)
	r.Post("/server/consent", s.PagesHandler.ConsentHandler)
	r.Post("/server/ccpa", s.PagesHandler.CCPAHandler)
	r.Post("/server/preferences", s.PagesHandler.ServerPreferencesUpdateHandler)
	r.Get("/server/preferences", s.PagesHandler.ServerPreferencesHandler)
	r.Get("/server/preferences/export", s.PagesHandler.ServerPreferencesExportHandler)
	r.Get("/server/preferences/import", s.PagesHandler.ServerPreferencesImportHandler)
	r.Post("/announcements/dismiss", s.PagesHandler.DismissAnnouncementHandler)

	// /api/autodiscover — unversioned; returns server info, cli_versions, cli_min_version (AI.md PART 32)
	r.Get("/api/autodiscover", s.autodiscoverHandler())

	// /cli/binaries/{project_name}-cli-{os}-{arch} — CLI binary download (AI.md PART 32)
	// Streams the CLI binary for the requested platform from the data directory.
	// When cli.binary_download.require_auth is set, the route is gated by the
	// operator-token middleware so the rejection path gets the constant-time
	// compare, the identical error message, and the timing floor AI.md PART 11
	// requires — an inline check in the handler cannot provide those.
	if s.config != nil && s.config.Server.CLI.BinaryDownload.RequireAuth {
		r.With(s.RequireOperatorToken).Get("/cli/binaries/{filename}", s.cliBinaryDownloadHandler())
	} else {
		r.Get("/cli/binaries/{filename}", s.cliBinaryDownloadHandler())
	}

	// /api/healthz — unversioned direct alias per PART 13, same handler as canonical
	r.Get("/api/healthz", s.HealthHandler.APIV1HealthzHandler)
	// .txt variant forces plain text per PART 14 content-negotiation priority 1.
	r.Get("/api/healthz.txt", s.HealthHandler.APIV1HealthzHandler)

	// API v1 routes
	r.Route("/api/v1", func(r chi.Router) {
		// A `.txt` suffix on ANY /api/v1 route forces plain text (AI.md PART 14
		// "Content Negotiation Priority"); the middleware strips it before
		// routing so no endpoint needs a second registration.
		r.Use(APITextSuffixMiddleware)
		r.Get("/", appHandlerToHTTP(s.APIV1InfoHandler))
		// /json is the API mirror of the web /json route.
		r.Get("/json", appHandlerToHTTP(s.APIV1InfoHandler))
		r.Get("/ip", appHandlerToHTTP(s.APIV1IPHandler))
		r.Get("/ip/*", appHandlerToHTTP(s.APIV1IPLookupHandler))
		r.Get("/server/healthz", s.HealthHandler.APIV1HealthzHandler)

		r.Get("/version", func(w http.ResponseWriter, r *http.Request) {
			type versionResponse struct {
				Version string `json:"version"`
				Commit  string `json:"commit"`
				Date    string `json:"date"`
			}
			resp := versionResponse{
				Version: s.Version,
				Commit:  s.CommitID,
				Date:    s.BuildDate,
			}
			data, _ := json.MarshalIndent(resp, "", "  ")
			w.Header().Set("Content-Type", "application/json")
			// Write errors are unrecoverable once headers are sent; log is not actionable here.
			w.Write(data)         //nolint:errcheck
			w.Write([]byte("\n")) //nolint:errcheck
		})

		// JSON versions of public pages
		r.Get("/server/about", s.PagesHandler.APIV1ServerAboutHandler)
		r.Get("/server/help", s.PagesHandler.APIV1ServerHelpHandler)
		r.Get("/server/privacy", s.PagesHandler.APIV1ServerPrivacyHandler)
		r.Post("/server/contact", s.PagesHandler.APIV1ServerContactHandler)
		r.Get("/server/terms", s.PagesHandler.APIV1ServerTermsHandler)
		r.Get("/server/preferences", s.PagesHandler.APIV1ServerPreferencesHandler)
		r.Get("/server/preferences/export", s.PagesHandler.APIV1ServerPreferencesExportHandler)
		r.Get("/server/preferences/import", s.PagesHandler.APIV1ServerPreferencesImportHandler)

		// Swagger and GraphQL inside /api/v1
		if s.SwaggerJSONHandler != nil {
			r.Get("/server/swagger", s.SwaggerJSONHandler)
		}
		if s.GraphQLHandler != nil {
			r.Get("/server/graphql", s.GraphQLHandler)
			r.Post("/server/graphql", s.GraphQLHandler)
		}

		// Web routes that change state need the same JSON-capable API mirror
		// (AI.md PART 14 web/API parity); these handlers already answer 204 to
		// a non-HTML client, so they serve both surfaces unchanged.
		r.Post("/server/consent", s.PagesHandler.ConsentHandler)
		r.Post("/server/ccpa", s.PagesHandler.CCPAHandler)
		r.Post("/announcements/dismiss", s.PagesHandler.DismissAnnouncementHandler)

		// GeoIP-dependent routes
		if !s.gr.IsEmpty() {
			r.Get("/country", appHandlerToHTTP(s.APIV1CountryHandler))
			r.Get("/city", appHandlerToHTTP(s.APIV1CityHandler))
			r.Get("/asn", appHandlerToHTTP(s.APIV1ASNHandler))
			r.Get("/country-iso", appHandlerToHTTP(s.APIV1CountryISOHandler))
			r.Get("/coordinates", appHandlerToHTTP(s.APIV1CoordinatesHandler))
			r.Get("/asn-org", appHandlerToHTTP(s.APIV1ASNOrgHandler))
		}

		// Port reachability mirror of the web /port/* route.
		if s.LookupPort != nil {
			r.Get("/port/*", appHandlerToHTTP(s.PortHandler))
		}

		// Report endpoints per AI.md PART 13
		r.Post("/server/reports/csp", s.reportsHandler("csp"))
		r.Post("/server/reports/nel", s.reportsHandler("nel"))
		r.Post("/server/reports/deprecation", s.reportsHandler("deprecation"))
		r.Post("/server/reports/intervention", s.reportsHandler("intervention"))
		r.Post("/server/reports/crash", s.reportsHandler("crash"))
		r.Post("/server/reports/error", s.reportsHandler("error"))
		r.Post("/server/reports/default", s.reportsHandler("default"))
	})

	// JSON endpoint
	r.Get("/json", appHandlerToHTTP(s.JSONHandler))

	// CLI endpoints
	r.Get("/ip", appHandlerToHTTP(s.CLIHandler))
	r.Get("/ip.txt", appHandlerToHTTP(s.CLIHandler))
	if !s.gr.IsEmpty() {
		r.Get("/country", appHandlerToHTTP(s.CLICountryHandler))
		r.Get("/country.txt", appHandlerToHTTP(s.CLICountryHandler))
		r.Get("/country-iso", appHandlerToHTTP(s.CLICountryISOHandler))
		r.Get("/country-iso.txt", appHandlerToHTTP(s.CLICountryISOHandler))
		r.Get("/city", appHandlerToHTTP(s.CLICityHandler))
		r.Get("/city.txt", appHandlerToHTTP(s.CLICityHandler))
		r.Get("/coordinates", appHandlerToHTTP(s.CLICoordinatesHandler))
		r.Get("/coordinates.txt", appHandlerToHTTP(s.CLICoordinatesHandler))
		r.Get("/asn", appHandlerToHTTP(s.CLIASNHandler))
		r.Get("/asn.txt", appHandlerToHTTP(s.CLIASNHandler))
		r.Get("/asn-org", appHandlerToHTTP(s.CLIASNOrgHandler))
		r.Get("/asn-org.txt", appHandlerToHTTP(s.CLIASNOrgHandler))
	}

	// Root path with content negotiation (JSON/CLI/Browser)
	r.Get("/", s.rootHandler())

	// Port testing
	if s.LookupPort != nil {
		r.Get("/port/*", appHandlerToHTTP(s.PortHandler))
	}

	// Store router for /debug/routes inspection, then register debug routes.
	s.router = r
	// registerDebugRoutes checks s.config.IsDebug() internally.
	s.registerDebugRoutes(r)

	// IP lookup catch-all for /{ip} requests
	// Handles IPv4 like /8.8.8.8 and IPv6 like /2001:4860:4860::8888
	r.NotFound(s.ipLookupOrNotFound())

	// Apply CORS middleware per AI.md spec
	// Uses github.com/rs/cors with configuration from server.yml.
	// When tor.onion_address is set it is added to the allow-list automatically (AI.md PART 12).
	var h http.Handler = r
	corsOrigin := config.GetCORS()
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
		MaxAge: 86400,
	}
	if corsOrigin == "*" {
		corsOpts.AllowedOrigins = []string{"*"}
		corsOpts.AllowCredentials = false
	} else if corsOrigin != "" {
		corsOpts.AllowedOrigins = strings.Split(corsOrigin, ",")
		corsOpts.AllowCredentials = true
	}
	// Automatically add the Tor onion origin when the hidden service is running.
	// Wildcard already covers all origins; only append for explicit allow-lists or when
	// no CORS config is set (corsOrigin == "") so the onion browser fetch is not blocked.
	// Read live from TorStatus, not s.config.Tor.OnionAddress — see SpecialHandler wiring
	// above for why that field is never populated.
	onionHostname := ""
	if s.TorStatus != nil && s.TorStatus.IsAvailable() && s.TorStatus.IsRunning() {
		onionHostname = s.TorStatus.GetHostname()
	}
	if onionHostname != "" && corsOrigin != "*" {
		onionOrigin := "http://" + onionHostname
		corsOpts.AllowedOrigins = append(corsOpts.AllowedOrigins, onionOrigin)
		corsOpts.AllowCredentials = true
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
		corsOpts.AllowCredentials = true
		corsOrigin = "overlay-enabled"
	}
	if corsOrigin != "" {
		h = cors.New(corsOpts).Handler(h)
	}

	return h
}

// rootHandler handles content negotiation for the root path per AI.md PART 16.
// Uses detectClientType to dispatch to JSON, plain-text, or HTML handler.
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

// scanCLIBinaries scans {dataDir}/binaries/ for ipgaze-cli-{os}-{arch}[.exe] files
// and returns a map keyed by "{os}-{arch}" with the server version and the file's SHA-256
// digest. Files that cannot be read are silently skipped. Returns an empty map when
// dataDir is empty or the directory does not exist (AI.md PART 32).
func scanCLIBinaries(dataDir, version string) map[string]cliVersionEntry {
	result := make(map[string]cliVersionEntry)
	if dataDir == "" {
		return result
	}
	binDir := filepath.Join(dataDir, "binaries")
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
		if key == "" {
			continue
		}
		sum, sumErr := sha256File(filepath.Join(binDir, name))
		if sumErr != nil {
			continue
		}
		result[key] = cliVersionEntry{Version: version, SHA256: sum}
	}
	return result
}

// sha256File computes the hex-encoded SHA-256 digest of the file at path.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// autodiscoverHandler returns server capabilities for CLI/agent auto-configuration.
// Response shape per AI.md PART 13 and PART 32 (CLI auto-update):
//
//	server_name, version, api_version, base_url, primary, cluster,
//	features (object), cli_versions (map[os-arch]{version,sha256}), cli_min_version.
func (s *Server) autodiscoverHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type featuresObject struct {
			MultiUser     bool `json:"multi_user"`
			Orgs          bool `json:"orgs"`
			CustomDomains bool `json:"custom_domains"`
			GeoIP         bool `json:"geoip"`
			GeoIPDetailed bool `json:"geoip_detailed"`
			PortLookup    bool `json:"port_lookup"`
		}
		type autodiscoverResponse struct {
			ServerName    string                     `json:"server_name"`
			Version       string                     `json:"version"`
			APIVersion    string                     `json:"api_version"`
			BaseURL       string                     `json:"base_url"`
			Primary       string                     `json:"primary"`
			Cluster       []string                   `json:"cluster"`
			Features      featuresObject             `json:"features"`
			CLIVersions   map[string]cliVersionEntry `json:"cli_versions"`
			CLIMinVersion string                     `json:"cli_min_version"`
		}

		// BuildURL resolves proto/fqdn/port via the full priority chain (AI.md PART 12 → Resolution Order):
		// priority 0 = Tor onion match, then reverse-proxy headers, then DOMAIN env, etc.
		baseURL := netutil.BuildURL(r, s.getTrust(), "")

		resp := autodiscoverResponse{
			ServerName: "ipgaze",
			Version:    s.Version,
			APIVersion: "v1",
			BaseURL:    baseURL,
			Primary:    baseURL,
			Cluster:    []string{},
			Features: featuresObject{
				MultiUser:     false,
				Orgs:          false,
				CustomDomains: false,
				GeoIP:         true,
				GeoIPDetailed: !s.gr.IsEmpty(),
				PortLookup:    s.LookupPort != nil,
			},
			// Scan data dir for ipgaze-cli-{os}-{arch}[.exe] binaries and compute SHA-256 (AI.md PART 32).
			CLIVersions: scanCLIBinaries(s.DataDir, s.Version),
			// CLIMinVersion from config (AI.md PART 32 — config-driven, not hardcoded)
			CLIMinVersion: func() string {
				if s.config != nil && s.config.Server.CLIMinVersion != "" {
					return s.config.Server.CLIMinVersion
				}
				return "1.0.0"
			}(),
		}

		data, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			detectedLang := i18n.DetectLocale(r)
			http.Error(w, i18n.T(i18n.WithLang(r.Context(), detectedLang), "errors.server_error"), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
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
// Streams the binary from {data_dir}/binaries/{filename} (built by `make build`).
func (s *Server) cliBinaryDownloadHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract filename from URL (chi wildcard is everything after /cli/binaries/)
		filename := filepath.Base(r.URL.Path)
		if filename == "" || filename == "." || filename == "/" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Reject path traversal
		if strings.Contains(filename, "..") || strings.ContainsAny(filename, "/\\") {
			http.Error(w, "invalid filename", http.StatusBadRequest)
			return
		}

		// Binaries live in {data_dir}/binaries/ (DataDir set from --data flag in main)
		binPath := filepath.Join(s.DataDir, "binaries", filename)

		f, err := os.Open(binPath)
		if err != nil {
			if os.IsNotExist(err) {
				http.Error(w, "binary not found", http.StatusNotFound)
				return
			}
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		defer f.Close()

		fi, err := f.Stat()
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename="+filename)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", fi.Size()))
		// Detect OS from filename suffix to set correct MIME
		if strings.HasSuffix(filename, ".exe") {
			w.Header().Set("Content-Type", "application/vnd.microsoft.portable-executable")
		}

		if _, err := io.Copy(w, f); err != nil {
			// Write error after headers are sent; nothing actionable
			return
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
		if !s.reportLimiter.Allow(clientIP) {
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
			r.Body.Close()
		}

		// sanitizeLogValue strips control characters and truncates, so a
		// crafted report cannot forge extra security.log lines.
		s.logManager.WriteSecurity(event+" "+sanitizeLogValue(string(body)), clientIP)

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
		case "", "json":
			// /{ip} or /{ip}/json → full JSON response
			appHandlerToHTTP(s.IPLookupHandler)(w, r)
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

		fmt.Fprintln(w, val)
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
