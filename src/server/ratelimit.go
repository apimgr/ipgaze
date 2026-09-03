package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	i18n "github.com/apimgr/ipgaze/src/common/i18n"
	applog "github.com/apimgr/ipgaze/src/log"
	"github.com/apimgr/ipgaze/src/netutil"
	"golang.org/x/time/rate"
)

// rateClass identifies which per-endpoint-class bucket a request belongs to
// per AI.md PART 12: Read (GET/HEAD), Write (everything else), Health.
type rateClass string

const (
	rateClassRead   rateClass = "read"
	rateClassWrite  rateClass = "write"
	rateClassHealth rateClass = "health"
	// rateClassGlobal is the absolute per-IP ceiling across all classes.
	rateClassGlobal rateClass = "global"
)

// RateLimitBucket is one endpoint class's limit.
type RateLimitBucket struct {
	// Limit is the number of requests allowed per Window.
	Limit int
	// Window is the length of the sliding window.
	Window time.Duration
	// Burst is the maximum instantaneous burst. When zero it defaults to Limit.
	Burst int
}

// effectiveWindow guards against a misconfigured zero/negative window, which
// would make the computed rate infinite and silently disable rate limiting.
func (b RateLimitBucket) effectiveWindow() time.Duration {
	if b.Window <= 0 {
		return time.Minute
	}
	return b.Window
}

// effectiveBurst returns the burst size, defaulting to the full limit so a
// client may spend its whole allowance at once and then refill gradually.
func (b RateLimitBucket) effectiveBurst() int {
	if b.Burst > 0 {
		return b.Burst
	}
	if b.Limit > 0 {
		return b.Limit
	}
	return 1
}

// configured reports whether this bucket enforces anything.
func (b RateLimitBucket) configured() bool {
	return b.Limit > 0
}

// RateLimitConfig holds per-class rate limiter configuration per AI.md PART 12.
// All callers are anonymous; there is no authenticated vs unauthenticated distinction.
type RateLimitConfig struct {
	// Read applies to GET and HEAD requests.
	Read RateLimitBucket
	// Write applies to POST, PUT, PATCH, DELETE and every other method.
	Write RateLimitBucket
	// Health applies to the health-check endpoints.
	Health RateLimitBucket
	// Global is the absolute per-IP ceiling across all classes.
	Global RateLimitBucket
}

// DefaultRateLimitConfig returns the AI.md PART 12 per-class defaults:
// read 120/min, write 10/min, health 120/min, global ceiling 240/min.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Read:   RateLimitBucket{Limit: 120, Window: time.Minute},
		Write:  RateLimitBucket{Limit: 10, Window: time.Minute},
		Health: RateLimitBucket{Limit: 120, Window: time.Minute},
		Global: RateLimitBucket{Limit: 240, Window: time.Minute},
	}
}

// bucketFor returns the configured bucket for a class.
func (c RateLimitConfig) bucketFor(class rateClass) RateLimitBucket {
	switch class {
	case rateClassWrite:
		return c.Write
	case rateClassHealth:
		return c.Health
	case rateClassGlobal:
		return c.Global
	default:
		return c.Read
	}
}

// RateLimiter manages per-IP, per-class rate limiting with trusted proxy support.
type RateLimiter struct {
	limiters        map[string]*clientLimiter
	config          RateLimitConfig
	trust           *netutil.TrustResolver
	mu              sync.RWMutex
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
	// logManager receives a security.log entry for every rejection so
	// Fail2ban can ban a sustained offender (AI.md PART 11).
	logManager *applog.Manager
	// OnBlocked, if set, is invoked whenever a request is rejected for
	// exceeding the rate limit. Kept as a caller-supplied hook rather than a
	// direct dependency so this package stays decoupled from the notification
	// subsystem (AI.md PART 17/18's security_alert event).
	OnBlocked func(clientIP string)
}

type clientLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewRateLimiter creates a new rate limiter.
// trust is used to gate proxy header trust when extracting client IPs per AI.md PART 11/15.
// Any class left at its zero value falls back to the AI.md PART 12 default for
// that class, so a partially-populated config never disables enforcement.
func NewRateLimiter(cfg RateLimitConfig, trust *netutil.TrustResolver) *RateLimiter {
	defaults := DefaultRateLimitConfig()
	if !cfg.Read.configured() {
		cfg.Read = defaults.Read
	}
	if !cfg.Write.configured() {
		cfg.Write = defaults.Write
	}
	if !cfg.Health.configured() {
		cfg.Health = defaults.Health
	}
	if !cfg.Global.configured() {
		cfg.Global = defaults.Global
	}

	rl := &RateLimiter{
		limiters:        make(map[string]*clientLimiter),
		config:          cfg,
		trust:           trust,
		cleanupInterval: 10 * time.Minute,
		stopCleanup:     make(chan struct{}),
	}

	go rl.cleanupLoop()

	return rl
}

// SetLogManager attaches the log manager used to record rejections in
// security.log. Safe to leave unset; writes to a nil manager are no-ops.
func (rl *RateLimiter) SetLogManager(lm *applog.Manager) {
	rl.logManager = lm
}

// cleanupLoop periodically removes stale rate limiters
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.cleanup()
		case <-rl.stopCleanup:
			return
		}
	}
}

// cleanup removes limiters that haven't been seen in a while
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-10 * time.Minute)
	for key, cl := range rl.limiters {
		if cl.lastSeen.Before(cutoff) {
			delete(rl.limiters, key)
		}
	}
}

// Stop stops the rate limiter cleanup goroutine
func (rl *RateLimiter) Stop() {
	close(rl.stopCleanup)
}

// ReportRateLimiter caps the public browser-report endpoints per source IP
// (AI.md PART 11 "Reports Endpoint": rate-limit per-IP to prevent flooding).
// It is deliberately separate from the request RateLimiter: report POSTs are
// emitted by the browser, not by the user, so they must not consume the
// client's normal write budget — and the ceiling is configured on its own
// under web.reports.
type ReportRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*clientLimiter
	// perMinute is the sustained ceiling across all report types.
	perMinute int
	// burst is the short-burst allowance.
	burst       int
	stopCleanup chan struct{}
}

// NewReportRateLimiter builds a limiter allowing perMinute reports per minute
// per IP with the given short burst. Non-positive values fall back to the
// AI.md PART 11 defaults so a partly-filled config never disables the ceiling.
func NewReportRateLimiter(perMinute, burst int) *ReportRateLimiter {
	if perMinute < 1 {
		perMinute = 60
	}
	if burst < 1 {
		burst = 10
	}
	rrl := &ReportRateLimiter{
		limiters:    make(map[string]*clientLimiter),
		perMinute:   perMinute,
		burst:       burst,
		stopCleanup: make(chan struct{}),
	}
	go rrl.cleanupLoop()
	return rrl
}

// Allow reports whether one more report from clientIP is within the ceiling.
// A nil limiter allows everything so callers need no nil guard.
func (rrl *ReportRateLimiter) Allow(clientIP string) bool {
	if rrl == nil {
		return true
	}
	rrl.mu.Lock()
	defer rrl.mu.Unlock()

	cl, exists := rrl.limiters[clientIP]
	if !exists {
		cl = &clientLimiter{
			limiter: rate.NewLimiter(rate.Limit(float64(rrl.perMinute)/60.0), rrl.burst),
		}
		rrl.limiters[clientIP] = cl
	}
	cl.lastSeen = time.Now()
	return cl.limiter.Allow()
}

// cleanupLoop drops limiters for IPs that have stopped reporting.
func (rrl *ReportRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rrl.cleanup()
		case <-rrl.stopCleanup:
			return
		}
	}
}

// cleanup removes limiters that have not been seen in the last 10 minutes.
func (rrl *ReportRateLimiter) cleanup() {
	rrl.mu.Lock()
	defer rrl.mu.Unlock()

	cutoff := time.Now().Add(-10 * time.Minute)
	for key, cl := range rrl.limiters {
		if cl.lastSeen.Before(cutoff) {
			delete(rrl.limiters, key)
		}
	}
}

// Stop halts the cleanup goroutine.
func (rrl *ReportRateLimiter) Stop() {
	close(rrl.stopCleanup)
}

// getLimiter returns the rate limiter for a given client IP and endpoint class.
func (rl *RateLimiter) getLimiter(clientIP string, class rateClass) *rate.Limiter {
	key := clientIP + "|" + string(class)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	cl, exists := rl.limiters[key]
	if !exists {
		bucket := rl.config.bucketFor(class)
		rps := rate.Limit(float64(bucket.Limit) / bucket.effectiveWindow().Seconds())
		cl = &clientLimiter{
			limiter: rate.NewLimiter(rps, bucket.effectiveBurst()),
		}
		rl.limiters[key] = cl
	}

	cl.lastSeen = time.Now()
	return cl.limiter
}

// Allow reports whether a read-class request from the given IP is allowed.
// It is the convenience form of AllowClass for callers outside the middleware.
func (rl *RateLimiter) Allow(clientIP string) bool {
	return rl.AllowClass(clientIP, rateClassRead)
}

// AllowClass consumes one token from the class bucket and one from the global
// ceiling. Both must have capacity for the request to proceed; the global
// bucket is only charged when the class bucket admitted the request, so a
// rejected request never eats the caller's overall allowance twice.
func (rl *RateLimiter) AllowClass(clientIP string, class rateClass) bool {
	if !rl.getLimiter(clientIP, class).Allow() {
		return false
	}
	return rl.getLimiter(clientIP, rateClassGlobal).Allow()
}

// classifyRequest maps a request to its endpoint class per AI.md PART 12.
func classifyRequest(r *http.Request) rateClass {
	if healthCheckPaths[r.URL.Path] {
		return rateClassHealth
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return rateClassRead
	}
	return rateClassWrite
}

// RateLimitMiddleware creates HTTP middleware for per-IP, per-class rate limiting.
func RateLimitMiddleware(rl *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := rl.getClientIP(r)
			class := classifyRequest(r)

			if !rl.AllowClass(clientIP, class) {
				if rl.OnBlocked != nil {
					rl.OnBlocked(clientIP)
				}
				// Fail2ban-consumable record of the rejection (AI.md PART 11).
				rl.logManager.WriteSecurity("Rate limit exceeded", sanitizeLogValue(clientIP))

				bucket := rl.config.bucketFor(class)
				retryAfter := int(bucket.effectiveWindow().Seconds())
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
				w.Header().Set("X-RateLimit-Limit", strconv.Itoa(bucket.Limit))
				w.Header().Set("X-RateLimit-Remaining", "0")
				lang := i18n.DetectLocale(r)
				msg := i18n.T(i18n.WithLang(r.Context(), lang), "errors.rate_limited")
				// Per AI.md PART 12: the 429 body carries only ok/error/message —
				// the wait time is conveyed by the Retry-After header alone.
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				writeRateLimitedBody(w, msg)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// writeRateLimitedBody writes the canonical 429 JSON body. The message is
// emitted through the JSON string encoder so a translated string containing a
// quote or backslash cannot break the document.
func writeRateLimitedBody(w http.ResponseWriter, msg string) {
	body := struct {
		OK      bool   `json:"ok"`
		Error   string `json:"error"`
		Message string `json:"message"`
	}{false, "RATE_LIMITED", msg}
	b, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		return
	}
	w.Write(b)            //nolint:errcheck
	w.Write([]byte("\n")) //nolint:errcheck
}

// getClientIP extracts the real client IP, honoring proxy headers only when the peer is trusted.
func (rl *RateLimiter) getClientIP(r *http.Request) string {
	return netutil.GetClientIdentifier(r, rl.trust)
}
