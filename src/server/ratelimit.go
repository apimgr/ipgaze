package server

import (
	"container/list"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	i18n "github.com/apimgr/ipgaze/src/common/i18n"
	applog "github.com/apimgr/ipgaze/src/log"
	"github.com/apimgr/ipgaze/src/netutil"
	"github.com/apimgr/ipgaze/src/server/handler"
	"golang.org/x/time/rate"
)

// rateClass identifies which per-endpoint-class bucket a request belongs to
// per AI.md PART 12: Read (GET/HEAD), Write (everything else), Health.
type rateClass string

const (
	rateClassRead   rateClass = "read"
	rateClassWrite  rateClass = "write"
	rateClassHealth rateClass = "health"
	rateClassStrict rateClass = "strict"
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
	// Strict applies to token reveal, rotate, and restore attempts.
	Strict RateLimitBucket
	// AuthFailures controls the per-IP failed-authentication lockout.
	AuthFailures RateLimitBucket
	// Global is the absolute per-IP ceiling across all classes.
	Global RateLimitBucket
}

// DefaultRateLimitConfig returns the AI.md PART 12 per-class defaults:
// read 120/min, write 10/min, health 120/min, global ceiling 240/min.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Read:         RateLimitBucket{Limit: 120, Window: time.Minute},
		Write:        RateLimitBucket{Limit: 10, Window: time.Minute},
		Health:       RateLimitBucket{Limit: 120, Window: time.Minute},
		Strict:       RateLimitBucket{Limit: 10, Window: 15 * time.Minute},
		AuthFailures: RateLimitBucket{Limit: 5, Window: 15 * time.Minute},
		Global:       RateLimitBucket{Limit: 240, Window: time.Minute},
	}
}

// bucketFor returns the configured bucket for a class.
func (c RateLimitConfig) bucketFor(class rateClass) RateLimitBucket {
	switch class {
	case rateClassWrite:
		return c.Write
	case rateClassHealth:
		return c.Health
	case rateClassStrict:
		return c.Strict
	case rateClassGlobal:
		return c.Global
	default:
		return c.Read
	}
}

// RateLimiter manages per-IP, per-class rate limiting with trusted proxy support.
type RateLimiter struct {
	limiters         map[string]*clientLimiter
	lru              *list.List
	config           RateLimitConfig
	db               *sql.DB
	windowCounter    rateLimitWindowCounter
	identityForToken func(string, bool) (string, bool)
	authFailures     map[string][]time.Time
	trust            *netutil.TrustResolver
	mu               sync.RWMutex
	cleanupInterval  time.Duration
	stopCleanup      chan struct{}
	// logManager receives a security.log entry for every rejection so
	// Fail2ban can ban a sustained offender (AI.md PART 11).
	logManager *applog.Manager
	// OnBlocked, if set, is invoked whenever a request is rejected for
	// exceeding the rate limit. Kept as a caller-supplied hook rather than a
	// direct dependency so this package stays decoupled from the notification
	// subsystem (AI.md PART 17/18's security_alert event).
	OnBlocked func(clientIP string)
}

type rateLimitWindowCounter interface {
	SupportsRateLimitWindow() bool
	RateLimitWindow(context.Context, string, time.Time, time.Duration, int, bool) (int64, time.Time, error)
}

type clientLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
	entry    *list.Element
	key      string
}

const maxPerIPRateLimiters = 65536

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
	if !cfg.Strict.configured() {
		cfg.Strict = defaults.Strict
	}
	if !cfg.AuthFailures.configured() {
		cfg.AuthFailures = defaults.AuthFailures
	}
	if !cfg.Global.configured() {
		cfg.Global = defaults.Global
	}

	rl := &RateLimiter{
		limiters:        make(map[string]*clientLimiter),
		lru:             list.New(),
		config:          cfg,
		authFailures:    make(map[string][]time.Time),
		trust:           trust,
		cleanupInterval: 10 * time.Minute,
		stopCleanup:     make(chan struct{}),
	}

	go rl.cleanupLoop()

	return rl
}

// AuthFailureBlocked reports whether an IP has reached its failed-auth limit.
func (rl *RateLimiter) AuthFailureBlocked(clientIP string) (bool, time.Duration) {
	if rl.windowCounter != nil {
		now := time.Now()
		count, oldest, err := rl.windowCounter.RateLimitWindow(context.Background(), "auth_failures|ip:"+clientIP, now, rl.config.AuthFailures.effectiveWindow(), rl.config.AuthFailures.Limit, false)
		if err != nil {
			return true, rl.config.AuthFailures.effectiveWindow()
		}
		if count >= int64(rl.config.AuthFailures.Limit) {
			return true, rateLimitRetryAfter(oldest, rl.config.AuthFailures.effectiveWindow(), now)
		}
		return false, 0
	}
	if rl.db != nil {
		now := time.Now()
		count, windowStart, err := rateLimitDBWindow(rl.db, "auth_failures|ip:"+clientIP, now, rl.config.AuthFailures.effectiveWindow(), rl.config.AuthFailures.Limit, false)
		if err != nil {
			return true, rl.config.AuthFailures.effectiveWindow()
		}
		if count >= int64(rl.config.AuthFailures.Limit) {
			return true, rateLimitRetryAfter(windowStart, rl.config.AuthFailures.effectiveWindow(), now)
		}
		return false, 0
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	window := rl.config.AuthFailures.effectiveWindow()
	cutoff := now.Add(-window)
	failures := rl.authFailures[clientIP]
	first := 0
	for first < len(failures) && failures[first].Before(cutoff) {
		first++
	}
	failures = failures[first:]
	if len(failures) == 0 {
		delete(rl.authFailures, clientIP)
		return false, 0
	}
	rl.authFailures[clientIP] = failures
	if len(failures) < rl.config.AuthFailures.Limit {
		return false, 0
	}
	return true, time.Until(failures[0].Add(window))
}

// RecordAuthFailure adds one failed authentication to the per-IP window.
func (rl *RateLimiter) RecordAuthFailure(clientIP string) {
	if rl.windowCounter != nil {
		_, _, _ = rl.windowCounter.RateLimitWindow(context.Background(), "auth_failures|ip:"+clientIP, time.Now(), rl.config.AuthFailures.effectiveWindow(), rl.config.AuthFailures.Limit+1, true)
		return
	}
	if rl.db != nil {
		_, _, _ = rateLimitDBWindow(rl.db, "auth_failures|ip:"+clientIP, time.Now(), rl.config.AuthFailures.effectiveWindow(), rl.config.AuthFailures.Limit+1, true)
		return
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if len(rl.authFailures) >= maxPerIPRateLimiters {
		for ip := range rl.authFailures {
			delete(rl.authFailures, ip)
			break
		}
	}
	rl.authFailures[clientIP] = append(rl.authFailures[clientIP], time.Now())
}

// SetLogManager attaches the log manager used to record rejections in
// security.log. Safe to leave unset; writes to a nil manager are no-ops.
func (rl *RateLimiter) SetLogManager(lm *applog.Manager) {
	rl.logManager = lm
}

// SetDB enables persisted sliding-window counters in the application database.
func (rl *RateLimiter) SetDB(db *sql.DB) {
	rl.db = db
}

func (rl *RateLimiter) SetWindowCounter(counter rateLimitWindowCounter) {
	if counter != nil && counter.SupportsRateLimitWindow() {
		rl.windowCounter = counter
		return
	}
	rl.windowCounter = nil
}

// SetTokenIdentityResolver maps a validated Bearer token to its rate-limit subject.
// The boolean indicates whether the token was valid; invalid credentials remain per-IP.
func (rl *RateLimiter) SetTokenIdentityResolver(resolve func(string, bool) (string, bool)) {
	rl.identityForToken = resolve
}

func rateLimitDBWindow(db *sql.DB, key string, now time.Time, window time.Duration, threshold int, add bool) (int64, time.Time, error) {
	tx, err := db.Begin()
	if err != nil {
		return 0, time.Time{}, err
	}
	count, start, err := rateLimitDBWindowTx(tx, key, now, window, threshold, add)
	if err != nil {
		_ = tx.Rollback()
		return 0, time.Time{}, err
	}
	if err := tx.Commit(); err != nil {
		return 0, time.Time{}, err
	}
	return count, start, nil
}

func rateLimitDBWindowTx(tx *sql.Tx, key string, now time.Time, window time.Duration, threshold int, add bool) (int64, time.Time, error) {
	_ = threshold
	windowSeconds := int64(window.Seconds())
	if windowSeconds < 1 {
		windowSeconds = 1
	}
	nowSeconds := now.Unix()
	currentStart := nowSeconds - nowSeconds%windowSeconds
	if _, err := tx.Exec(`INSERT INTO rate_limits(key, count, prev_count, window_start, updated_at) VALUES(?, 0, 0, ?, ?) ON CONFLICT(key) DO NOTHING`, key, currentStart, nowSeconds); err != nil {
		return 0, time.Time{}, err
	}
	var count, previousCount, start int64
	if err := tx.QueryRow(`SELECT count, prev_count, window_start FROM rate_limits WHERE key = ?`, key).Scan(&count, &previousCount, &start); err != nil {
		return 0, time.Time{}, err
	}
	if currentStart > start {
		if currentStart-start >= 2*windowSeconds {
			previousCount = 0
		} else {
			previousCount = count
		}
		count = 0
		start = currentStart
	}
	if add {
		count++
	}
	if _, err := tx.Exec(`UPDATE rate_limits SET count = ?, prev_count = ?, window_start = ?, updated_at = ? WHERE key = ?`, count, previousCount, start, nowSeconds, key); err != nil {
		return 0, time.Time{}, err
	}
	elapsed := float64(nowSeconds-start) / float64(windowSeconds)
	effective := float64(previousCount)*(1-elapsed) + float64(count)
	return int64(math.Ceil(effective)), time.Unix(start, 0), nil
}

func (rl *RateLimiter) requestSubject(r *http.Request, class rateClass) string {
	clientIP := rl.getClientIP(r)
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && rl.identityForToken != nil {
		if subject, ok := rl.identityForToken(parts[1], class == rateClassStrict); ok {
			return subject
		}
	} else if class == rateClassStrict && rl.identityForToken != nil {
		if cookie, err := r.Cookie(handler.OwnerTokenCookieName); err == nil {
			if subject, ok := rl.identityForToken(cookie.Value, true); ok {
				return subject
			}
		}
	}
	return "ip:" + clientIP
}

func (rl *RateLimiter) allowPersisted(class rateClass, subject string) bool {
	if rl.windowCounter != nil {
		now := time.Now()
		keys := []struct {
			name   string
			bucket RateLimitBucket
		}{{string(class), rl.config.bucketFor(class)}}
		if class != rateClassGlobal {
			keys = append(keys, struct {
				name   string
				bucket RateLimitBucket
			}{string(rateClassGlobal), rl.config.Global})
		}
		for _, key := range keys {
			count, _, err := rl.windowCounter.RateLimitWindow(context.Background(), key.name+"|"+subject, now, key.bucket.effectiveWindow(), key.bucket.Limit+1, true)
			if err != nil || count > int64(key.bucket.Limit) {
				return false
			}
		}
		return true
	}
	if rl.db == nil {
		return false
	}
	tx, err := rl.db.Begin()
	if err != nil {
		return false
	}
	defer func() {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			slog.Warn("rate limit transaction rollback failed", "error", rollbackErr)
		}
	}()
	now := time.Now()
	keys := []struct {
		name   string
		bucket RateLimitBucket
	}{{string(class), rl.config.bucketFor(class)}}
	if class != rateClassGlobal {
		keys = append(keys, struct {
			name   string
			bucket RateLimitBucket
		}{string(rateClassGlobal), rl.config.Global})
	}
	allowed := true
	for _, key := range keys {
		bucketKey := key.name + "|" + subject
		count, _, err := rateLimitDBWindowTx(tx, bucketKey, now, key.bucket.effectiveWindow(), key.bucket.Limit+1, true)
		if err != nil {
			return false
		}
		if count > int64(key.bucket.Limit) {
			allowed = false
			break
		}
	}
	if err := tx.Commit(); err != nil {
		return false
	}
	return allowed
}

func (rl *RateLimiter) retryAfter(class rateClass, subject string) time.Duration {
	if rl.windowCounter != nil {
		now := time.Now()
		windows := []struct {
			class  rateClass
			bucket RateLimitBucket
		}{{class, rl.config.bucketFor(class)}}
		if class != rateClassGlobal {
			windows = append(windows, struct {
				class  rateClass
				bucket RateLimitBucket
			}{rateClassGlobal, rl.config.Global})
		}
		var retry time.Duration
		for _, item := range windows {
			_, oldest, err := rl.windowCounter.RateLimitWindow(context.Background(), fmt.Sprintf("%s|%s", item.class, subject), now, item.bucket.effectiveWindow(), item.bucket.Limit+1, false)
			if err == nil && !oldest.IsZero() {
				if remaining := time.Until(oldest.Add(item.bucket.effectiveWindow())); remaining > retry {
					retry = remaining
				}
			}
		}
		if retry < time.Second {
			return time.Second
		}
		return retry
	}
	if rl.db == nil {
		return rl.config.bucketFor(class).effectiveWindow()
	}
	now := time.Now()
	windows := []struct {
		class  rateClass
		bucket RateLimitBucket
	}{{class, rl.config.bucketFor(class)}}
	if class != rateClassGlobal {
		windows = append(windows, struct {
			class  rateClass
			bucket RateLimitBucket
		}{rateClassGlobal, rl.config.Global})
	}
	var retry time.Duration
	for _, item := range windows {
		count, windowStart, err := rateLimitDBWindow(rl.db, fmt.Sprintf("%s|%s", item.class, subject), now, item.bucket.effectiveWindow(), item.bucket.Limit+1, false)
		if err != nil || count <= int64(item.bucket.Limit) {
			continue
		}
		remaining := windowStart.Add(item.bucket.effectiveWindow()).Sub(now)
		if remaining > retry {
			retry = remaining
		}
	}
	if retry < time.Second {
		return time.Second
	}
	return retry
}

func rateLimitRetryAfter(oldest time.Time, window time.Duration, now time.Time) time.Duration {
	if oldest.IsZero() {
		return window
	}
	retry := oldest.Add(window).Sub(now)
	if retry < time.Second {
		return time.Second
	}
	return retry
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

	cutoff := time.Now().Add(-rl.retentionDuration())
	for key, cl := range rl.limiters {
		if cl.lastSeen.Before(cutoff) {
			delete(rl.limiters, key)
			rl.lru.Remove(cl.entry)
		}
	}
	if rl.db != nil {
		cutoffUnix := time.Now().Add(-rl.retentionDuration()).Unix()
		_, _ = rl.db.Exec(`DELETE FROM rate_limits WHERE window_start <= ?`, cutoffUnix)
	}
}

func (rl *RateLimiter) retentionDuration() time.Duration {
	retention := time.Minute
	for _, bucket := range []RateLimitBucket{rl.config.Read, rl.config.Write, rl.config.Health, rl.config.Strict, rl.config.AuthFailures, rl.config.Global} {
		window := bucket.effectiveWindow()
		burst := time.Duration(bucket.effectiveBurst()) * window / time.Duration(maxInt(bucket.Limit, 1))
		if window > retention {
			retention = window
		}
		if burst > retention {
			retention = burst
		}
	}
	return retention
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
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
	lru      *list.List
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
		lru:         list.New(),
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
	if rrl.lru == nil {
		rrl.lru = list.New()
		for key, cl := range rrl.limiters {
			cl.key = key
			cl.entry = rrl.lru.PushFront(cl)
		}
	}

	cl, exists := rrl.limiters[clientIP]
	if !exists {
		if rrl.lru.Len() >= maxPerIPRateLimiters {
			rrl.removeLRU()
		}
		cl = &clientLimiter{
			limiter: rate.NewLimiter(rate.Limit(float64(rrl.perMinute)/60.0), rrl.burst),
			key:     clientIP,
		}
		rrl.limiters[clientIP] = cl
		cl.entry = rrl.lru.PushFront(cl)
	}
	cl.lastSeen = time.Now()
	rrl.lru.MoveToFront(cl.entry)
	return cl.limiter.Allow()
}

func (rrl *ReportRateLimiter) removeLRU() {
	entry := rrl.lru.Back()
	if entry == nil {
		return
	}
	cl := entry.Value.(*clientLimiter)
	delete(rrl.limiters, cl.key)
	rrl.lru.Remove(entry)
}

// cleanupLoop drops limiters for IPs that have stopped reporting.
func (rrl *ReportRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
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

	cutoff := time.Now().Add(-time.Minute)
	for key, cl := range rrl.limiters {
		if cl.lastSeen.Before(cutoff) {
			delete(rrl.limiters, key)
			rrl.lru.Remove(cl.entry)
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
	if rl.lru == nil {
		rl.lru = list.New()
		for existingKey, existing := range rl.limiters {
			existing.key = existingKey
			existing.entry = rl.lru.PushFront(existing)
		}
	}

	cl, exists := rl.limiters[key]
	if !exists {
		if rl.lru.Len() >= maxPerIPRateLimiters {
			entry := rl.lru.Back()
			if entry != nil {
				oldest := entry.Value.(*clientLimiter)
				delete(rl.limiters, oldest.key)
				rl.lru.Remove(entry)
			}
		}
		bucket := rl.config.bucketFor(class)
		rps := rate.Limit(float64(bucket.Limit) / bucket.effectiveWindow().Seconds())
		cl = &clientLimiter{
			limiter: rate.NewLimiter(rps, bucket.effectiveBurst()),
			key:     key,
		}
		rl.limiters[key] = cl
		cl.entry = rl.lru.PushFront(cl)
	}

	cl.lastSeen = time.Now()
	rl.lru.MoveToFront(cl.entry)
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
	switch r.URL.Path {
	case "/server/preferences/token/reveal", "/server/preferences/token/rotate", "/server/preferences/token/restore", "/server/preferences/token/create",
		"/api/v1/server/preferences/tokens/primary", "/api/v1/server/preferences/tokens/primary/reveal", "/api/v1/server/preferences/tokens/primary/rotate":
		return rateClassStrict
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/server/preferences/tokens/") &&
		(strings.HasSuffix(r.URL.Path, "/reveal") || strings.HasSuffix(r.URL.Path, "/rotate")) {
		return rateClassStrict
	}
	if strings.HasPrefix(r.URL.Path, "/server/preferences/tokens/") &&
		(strings.HasSuffix(r.URL.Path, "/reveal") || strings.HasSuffix(r.URL.Path, "/rotate")) {
		return rateClassStrict
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
			if blocked, retryAfter := rl.AuthFailureBlocked(clientIP); blocked {
				writeRateLimitResponse(w, r, retryAfter)
				return
			}
			if IsAllowlisted(r.Context()) {
				next.ServeHTTP(w, r)
				return
			}
			class := classifyRequest(r)
			isI2P := netutil.IsI2PRequest(r, rl.trust)
			if isI2P {
				// I2P streams share one loopback listener, so apply one dedicated
				// global bucket instead of charging 127.0.0.1 to per-IP classes.
				class = rateClassGlobal
			}

			var allowed bool
			if isI2P {
				allowed = rl.getLimiter(clientIP, rateClassGlobal).Allow()
			} else if rl.db != nil || rl.windowCounter != nil {
				allowed = rl.allowPersisted(class, rl.requestSubject(r, class))
			} else {
				allowed = rl.AllowClass(clientIP, class)
			}
			if !allowed {
				if rl.OnBlocked != nil {
					rl.OnBlocked(clientIP)
				}
				// Fail2ban-consumable record of the rejection (AI.md PART 11).
				rl.logManager.WriteSecurity("Rate limit exceeded", sanitizeLogValue(clientIP))

				subject := "ip:" + clientIP
				if !isI2P {
					subject = rl.requestSubject(r, class)
				}
				writeRateLimitResponse(w, r, rl.retryAfter(class, subject))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func writeRateLimitResponse(w http.ResponseWriter, r *http.Request, retryAfter time.Duration) {
	seconds := int((retryAfter + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	writeRateLimitedBody(w, i18n.T(i18n.WithLang(r.Context(), i18n.DetectLocale(r)), "errors.rate_limited"))
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
	return clientIPIdentifier(r, rl.trust)
}
