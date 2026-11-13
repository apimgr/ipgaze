package server

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	i18n "github.com/apimgr/ipgaze/src/common/i18n"
	"github.com/apimgr/ipgaze/src/config"
	applog "github.com/apimgr/ipgaze/src/log"
	"github.com/apimgr/ipgaze/src/netutil"
)

// AbusePolicy contains the runtime limits used by the flood detector.
type AbusePolicy struct {
	Enabled       bool
	AutoBlockIP   bool
	AutoAlert     bool
	Multiplier    int
	Window        time.Duration
	BlockDuration time.Duration
	Limits        RateLimitConfig
	Permanent     []config.BlockedIPEntry
}

// AbusePolicyFromConfig translates the operator settings to runtime policy.
// Flood counting remains active when automatic blocking and alerting are off;
// those settings control only the corresponding actions.
func AbusePolicyFromConfig(cfg *config.AppConfig, limits RateLimitConfig) AbusePolicy {
	if cfg == nil {
		return AbusePolicy{}
	}
	settings := cfg.Server.Security.AbuseDetection
	window, err := time.ParseDuration(strings.TrimSpace(settings.RequestFlood.Window))
	if err != nil || window <= 0 {
		window = time.Minute
	}
	blockDuration, err := time.ParseDuration(strings.TrimSpace(settings.RequestFlood.BlockDuration))
	if err != nil || blockDuration <= 0 {
		blockDuration = time.Hour
	}
	return AbusePolicy{
		Enabled:       true,
		AutoBlockIP:   settings.AutoBlockIP,
		AutoAlert:     settings.AutoAlert,
		Multiplier:    settings.RequestFlood.Multiplier,
		Window:        window,
		BlockDuration: blockDuration,
		Limits:        limits,
		Permanent:     cfg.Server.Security.BlockedIPs,
	}
}

type requestCounts struct {
	classes map[rateClass][]time.Time
	total   []time.Time
	last    time.Time
	flooded bool
}

// AbuseMiddleware enforces configured permanent and persisted temporary IP
// blocks, then counts requests for flood detection. It must run before the
// normal rate limiter so requests rejected with 429 still count toward a flood.
func AbuseMiddleware(db *sql.DB, policy AbusePolicy, trust *netutil.TrustResolver, allowlist *AllowlistLookup, logs *applog.Manager, onAlert func(string)) func(http.Handler) http.Handler {
	if policy.Multiplier < 1 {
		policy.Multiplier = 10
	}
	if policy.Window <= 0 {
		policy.Window = time.Minute
	}
	if policy.BlockDuration <= 0 {
		policy.BlockDuration = time.Hour
	}
	if db != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err := db.ExecContext(cleanupCtx, `DELETE FROM ip_blocks WHERE expires_at <= ?`, time.Now().Unix())
		cancel()
		if err != nil {
			log.Printf("abuse block cleanup: failed to remove expired IP blocks: %v", err)
		}
	}
	permanent := compileIPBlocks(policy.Permanent)
	counts := &requestCounter{clients: make(map[string]*requestCounts)}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := extractIP(r)
			if ip == nil || IsTorRequestContext(r.Context()) || netutil.IsTorRequest(r, trust) || netutil.IsI2PRequest(r, trust) {
				next.ServeHTTP(w, r)
				return
			}
			if IsAllowlisted(r.Context()) || allowlist != nil && allowlist.Contains(ip) {
				if db != nil {
					writeCtx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
					_, err := db.ExecContext(writeCtx, `DELETE FROM ip_blocks WHERE ip = ?`, ip.String())
					cancel()
					if err != nil {
						writeAbuseStorageError(w, r, logs, err)
						return
					}
				}
				next.ServeHTTP(w, r)
				return
			}
			blocked, err := isIPBlocked(r.Context(), db, ip, permanent, time.Now())
			if err != nil {
				writeAbuseStorageError(w, r, logs, err)
				return
			}
			if blocked {
				writeSecurityBlocked(w, r)
				return
			}
			if policy.Enabled {
				class := classifyRequest(r)
				flood, newFlood, count := counts.add(ip.String(), class, policy, time.Now())
				if newFlood {
					if logs != nil {
						result := "detected"
						if policy.AutoBlockIP {
							result = "blocked"
						}
						logs.WriteAuditEvent("", "abuse.request_flood", "security", "warn", result, ip.String(), map[string]any{
							"class": string(class), "count": count, "block_duration": policy.BlockDuration.String(),
						})
					}
					if policy.AutoAlert && onAlert != nil {
						onAlert(ip.String())
					}
				}
				if flood && policy.AutoBlockIP {
					expires := time.Now().Add(policy.BlockDuration)
					if err := persistTemporaryIPBlock(r.Context(), db, ip.String(), expires, count); err != nil {
						writeAbuseStorageError(w, r, logs, err)
						return
					}
					writeSecurityBlocked(w, r)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func writeAbuseStorageError(w http.ResponseWriter, r *http.Request, logs *applog.Manager, err error) {
	detail := fmt.Sprintf("abuse storage unavailable: request_id=%s http_status=%d method=%s path=%s ip=%s internal=%v",
		RequestIDFromContext(r.Context()), http.StatusServiceUnavailable, r.Method, r.URL.Path, clientIPIdentifier(r), err)
	log.Print(detail)
	if logs != nil {
		logs.WriteError("error", detail)
	}
	writeNegotiatedError(w, r, http.StatusServiceUnavailable, "", i18n.T(r.Context(), "errors.server_error"))
}

func writeSecurityBlocked(w http.ResponseWriter, r *http.Request) {
	lang := i18n.DetectLocale(r)
	writeForbidden(w, r, i18n.T(i18n.WithLang(r.Context(), lang), "errors.blocked_by_blocklist"))
}

type requestCounter struct {
	mu      sync.Mutex
	clients map[string]*requestCounts
}

func (c *requestCounter) add(ip string, class rateClass, policy AbusePolicy, now time.Time) (bool, bool, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	state := c.clients[ip]
	if state == nil {
		state = &requestCounts{classes: make(map[rateClass][]time.Time)}
		c.clients[ip] = state
	}
	cutoff := now.Add(-policy.Window)
	state.total = retainRecent(state.total, cutoff)
	for kind, times := range state.classes {
		state.classes[kind] = retainRecent(times, cutoff)
	}
	state.total = append(state.total, now)
	state.classes[class] = append(state.classes[class], now)
	state.last = now
	if len(c.clients) > 10000 {
		for key, entry := range c.clients {
			if now.Sub(entry.last) > 10*time.Minute {
				delete(c.clients, key)
			}
		}
	}
	classCount := len(state.classes[class])
	limit := policy.Limits.bucketFor(class).Limit
	if limit < 1 {
		limit = DefaultRateLimitConfig().bucketFor(class).Limit
	}
	global := policy.Limits.Global.Limit
	if global < 1 {
		global = DefaultRateLimitConfig().Global.Limit
	}
	flood := classCount > policy.Multiplier*limit || len(state.total) > policy.Multiplier*global
	newFlood := flood && !state.flooded
	state.flooded = flood
	return flood, newFlood, max(classCount, len(state.total))
}

func retainRecent(values []time.Time, cutoff time.Time) []time.Time {
	first := 0
	for first < len(values) && values[first].Before(cutoff) {
		first++
	}
	return values[first:]
}

func compileIPBlocks(entries []config.BlockedIPEntry) []*net.IPNet {
	var result []*net.IPNet
	for _, entry := range entries {
		value := strings.TrimSpace(entry.CIDR)
		if value == "" {
			continue
		}
		if !strings.Contains(value, "/") {
			if strings.Contains(value, ":") {
				value += "/128"
			} else {
				value += "/32"
			}
		}
		_, network, err := net.ParseCIDR(value)
		if err == nil {
			result = append(result, network)
		}
	}
	return result
}

func isIPBlocked(ctx context.Context, db *sql.DB, ip net.IP, permanent []*net.IPNet, now time.Time) (bool, error) {
	for _, network := range permanent {
		if network.Contains(ip) {
			return true, nil
		}
	}
	if db == nil {
		return false, nil
	}
	var expires int64
	readCtx, cancelRead := context.WithTimeout(ctx, 5*time.Second)
	err := db.QueryRowContext(readCtx, `SELECT expires_at FROM ip_blocks WHERE ip = ?`, ip.String()).Scan(&expires)
	cancelRead()
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("lookup temporary IP block: %w", err)
	}
	if expires <= now.Unix() {
		writeCtx, cancelWrite := context.WithTimeout(ctx, 10*time.Second)
		_, err := db.ExecContext(writeCtx, `DELETE FROM ip_blocks WHERE ip = ? AND expires_at <= ?`, ip.String(), now.Unix())
		cancelWrite()
		if err != nil {
			return false, fmt.Errorf("expire temporary IP block: %w", err)
		}
		return false, nil
	}
	return true, nil
}

func persistTemporaryIPBlock(ctx context.Context, db *sql.DB, ip string, expires time.Time, offenseCount int) error {
	if db == nil {
		return fmt.Errorf("temporary IP block database unavailable")
	}
	writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, err := db.ExecContext(writeCtx, `INSERT INTO ip_blocks (ip, reason, blocked_at, expires_at, offense_count, auto_blocked)
VALUES (?, 'request flood', ?, ?, ?, 1)
ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason, blocked_at=excluded.blocked_at,
expires_at=MAX(ip_blocks.expires_at, excluded.expires_at), offense_count=ip_blocks.offense_count+1, auto_blocked=1`,
		ip, time.Now().Unix(), expires.Unix(), offenseCount)
	if err != nil {
		return fmt.Errorf("persist temporary IP block: %w", err)
	}
	return nil
}
