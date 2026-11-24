// Package cache provides a unified caching interface over multiple backends
// (in-process memory, Valkey/Redis, Memcache) as specified in AI.md PART 9.
package cache

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apimgr/ipgaze/src/config"
	"github.com/bradfitz/gomemcache/memcache"
	"github.com/redis/go-redis/v9"
)

// Cache is the common interface implemented by every backend.
type Cache interface {
	// Get retrieves the value stored under key. Returns ErrNotFound if absent.
	Get(ctx context.Context, key string) ([]byte, error)
	// Set stores value under key with the given TTL. Zero TTL uses the backend default.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	// Delete removes key. It is a no-op if the key does not exist.
	Delete(ctx context.Context, key string) error
	// Flush removes all entries from the cache.
	Flush(ctx context.Context) error
	// Ping verifies connectivity to the backend. Backends with no network
	// dependency (noop, memory) always report healthy. Used by the /server/healthz
	// checks.cache probe (AI.md PART 13).
	Ping(ctx context.Context) error
	// Close releases any connections held by the backend.
	Close() error
}

// SlidingWindowCounter is implemented by external caches that can atomically
// track rate-limit events across server instances.
type SlidingWindowCounter interface {
	SupportsRateLimitWindow() bool
	RateLimitWindow(ctx context.Context, key string, now time.Time, window time.Duration, threshold int, add bool) (int64, time.Time, error)
}

// ErrNotFound is returned by Get when the requested key does not exist.
var ErrNotFound = fmt.Errorf("cache: key not found")

// ApplyEnvOverrides is retained for compatibility. Connection environment
// variables are consumed only during first-run config initialization.
func ApplyEnvOverrides(_ *config.CacheConfig) {}

// NewCache constructs the appropriate Cache backend from cfg.
// Supported types: "none", "memory", "valkey", "redis", "memcache".
// An empty or unrecognised type falls back to the memory backend.
func NewCache(cfg config.CacheConfig) (Cache, error) {
	defaultTTL := parseDuration(cfg.TTL, time.Hour)
	prefix := cfg.Prefix

	switch cfg.Type {
	case "none":
		return newNoopCache(), nil
	case "valkey", "redis":
		return newRedisCache(cfg, prefix, defaultTTL)
	case "memcache":
		return newMemcacheCache(cfg, prefix, defaultTTL)
	default:
		if cfg.URL != "" {
			return nil, fmt.Errorf("cache connection URL has an unsupported scheme; use valkey://, valkeys://, redis://, or rediss://")
		}
		return newMemoryCache(prefix, defaultTTL), nil
	}
}

// Key builds a cache key using the standard ipgaze pattern: prefix + resource + ":" + id.
// If the Cache instance has its own prefix baked in, callers can pass prefix="" and rely
// on the backend to prepend it automatically. This helper is for explicit key construction.
func Key(prefix, resource, id string) string {
	if prefix != "" {
		return prefix + resource + ":" + id
	}
	return resource + ":" + id
}

// parseDuration parses s as a time.Duration and returns fallback on failure or empty.
func parseDuration(s string, fallback time.Duration) time.Duration {
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}

// ---------- noop backend ----------

type noopCache struct{}

func newNoopCache() Cache { return &noopCache{} }

func (n *noopCache) Get(_ context.Context, _ string) ([]byte, error) { return nil, ErrNotFound }
func (n *noopCache) Set(_ context.Context, _ string, _ []byte, _ time.Duration) error {
	return nil
}
func (n *noopCache) Delete(_ context.Context, _ string) error { return nil }
func (n *noopCache) Flush(_ context.Context) error            { return nil }
func (n *noopCache) Ping(_ context.Context) error             { return nil }
func (n *noopCache) Close() error                             { return nil }

// ---------- memory backend ----------

type memoryEntry struct {
	value   []byte
	expires time.Time
}

// memoryJanitorInterval is how often the background sweep removes expired
// entries from a memoryCache. Without this sweep, keys that are Set but
// never Get again (e.g. a rolled-over rate-limit counter) are only ever
// deleted lazily on read, so an idle process accumulates stale entries
// forever.
const memoryJanitorInterval = 5 * time.Minute

type memoryCache struct {
	mu          sync.RWMutex
	entries     map[string]memoryEntry
	prefix      string
	defaultTTL  time.Duration
	stopJanitor chan struct{}
	closeOnce   sync.Once
}

func newMemoryCache(prefix string, defaultTTL time.Duration) Cache {
	m := &memoryCache{
		entries:     make(map[string]memoryEntry),
		prefix:      prefix,
		defaultTTL:  defaultTTL,
		stopJanitor: make(chan struct{}),
	}
	go m.runJanitor()
	return m
}

// runJanitor periodically sweeps expired entries out of the map so an idle
// memory cache does not grow unbounded. It exits when stopJanitor is closed
// by Close().
func (m *memoryCache) runJanitor() {
	ticker := time.NewTicker(memoryJanitorInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			m.mu.Lock()
			for k, e := range m.entries {
				if now.After(e.expires) {
					delete(m.entries, k)
				}
			}
			m.mu.Unlock()
		case <-m.stopJanitor:
			return
		}
	}
}

func (m *memoryCache) key(k string) string { return m.prefix + k }

func (m *memoryCache) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.RLock()
	e, ok := m.entries[m.key(key)]
	m.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	if time.Now().After(e.expires) {
		m.mu.Lock()
		delete(m.entries, m.key(key))
		m.mu.Unlock()
		return nil, ErrNotFound
	}
	out := make([]byte, len(e.value))
	copy(out, e.value)
	return out, nil
}

func (m *memoryCache) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = m.defaultTTL
	}
	buf := make([]byte, len(value))
	copy(buf, value)
	m.mu.Lock()
	m.entries[m.key(key)] = memoryEntry{value: buf, expires: time.Now().Add(ttl)}
	m.mu.Unlock()
	return nil
}

func (m *memoryCache) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	delete(m.entries, m.key(key))
	m.mu.Unlock()
	return nil
}

func (m *memoryCache) Flush(_ context.Context) error {
	m.mu.Lock()
	m.entries = make(map[string]memoryEntry)
	m.mu.Unlock()
	return nil
}

func (m *memoryCache) Ping(_ context.Context) error { return nil }

func (m *memoryCache) Close() error {
	m.closeOnce.Do(func() { close(m.stopJanitor) })
	return nil
}

// ---------- Redis / Valkey backend ----------

type redisCache struct {
	client     *redis.Client
	prefix     string
	defaultTTL time.Duration
}

func newRedisCache(cfg config.CacheConfig, prefix string, defaultTTL time.Duration) (Cache, error) {
	timeout := parseDuration(cfg.Timeout, 5*time.Second)

	opts := &redis.Options{
		Username:     cfg.Username,
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdle,
		DialTimeout:  timeout,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
	}

	urlTLS := false
	urlSkipVerify := false
	verifySpecified := false
	if cfg.URL != "" {
		connectionURL := encodeRawUserinfo(cfg.URL)
		if parsedURL, err := url.Parse(connectionURL); err == nil {
			query := parsedURL.Query()
			urlTLS = strings.EqualFold(parsedURL.Scheme, "rediss") || strings.EqualFold(parsedURL.Scheme, "valkeys")
			for key, values := range query {
				switch strings.ToLower(key) {
				case "tls", "encrypt":
					if len(values) > 0 {
						urlTLS = strings.EqualFold(values[0], "true") || values[0] == "1"
					}
					delete(query, key)
				case "sslmode":
					if len(values) > 0 {
						switch strings.ToLower(values[0]) {
						case "disable":
							urlTLS = false
						case "require", "verify-ca", "verify-full":
							urlTLS = true
							verifySpecified = strings.EqualFold(values[0], "verify-ca") || strings.EqualFold(values[0], "verify-full")
							urlSkipVerify = false
						}
					}
					delete(query, key)
				case "tls_skip_verify":
					if len(values) > 0 {
						verifySpecified = true
						urlSkipVerify = strings.EqualFold(values[0], "true") || values[0] == "1"
					}
					delete(query, key)
				}
			}
			parsedURL.RawQuery = query.Encode()
			connectionURL = parsedURL.String()
		}
		switch {
		case strings.HasPrefix(strings.ToLower(connectionURL), "valkey://"):
			connectionURL = "redis://" + connectionURL[len("valkey://"):]
		case strings.HasPrefix(strings.ToLower(connectionURL), "valkeys://"):
			connectionURL = "rediss://" + connectionURL[len("valkeys://"):]
		}
		parsed, err := redis.ParseURL(connectionURL)
		if err != nil {
			return nil, fmt.Errorf("cache: invalid connection URL (credentials are omitted)")
		}
		opts = parsed
		// Respect pool settings from config even when URL is used.
		if cfg.PoolSize > 0 {
			opts.PoolSize = cfg.PoolSize
		}
		if cfg.MinIdle > 0 {
			opts.MinIdleConns = cfg.MinIdle
		}
	} else {
		host := cfg.Host
		if host == "" {
			host = "localhost"
		}
		port := cfg.Port
		if port == 0 {
			port = 6379
		}
		opts.Addr = net.JoinHostPort(host, fmt.Sprintf("%d", port))
	}

	requestedTLS := cfg.TLS || opts.TLSConfig != nil || urlTLS || cfg.TLSCA != "" || cfg.TLSCert != "" || cfg.TLSKey != ""
	if requestedTLS {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if opts.TLSConfig != nil {
			tlsCfg = opts.TLSConfig.Clone()
			tlsCfg.MinVersion = tls.VersionTLS12
		}
		if cfg.TLS || urlTLS {
			tlsCfg.InsecureSkipVerify = cfg.TLSSkipVerify //nolint:gosec
			if urlTLS && !verifySpecified {
				tlsCfg.InsecureSkipVerify = true //nolint:gosec
			}
			if verifySpecified {
				tlsCfg.InsecureSkipVerify = urlSkipVerify //nolint:gosec
			}
		}
		if caPath := cfg.TLSCA; caPath != "" {
			resolved, err := resolveTLSFile(caPath)
			if err != nil {
				return nil, fmt.Errorf("cache: invalid tls_ca path")
			}
			caPEM, err := os.ReadFile(resolved)
			if err != nil {
				return nil, fmt.Errorf("cache: cannot read tls_ca file")
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caPEM) {
				return nil, fmt.Errorf("cache: tls_ca contains no certificates")
			}
			tlsCfg.RootCAs = pool
			tlsCfg.InsecureSkipVerify = false
		}
		if cfg.TLSCert != "" || cfg.TLSKey != "" {
			certPath, certErr := resolveTLSFile(cfg.TLSCert)
			keyPath, keyErr := resolveTLSFile(cfg.TLSKey)
			if certErr != nil || keyErr != nil {
				return nil, fmt.Errorf("cache: invalid tls_cert or tls_key path")
			}
			certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				return nil, fmt.Errorf("cache: cannot load client TLS certificate")
			}
			tlsCfg.Certificates = []tls.Certificate{certificate}
		}
		opts.TLSConfig = tlsCfg
	}

	client := redis.NewClient(opts)
	return &redisCache{client: client, prefix: prefix, defaultTTL: defaultTTL}, nil
}

func encodeRawUserinfo(raw string) string {
	schemeEnd := strings.Index(raw, "://")
	if schemeEnd < 0 {
		return raw
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.User != nil {
		return raw
	}
	authorityStart := schemeEnd + 3
	searchFrom := authorityStart
	for {
		relativeAt := strings.IndexByte(raw[searchFrom:], '@')
		if relativeAt < 0 {
			break
		}
		at := searchFrom + relativeAt
		parsed, err := url.Parse("redis://" + raw[at+1:])
		if err != nil || parsed.Hostname() == "" || parsed.User != nil {
			searchFrom = at + 1
			continue
		}
		userinfo := raw[authorityStart:at]
		if !strings.Contains(userinfo, ":") && strings.Contains(userinfo, "=") {
			return raw
		}
		username, password, hasPassword := strings.Cut(userinfo, ":")
		if !hasPassword {
			password = username
			username = ""
		}
		encoded := encodeURLUserinfoPart(username)
		if hasPassword {
			encoded += ":"
		}
		encoded += encodeURLUserinfoPart(password)
		return raw[:authorityStart] + encoded + raw[at:]
	}
	return raw
}

func encodeURLUserinfoPart(raw string) string {
	const hexDigits = "0123456789abcdefABCDEF"
	var encoded strings.Builder
	for index := 0; index < len(raw); index++ {
		char := raw[index]
		if isUnreservedURLByte(char) {
			encoded.WriteByte(char)
			continue
		}
		if char == '%' && index+2 < len(raw) && strings.ContainsRune(hexDigits, rune(raw[index+1])) && strings.ContainsRune(hexDigits, rune(raw[index+2])) {
			encoded.WriteString(raw[index : index+3])
			index += 2
			continue
		}
		const hex = "0123456789ABCDEF"
		encoded.WriteByte('%')
		encoded.WriteByte(hex[char>>4])
		encoded.WriteByte(hex[char&0x0f])
	}
	return encoded.String()
}

func isUnreservedURLByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || strings.ContainsRune("-._~", rune(value))
}

func resolveTLSFile(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty TLS path")
	}
	sslDir := filepath.Join(config.ConfigDirectory(), "ssl")
	resolved := path
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(sslDir, resolved)
	}
	resolved, err := filepath.Abs(resolved)
	if err != nil {
		return "", err
	}
	root, err := filepath.Abs(sslDir)
	if err != nil {
		return "", err
	}
	resolved, err = filepath.EvalSymlinks(resolved)
	if err != nil {
		return "", err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("TLS file must be inside config ssl directory")
	}
	return resolved, nil
}

func (r *redisCache) key(k string) string { return r.prefix + k }

func (r *redisCache) Get(ctx context.Context, key string) ([]byte, error) {
	val, err := r.client.Get(ctx, r.key(key)).Bytes()
	if err == redis.Nil {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("cache: redis get %q: %w", key, err)
	}
	return val, nil
}

func (r *redisCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = r.defaultTTL
	}
	if err := r.client.Set(ctx, r.key(key), value, ttl).Err(); err != nil {
		return fmt.Errorf("cache: redis set %q: %w", key, err)
	}
	return nil
}

func (r *redisCache) Delete(ctx context.Context, key string) error {
	if err := r.client.Del(ctx, r.key(key)).Err(); err != nil {
		return fmt.Errorf("cache: redis del %q: %w", key, err)
	}
	return nil
}

func (r *redisCache) Flush(ctx context.Context) error {
	if err := r.client.FlushDB(ctx).Err(); err != nil {
		return fmt.Errorf("cache: redis flushdb: %w", err)
	}
	return nil
}

func (r *redisCache) Ping(ctx context.Context) error {
	if err := r.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("cache: redis ping: %w", err)
	}
	return nil
}

func (r *redisCache) Close() error { return r.client.Close() }

func (r *redisCache) SupportsRateLimitWindow() bool { return true }

func (r *redisCache) RateLimitWindow(ctx context.Context, key string, now time.Time, window time.Duration, threshold int, add bool) (int64, time.Time, error) {
	const script = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local add = tonumber(ARGV[4])
local current_start = math.floor(now / window) * window
local count = tonumber(redis.call('HGET', key, 'count') or '0')
local prev_count = tonumber(redis.call('HGET', key, 'prev_count') or '0')
local window_start = tonumber(redis.call('HGET', key, 'window_start') or tostring(current_start))
if current_start > window_start then
  if current_start - window_start >= 2 * window then prev_count = 0 else prev_count = count end
  count = 0
  window_start = current_start
end
if add == 1 then
  count = count + 1
end
redis.call('HSET', key, 'count', count, 'prev_count', prev_count, 'window_start', window_start)
redis.call('PEXPIRE', key, 2 * window + 1000)
local elapsed = (now - window_start) / window
local effective = math.ceil(prev_count * (1 - elapsed) + count)
return {effective, window_start}
`
	windowMillis := window.Milliseconds()
	if windowMillis < 1 {
		windowMillis = 1
	}
	_ = threshold
	result, err := r.client.Eval(ctx, script, []string{r.key("rate_limit:" + key)}, now.UnixMilli(), windowMillis, threshold, boolToInt(add)).Result()
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("cache: redis rate-limit window: %w", err)
	}
	values, ok := result.([]interface{})
	if !ok || len(values) != 2 {
		return 0, time.Time{}, fmt.Errorf("cache: invalid redis rate-limit response")
	}
	count, err := redisInt64(values[0])
	if err != nil {
		return 0, time.Time{}, err
	}
	oldestMillis, err := redisInt64(values[1])
	if err != nil {
		return 0, time.Time{}, err
	}
	if oldestMillis == 0 {
		return count, time.Time{}, nil
	}
	return count, time.UnixMilli(oldestMillis), nil
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func redisInt64(value interface{}) (int64, error) {
	switch number := value.(type) {
	case int64:
		return number, nil
	case string:
		parsed, err := strconv.ParseInt(number, 10, 64)
		return parsed, err
	case []byte:
		parsed, err := strconv.ParseInt(string(number), 10, 64)
		return parsed, err
	default:
		return 0, fmt.Errorf("cache: invalid redis integer response")
	}
}

// ---------- Memcache backend ----------

type memcacheCache struct {
	client     *memcache.Client
	prefix     string
	defaultTTL time.Duration
}

func newMemcacheCache(cfg config.CacheConfig, prefix string, defaultTTL time.Duration) (Cache, error) {
	addr := cfg.URL
	if addr == "" {
		host := cfg.Host
		if host == "" {
			host = "localhost"
		}
		port := cfg.Port
		if port == 0 {
			port = 11211
		}
		addr = net.JoinHostPort(host, fmt.Sprintf("%d", port))
	}

	timeout := parseDuration(cfg.Timeout, 5*time.Second)
	client := memcache.New(addr)
	client.Timeout = timeout

	return &memcacheCache{client: client, prefix: prefix, defaultTTL: defaultTTL}, nil
}

func (m *memcacheCache) key(k string) string { return m.prefix + k }

func (m *memcacheCache) Get(_ context.Context, key string) ([]byte, error) {
	item, err := m.client.Get(m.key(key))
	if err == memcache.ErrCacheMiss {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("cache: memcache get %q: %w", key, err)
	}
	return item.Value, nil
}

// maxRelativeTTL is the memcached protocol threshold (30 days, in seconds)
// below which the Expiration field is interpreted as a relative number of
// seconds from now, and above which it is interpreted as an absolute Unix
// timestamp. A TTL longer than this must be converted to an absolute
// timestamp, or memcached reads it as a timestamp far in the past and the
// item expires immediately.
const maxRelativeTTL = 30 * 24 * time.Hour

func (m *memcacheCache) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = m.defaultTTL
	}
	var expSecs int32
	if ttl > maxRelativeTTL {
		expSecs = int32(time.Now().Add(ttl).Unix())
	} else {
		expSecs = int32(ttl.Seconds())
		if expSecs <= 0 {
			expSecs = 3600
		}
	}
	if err := m.client.Set(&memcache.Item{Key: m.key(key), Value: value, Expiration: expSecs}); err != nil {
		return fmt.Errorf("cache: memcache set %q: %w", key, err)
	}
	return nil
}

func (m *memcacheCache) Delete(_ context.Context, key string) error {
	err := m.client.Delete(m.key(key))
	if err == memcache.ErrCacheMiss {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cache: memcache delete %q: %w", key, err)
	}
	return nil
}

func (m *memcacheCache) Flush(_ context.Context) error {
	if err := m.client.FlushAll(); err != nil {
		return fmt.Errorf("cache: memcache flushall: %w", err)
	}
	return nil
}

// Ping verifies connectivity by issuing a Get for a sentinel key. gomemcache
// has no dedicated ping RPC; ErrCacheMiss still proves the server was reached.
func (m *memcacheCache) Ping(_ context.Context) error {
	_, err := m.client.Get(m.key("__ping__"))
	if err != nil && err != memcache.ErrCacheMiss {
		return fmt.Errorf("cache: memcache ping: %w", err)
	}
	return nil
}

func (m *memcacheCache) Close() error { return nil }
