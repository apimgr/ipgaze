// Package cache provides a unified caching interface over multiple backends
// (in-process memory, Valkey/Redis, Memcache) as specified in AI.md PART 9.
package cache

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
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

// ErrNotFound is returned by Get when the requested key does not exist.
var ErrNotFound = fmt.Errorf("cache: key not found")

// ApplyEnvOverrides copies CACHE_URL onto cfg in place (AI.md PART 12's
// `url: ${CACHE_URL}` example). CACHE_URL is a Runtime variable: it always
// wins over server.yml's `server.cache.url` when set. When cfg.Type is
// unset, "none", or "memory", it is upgraded to "valkey" so a CACHE_URL
// alone (e.g. the shipped docker-compose.yml valkey sidecar) is enough to
// reach the backend without also requiring `type: valkey` in server.yml.
func ApplyEnvOverrides(cfg *config.CacheConfig) {
	v := os.Getenv("CACHE_URL")
	if v == "" {
		return
	}
	cfg.URL = v
	if cfg.Type == "" || cfg.Type == "none" || cfg.Type == "memory" {
		cfg.Type = "valkey"
	}
}

// New constructs the appropriate Cache backend from cfg.
// Supported types: "none", "memory", "valkey", "redis", "memcache".
// An empty or unrecognised type falls back to the memory backend.
func New(cfg config.CacheConfig) (Cache, error) {
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

	if cfg.URL != "" {
		parsed, err := redis.ParseURL(cfg.URL)
		if err != nil {
			return nil, fmt.Errorf("cache: parse redis URL: %w", err)
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

	if cfg.TLS {
		tlsCfg := &tls.Config{
			InsecureSkipVerify: cfg.TLSSkipVerify, //nolint:gosec
			MinVersion:         tls.VersionTLS12,
		}
		opts.TLSConfig = tlsCfg
	}

	client := redis.NewClient(opts)
	return &redisCache{client: client, prefix: prefix, defaultTTL: defaultTTL}, nil
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
