package cache

import (
	"context"
	"testing"
	"time"

	"github.com/apimgr/ipgaze/src/config"
)

// unreachablePort is a port unlikely to have a listener, used to force
// connection-refused errors so backend error-wrapping paths are exercised
// without requiring a real Redis/Memcache server in CI.
const unreachablePort = 1

// ---------------------------------------------------------------------------
// redisCache
// ---------------------------------------------------------------------------

func newTestRedisCache(t *testing.T) Cache {
	t.Helper()
	c, err := newRedisCache(config.CacheConfig{
		Host:    "127.0.0.1",
		Port:    unreachablePort,
		Timeout: "50ms",
	}, "test:", time.Minute)
	if err != nil {
		t.Fatalf("newRedisCache() error: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestNewRedisCache_URLParseError(t *testing.T) {
	_, err := newRedisCache(config.CacheConfig{URL: "://bad-url"}, "test:", time.Minute)
	if err == nil {
		t.Error("newRedisCache() with malformed URL: want error, got nil")
	}
}

func TestNewRedisCache_DefaultHostPort(t *testing.T) {
	c, err := newRedisCache(config.CacheConfig{}, "test:", time.Minute)
	if err != nil {
		t.Fatalf("newRedisCache() error: %v", err)
	}
	defer c.Close()
}

func TestNewRedisCache_TLSEnabled(t *testing.T) {
	c, err := newRedisCache(config.CacheConfig{
		Host: "127.0.0.1",
		Port: unreachablePort,
		TLS:  true,
	}, "test:", time.Minute)
	if err != nil {
		t.Fatalf("newRedisCache() error: %v", err)
	}
	defer c.Close()
}

func TestRedisCache_GetConnectionError(t *testing.T) {
	c := newTestRedisCache(t)
	if _, err := c.Get(context.Background(), "k"); err == nil {
		t.Error("Get() against unreachable redis: want error, got nil")
	}
}

func TestRedisCache_SetConnectionError(t *testing.T) {
	c := newTestRedisCache(t)
	if err := c.Set(context.Background(), "k", []byte("v"), 0); err == nil {
		t.Error("Set() against unreachable redis: want error, got nil")
	}
}

func TestRedisCache_DeleteConnectionError(t *testing.T) {
	c := newTestRedisCache(t)
	if err := c.Delete(context.Background(), "k"); err == nil {
		t.Error("Delete() against unreachable redis: want error, got nil")
	}
}

func TestRedisCache_FlushConnectionError(t *testing.T) {
	c := newTestRedisCache(t)
	if err := c.Flush(context.Background()); err == nil {
		t.Error("Flush() against unreachable redis: want error, got nil")
	}
}

func TestRedisCache_PingConnectionError(t *testing.T) {
	c := newTestRedisCache(t)
	if err := c.Ping(context.Background()); err == nil {
		t.Error("Ping() against unreachable redis: want error, got nil")
	}
}

func TestRedisCache_Close(t *testing.T) {
	c, err := newRedisCache(config.CacheConfig{Host: "127.0.0.1", Port: unreachablePort}, "test:", time.Minute)
	if err != nil {
		t.Fatalf("newRedisCache() error: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close() error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// memcacheCache
// ---------------------------------------------------------------------------

func newTestMemcacheCache(t *testing.T) Cache {
	t.Helper()
	c, err := newMemcacheCache(config.CacheConfig{
		Host:    "127.0.0.1",
		Port:    unreachablePort,
		Timeout: "50ms",
	}, "test:", time.Minute)
	if err != nil {
		t.Fatalf("newMemcacheCache() error: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestNewMemcacheCache_DefaultHostPort(t *testing.T) {
	c, err := newMemcacheCache(config.CacheConfig{}, "test:", time.Minute)
	if err != nil {
		t.Fatalf("newMemcacheCache() error: %v", err)
	}
	defer c.Close()
}

func TestNewMemcacheCache_URLTakesPrecedence(t *testing.T) {
	c, err := newMemcacheCache(config.CacheConfig{URL: "127.0.0.1:1"}, "test:", time.Minute)
	if err != nil {
		t.Fatalf("newMemcacheCache() error: %v", err)
	}
	defer c.Close()
}

func TestMemcacheCache_GetConnectionError(t *testing.T) {
	c := newTestMemcacheCache(t)
	if _, err := c.Get(context.Background(), "k"); err == nil {
		t.Error("Get() against unreachable memcache: want error, got nil")
	}
}

func TestMemcacheCache_SetConnectionError(t *testing.T) {
	c := newTestMemcacheCache(t)
	if err := c.Set(context.Background(), "k", []byte("v"), 0); err == nil {
		t.Error("Set() against unreachable memcache: want error, got nil")
	}
}

func TestMemcacheCache_SetZeroTTLUsesFallbackExpiration(t *testing.T) {
	c := newTestMemcacheCache(t)
	// defaultTTL of the test cache is time.Minute, so this exercises the
	// ttl<=0 -> defaultTTL branch as well as the connection-error path.
	if err := c.Set(context.Background(), "k", []byte("v"), -1); err == nil {
		t.Error("Set() against unreachable memcache: want error, got nil")
	}
}

func TestMemcacheCache_DeleteConnectionError(t *testing.T) {
	c := newTestMemcacheCache(t)
	if err := c.Delete(context.Background(), "k"); err == nil {
		t.Error("Delete() against unreachable memcache: want error, got nil")
	}
}

func TestMemcacheCache_FlushConnectionError(t *testing.T) {
	c := newTestMemcacheCache(t)
	if err := c.Flush(context.Background()); err == nil {
		t.Error("Flush() against unreachable memcache: want error, got nil")
	}
}

func TestMemcacheCache_PingConnectionError(t *testing.T) {
	c := newTestMemcacheCache(t)
	if err := c.Ping(context.Background()); err == nil {
		t.Error("Ping() against unreachable memcache: want error, got nil")
	}
}

func TestMemcacheCache_Close(t *testing.T) {
	c, err := newMemcacheCache(config.CacheConfig{Host: "127.0.0.1", Port: unreachablePort}, "test:", time.Minute)
	if err != nil {
		t.Fatalf("newMemcacheCache() error: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close() error: %v", err)
	}
}
