package cache

import (
	"context"
	"testing"
	"time"

	"github.com/apimgr/ipgaze/src/config"
)

// --- parseDuration ---

func TestParseDuration_ValidString(t *testing.T) {
	d := parseDuration("5m", time.Hour)
	if d != 5*time.Minute {
		t.Errorf("parseDuration(\"5m\") = %v; want 5m", d)
	}
}

func TestParseDuration_EmptyFallback(t *testing.T) {
	d := parseDuration("", time.Hour)
	if d != time.Hour {
		t.Errorf("parseDuration(\"\") = %v; want 1h", d)
	}
}

func TestParseDuration_InvalidFallback(t *testing.T) {
	d := parseDuration("notaduration", 30*time.Second)
	if d != 30*time.Second {
		t.Errorf("parseDuration(invalid) = %v; want 30s", d)
	}
}

func TestParseDuration_NegativeFallback(t *testing.T) {
	d := parseDuration("-1s", time.Minute)
	if d != time.Minute {
		t.Errorf("parseDuration(-1s) = %v; want 1m", d)
	}
}

// --- Key helper ---

func TestKey_WithPrefix(t *testing.T) {
	got := Key("ipgaze:", "session", "abc123")
	want := "ipgaze:session:abc123"
	if got != want {
		t.Errorf("Key() = %q; want %q", got, want)
	}
}

func TestKey_NoPrefix(t *testing.T) {
	got := Key("", "session", "abc123")
	want := "session:abc123"
	if got != want {
		t.Errorf("Key(no prefix) = %q; want %q", got, want)
	}
}

// --- New factory ---

func TestNew_EmptyType_UsesMemory(t *testing.T) {
	c, err := New(config.CacheConfig{})
	if err != nil {
		t.Fatalf("New(empty) error: %v", err)
	}
	defer c.Close()
	if _, ok := c.(*memoryCache); !ok {
		t.Errorf("New(empty) type = %T; want *memoryCache", c)
	}
}

func TestNew_TypeMemory(t *testing.T) {
	c, err := New(config.CacheConfig{Type: "memory"})
	if err != nil {
		t.Fatalf("New(memory) error: %v", err)
	}
	defer c.Close()
	if _, ok := c.(*memoryCache); !ok {
		t.Errorf("New(memory) type = %T; want *memoryCache", c)
	}
}

func TestNew_TypeNone(t *testing.T) {
	c, err := New(config.CacheConfig{Type: "none"})
	if err != nil {
		t.Fatalf("New(none) error: %v", err)
	}
	defer c.Close()
	if _, ok := c.(*noopCache); !ok {
		t.Errorf("New(none) type = %T; want *noopCache", c)
	}
}

func TestNew_TypeRedis_ReturnsClient(t *testing.T) {
	c, err := New(config.CacheConfig{Type: "redis", Host: "localhost", Port: 6379})
	if err != nil {
		t.Fatalf("New(redis) error: %v", err)
	}
	defer c.Close()
	if _, ok := c.(*redisCache); !ok {
		t.Errorf("New(redis) type = %T; want *redisCache", c)
	}
}

func TestNew_TypeValkey_ReturnsRedisClient(t *testing.T) {
	c, err := New(config.CacheConfig{Type: "valkey", Host: "localhost", Port: 6379})
	if err != nil {
		t.Fatalf("New(valkey) error: %v", err)
	}
	defer c.Close()
	if _, ok := c.(*redisCache); !ok {
		t.Errorf("New(valkey) type = %T; want *redisCache", c)
	}
}

func TestNew_TypeMemcache_ReturnsClient(t *testing.T) {
	c, err := New(config.CacheConfig{Type: "memcache", Host: "localhost", Port: 11211})
	if err != nil {
		t.Fatalf("New(memcache) error: %v", err)
	}
	defer c.Close()
	if _, ok := c.(*memcacheCache); !ok {
		t.Errorf("New(memcache) type = %T; want *memcacheCache", c)
	}
}

func TestNew_InvalidRedisURL_ReturnsError(t *testing.T) {
	_, err := New(config.CacheConfig{Type: "redis", URL: "://bad-url"})
	if err == nil {
		t.Error("New(redis, bad URL) expected error, got nil")
	}
}

// --- noop backend ---

func TestNoopCache_GetAlwaysNotFound(t *testing.T) {
	c := newNoopCache()
	_, err := c.Get(context.Background(), "key")
	if err != ErrNotFound {
		t.Errorf("noop Get = %v; want ErrNotFound", err)
	}
}

func TestNoopCache_SetNeverErrors(t *testing.T) {
	c := newNoopCache()
	if err := c.Set(context.Background(), "k", []byte("v"), time.Second); err != nil {
		t.Errorf("noop Set error: %v", err)
	}
}

func TestNoopCache_DeleteNeverErrors(t *testing.T) {
	c := newNoopCache()
	if err := c.Delete(context.Background(), "k"); err != nil {
		t.Errorf("noop Delete error: %v", err)
	}
}

func TestNoopCache_FlushNeverErrors(t *testing.T) {
	c := newNoopCache()
	if err := c.Flush(context.Background()); err != nil {
		t.Errorf("noop Flush error: %v", err)
	}
}

func TestNoopCache_PingNeverErrors(t *testing.T) {
	c := newNoopCache()
	if err := c.Ping(context.Background()); err != nil {
		t.Errorf("noop Ping error: %v", err)
	}
}

// --- memory backend ---

func TestMemoryCache_SetAndGet(t *testing.T) {
	c := newMemoryCache("", time.Hour)
	ctx := context.Background()
	if err := c.Set(ctx, "hello", []byte("world"), 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := c.Get(ctx, "hello")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "world" {
		t.Errorf("Get = %q; want %q", got, "world")
	}
}

func TestMemoryCache_GetMissing_ReturnsNotFound(t *testing.T) {
	c := newMemoryCache("", time.Hour)
	_, err := c.Get(context.Background(), "no-such-key")
	if err != ErrNotFound {
		t.Errorf("Get missing = %v; want ErrNotFound", err)
	}
}

func TestMemoryCache_Expiry(t *testing.T) {
	c := newMemoryCache("", time.Hour)
	ctx := context.Background()
	if err := c.Set(ctx, "exp", []byte("val"), 1*time.Millisecond); err != nil {
		t.Fatalf("Set: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	_, err := c.Get(ctx, "exp")
	if err != ErrNotFound {
		t.Errorf("expired key Get = %v; want ErrNotFound", err)
	}
}

func TestMemoryCache_Delete(t *testing.T) {
	c := newMemoryCache("", time.Hour)
	ctx := context.Background()
	c.Set(ctx, "k", []byte("v"), 0) //nolint:errcheck
	if err := c.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err := c.Get(ctx, "k")
	if err != ErrNotFound {
		t.Errorf("after Delete, Get = %v; want ErrNotFound", err)
	}
}

func TestMemoryCache_Flush(t *testing.T) {
	c := newMemoryCache("", time.Hour)
	ctx := context.Background()
	c.Set(ctx, "a", []byte("1"), 0) //nolint:errcheck
	c.Set(ctx, "b", []byte("2"), 0) //nolint:errcheck
	if err := c.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	for _, k := range []string{"a", "b"} {
		if _, err := c.Get(ctx, k); err != ErrNotFound {
			t.Errorf("after Flush, Get(%q) = %v; want ErrNotFound", k, err)
		}
	}
}

func TestMemoryCache_Prefix(t *testing.T) {
	c := newMemoryCache("pfx:", time.Hour)
	ctx := context.Background()
	c.Set(ctx, "key", []byte("val"), 0) //nolint:errcheck
	// Direct access via internal map: the stored key should carry the prefix.
	mc := c.(*memoryCache)
	mc.mu.RLock()
	_, ok := mc.entries["pfx:key"]
	mc.mu.RUnlock()
	if !ok {
		t.Error("expected entry under prefixed key \"pfx:key\"")
	}
}

func TestMemoryCache_PingNeverErrors(t *testing.T) {
	c := newMemoryCache("", time.Hour)
	if err := c.Ping(context.Background()); err != nil {
		t.Errorf("memory Ping error: %v", err)
	}
}

func TestMemoryCache_ValueIsolation(t *testing.T) {
	// Verify that Set and Get return independent copies (no aliasing).
	c := newMemoryCache("", time.Hour)
	ctx := context.Background()
	original := []byte("data")
	c.Set(ctx, "k", original, 0) //nolint:errcheck
	original[0] = 'X'            // mutate original after Set

	got, _ := c.Get(ctx, "k")
	if string(got) != "data" {
		t.Errorf("value aliasing: Get = %q; want %q", got, "data")
	}

	// Mutate returned slice; second Get must still return original.
	got[0] = 'Z'
	got2, _ := c.Get(ctx, "k")
	if string(got2) != "data" {
		t.Errorf("return aliasing: Get2 = %q; want %q", got2, "data")
	}
}

func TestMemoryCache_Close(t *testing.T) {
	c := newMemoryCache("", time.Hour)
	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestMemoryCache_DeleteMissing_NoError(t *testing.T) {
	c := newMemoryCache("", time.Hour)
	if err := c.Delete(context.Background(), "nope"); err != nil {
		t.Errorf("Delete missing key: %v", err)
	}
}

func TestMemoryCache_ZeroTTL_UsesDefault(t *testing.T) {
	// A 10ms default TTL; setting with ttl=0 must adopt it.
	c := newMemoryCache("", 10*time.Millisecond)
	ctx := context.Background()
	c.Set(ctx, "k", []byte("v"), 0) //nolint:errcheck
	time.Sleep(20 * time.Millisecond)
	_, err := c.Get(ctx, "k")
	if err != ErrNotFound {
		t.Errorf("zero TTL key: Get = %v; want ErrNotFound after expiry", err)
	}
}
