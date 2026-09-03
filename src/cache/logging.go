package cache

import (
	"context"
	"log/slog"
	"time"
)

// loggingCache wraps a Cache backend to log every operation (hits, misses,
// evictions via Delete/Flush) when server.debug.log_cache is enabled per
// AI.md PART 6. Only constructed when both --debug/DEBUG=true and
// server.debug.log_cache are active; otherwise callers use the plain
// backend directly.
type loggingCache struct {
	inner Cache
}

// NewLogging wraps inner so every Get/Set/Delete/Flush operation logs its
// key, hit/miss outcome, and duration via slog.Debug. Callers should only
// use this when server.debug.log_cache is enabled (AI.md PART 6) — the
// wrapper itself performs no gating of its own.
func NewLogging(inner Cache) Cache {
	return &loggingCache{inner: inner}
}

func (l *loggingCache) Get(ctx context.Context, key string) ([]byte, error) {
	start := time.Now()
	val, err := l.inner.Get(ctx, key)
	slog.Debug("cache",
		"operation", "get",
		"key", key,
		"hit", err == nil,
		"duration_us", time.Since(start).Microseconds(),
	)
	return val, err
}

func (l *loggingCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	start := time.Now()
	err := l.inner.Set(ctx, key, value, ttl)
	slog.Debug("cache",
		"operation", "set",
		"key", key,
		"hit", err == nil,
		"duration_us", time.Since(start).Microseconds(),
	)
	return err
}

func (l *loggingCache) Delete(ctx context.Context, key string) error {
	start := time.Now()
	err := l.inner.Delete(ctx, key)
	slog.Debug("cache",
		"operation", "delete",
		"key", key,
		"hit", err == nil,
		"duration_us", time.Since(start).Microseconds(),
	)
	return err
}

func (l *loggingCache) Flush(ctx context.Context) error {
	start := time.Now()
	err := l.inner.Flush(ctx)
	slog.Debug("cache",
		"operation", "flush",
		"hit", err == nil,
		"duration_us", time.Since(start).Microseconds(),
	)
	return err
}

func (l *loggingCache) Ping(ctx context.Context) error { return l.inner.Ping(ctx) }
func (l *loggingCache) Close() error                   { return l.inner.Close() }
