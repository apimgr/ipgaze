package cache

import (
	"context"
	"testing"
	"time"
)

// TestLoggingCache exercises every method of the loggingCache decorator
// (server.debug.log_cache, AI.md PART 6) against an in-memory backend,
// covering both hit and miss paths for each operation.
func TestLoggingCache(t *testing.T) {
	inner := newMemoryCache("test:", time.Minute)
	c := NewLogging(inner)
	ctx := context.Background()

	if err := c.Set(ctx, "k1", []byte("v1"), time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}

	val, err := c.Get(ctx, "k1")
	if err != nil {
		t.Fatalf("Get (hit): %v", err)
	}
	if string(val) != "v1" {
		t.Errorf("Get(k1) = %q, want v1", val)
	}

	if _, err := c.Get(ctx, "missing"); err == nil {
		t.Error("Get (miss) expected error, got nil")
	}

	if err := c.Delete(ctx, "k1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := c.Get(ctx, "k1"); err == nil {
		t.Error("Get after Delete expected miss, got hit")
	}

	if err := c.Set(ctx, "k2", []byte("v2"), time.Minute); err != nil {
		t.Fatalf("Set k2: %v", err)
	}
	if err := c.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if _, err := c.Get(ctx, "k2"); err == nil {
		t.Error("Get after Flush expected miss, got hit")
	}

	if err := c.Ping(ctx); err != nil {
		t.Errorf("Ping: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
