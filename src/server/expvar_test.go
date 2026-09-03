package server

import (
	"expvar"
	"testing"
	"time"
)

// TestExpvarNamesRegistered asserts every name AI.md PART 12 requires on
// /debug/vars is actually published by this package's init.
func TestExpvarNamesRegistered(t *testing.T) {
	required := []string{
		"requests_total",
		"requests_duration_seconds",
		"errors_total",
		"uptime_seconds",
		"goroutines",
		"memory",
	}
	for _, name := range required {
		if expvar.Get(name) == nil {
			t.Errorf("expvar %q: not registered", name)
		}
	}
}

// TestExpvarPublishedFuncsReturnValues asserts the published functions produce
// usable values rather than nil.
func TestExpvarPublishedFuncsReturnValues(t *testing.T) {
	uptime, ok := expvar.Get("uptime_seconds").(expvar.Func)
	if !ok {
		t.Fatal("uptime_seconds: want expvar.Func")
	}
	if secs, ok := uptime().(float64); !ok || secs < 0 {
		t.Errorf("uptime_seconds: got %v, want non-negative float64", uptime())
	}

	goroutines, ok := expvar.Get("goroutines").(expvar.Func)
	if !ok {
		t.Fatal("goroutines: want expvar.Func")
	}
	if n, ok := goroutines().(int); !ok || n < 1 {
		t.Errorf("goroutines: got %v, want int >= 1", goroutines())
	}

	memory, ok := expvar.Get("memory").(expvar.Func)
	if !ok {
		t.Fatal("memory: want expvar.Func")
	}
	stats, ok := memory().(map[string]uint64)
	if !ok {
		t.Fatalf("memory: got %T, want map[string]uint64", memory())
	}
	for _, key := range []string{"alloc", "total_alloc", "sys", "heap_alloc", "heap_sys"} {
		if _, present := stats[key]; !present {
			t.Errorf("memory: missing key %q", key)
		}
	}
}

// TestRecordExpvarRequestMovesCounters asserts a recorded request bumps both the
// request count and the accumulated duration.
func TestRecordExpvarRequestMovesCounters(t *testing.T) {
	beforeCount := expvarRequestCount.Value()
	beforeDuration := expvarRequestDuration.Value()

	recordExpvarRequest(250 * time.Millisecond)

	if got := expvarRequestCount.Value(); got != beforeCount+1 {
		t.Errorf("requests_total: got %d, want %d", got, beforeCount+1)
	}
	if got := expvarRequestDuration.Value(); got <= beforeDuration {
		t.Errorf("requests_duration_seconds: got %v, want > %v", got, beforeDuration)
	}
}

// TestRecordExpvarErrorMovesCounter asserts a recorded error bumps errors_total.
func TestRecordExpvarErrorMovesCounter(t *testing.T) {
	before := expvarErrorCount.Value()

	recordExpvarError()

	if got := expvarErrorCount.Value(); got != before+1 {
		t.Errorf("errors_total: got %d, want %d", got, before+1)
	}
}

// TestRecordExpvarConcurrent asserts the recorders are safe under concurrent use.
func TestRecordExpvarConcurrent(t *testing.T) {
	const goroutines = 50
	const perGoroutine = 20

	beforeRequests := expvarRequestCount.Value()
	beforeErrors := expvarErrorCount.Value()

	done := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func() {
			for j := 0; j < perGoroutine; j++ {
				recordExpvarRequest(time.Millisecond)
				recordExpvarError()
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < goroutines; i++ {
		<-done
	}

	wantDelta := int64(goroutines * perGoroutine)
	if got := expvarRequestCount.Value() - beforeRequests; got != wantDelta {
		t.Errorf("requests_total delta: got %d, want %d", got, wantDelta)
	}
	if got := expvarErrorCount.Value() - beforeErrors; got != wantDelta {
		t.Errorf("errors_total delta: got %d, want %d", got, wantDelta)
	}
}
