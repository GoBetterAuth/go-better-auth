package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/GoBetterAuth/go-better-auth/storage"
)

func TestLimiter_Check_AllowsRequests(t *testing.T) {
	secondary := storage.NewInMemorySecondaryStorage()
	limiter := NewLimiter(secondary)
	ctx := context.Background()

	key := "test-key"
	window := 10 // 10 seconds
	max := 5     // 5 requests

	// First request should be allowed
	remaining, allowed, err := limiter.Check(ctx, key, window, max)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !allowed {
		t.Error("expected request to be allowed")
	}
	if remaining != 4 {
		t.Errorf("expected remaining 4, got %d", remaining)
	}

	// Make more requests up to the limit
	for i := 0; i < 4; i++ {
		remaining, allowed, err := limiter.Check(ctx, key, window, max)
		if err != nil {
			t.Fatalf("expected no error on request %d, got %v", i+2, err)
		}
		if !allowed {
			t.Errorf("expected request %d to be allowed", i+2)
		}
		expectedRemaining := 3 - i
		if remaining != expectedRemaining {
			t.Errorf("expected remaining %d on request %d, got %d", expectedRemaining, i+2, remaining)
		}
	}
}

func TestLimiter_Check_BlocksExcessRequests(t *testing.T) {
	secondary := storage.NewInMemorySecondaryStorage()
	limiter := NewLimiter(secondary)
	ctx := context.Background()

	key := "test-key"
	window := 10 // 10 seconds
	max := 3     // 3 requests

	// Make requests up to the limit
	for i := 0; i < max; i++ {
		_, allowed, err := limiter.Check(ctx, key, window, max)
		if err != nil {
			t.Fatalf("expected no error on request %d, got %v", i+1, err)
		}
		if !allowed {
			t.Errorf("expected request %d to be allowed", i+1)
		}
	}

	// Next request should be blocked
	remaining, allowed, err := limiter.Check(ctx, key, window, max)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if allowed {
		t.Error("expected request to be blocked")
	}
	if remaining != 0 {
		t.Errorf("expected remaining 0, got %d", remaining)
	}
}

func TestLimiter_Check_ResetAfterWindow(t *testing.T) {
	secondary := storage.NewInMemorySecondaryStorage()
	limiter := NewLimiter(secondary)
	ctx := context.Background()

	key := "test-key"
	window := 1 // 1 second
	max := 2    // 2 requests

	// Make requests up to the limit
	for i := 0; i < max; i++ {
		_, allowed, err := limiter.Check(ctx, key, window, max)
		if err != nil {
			t.Fatalf("expected no error on request %d, got %v", i+1, err)
		}
		if !allowed {
			t.Errorf("expected request %d to be allowed", i+1)
		}
	}

	// Next request should be blocked
	_, allowed, err := limiter.Check(ctx, key, window, max)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if allowed {
		t.Error("expected request to be blocked before window expires")
	}

	// Wait for window to expire
	time.Sleep(1100 * time.Millisecond)

	// Request should be allowed after window expires
	remaining, allowed, err := limiter.Check(ctx, key, window, max)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !allowed {
		t.Error("expected request to be allowed after window expires")
	}
	if remaining != 1 {
		t.Errorf("expected remaining 1, got %d", remaining)
	}
}

func TestLimiter_Reset(t *testing.T) {
	secondary := storage.NewInMemorySecondaryStorage()
	limiter := NewLimiter(secondary)
	ctx := context.Background()

	key := "test-key"
	window := 10
	max := 2

	// Make requests up to the limit
	for i := 0; i < max; i++ {
		_, allowed, err := limiter.Check(ctx, key, window, max)
		if err != nil {
			t.Fatalf("expected no error on request %d, got %v", i+1, err)
		}
		if !allowed {
			t.Errorf("expected request %d to be allowed", i+1)
		}
	}

	// Next request should be blocked
	_, allowed, err := limiter.Check(ctx, key, window, max)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if allowed {
		t.Error("expected request to be blocked")
	}

	// Reset the counter
	if err := limiter.Reset(ctx, key); err != nil {
		t.Fatalf("failed to reset: %v", err)
	}

	// Request should be allowed after reset
	remaining, allowed, err := limiter.Check(ctx, key, window, max)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !allowed {
		t.Error("expected request to be allowed after reset")
	}
	if remaining != 1 {
		t.Errorf("expected remaining 1, got %d", remaining)
	}
}

func TestLimiter_GetCount(t *testing.T) {
	secondary := storage.NewInMemorySecondaryStorage()
	limiter := NewLimiter(secondary)
	ctx := context.Background()

	key := "test-key"
	window := 10
	max := 5

	// Initial count should be 0
	count, err := limiter.GetCount(ctx, key)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != 0 {
		t.Errorf("expected count 0, got %d", count)
	}

	// Make 3 requests
	for i := 0; i < 3; i++ {
		_, _, err := limiter.Check(ctx, key, window, max)
		if err != nil {
			t.Fatalf("expected no error on request %d, got %v", i+1, err)
		}
	}

	// Count should be 3
	count, err = limiter.GetCount(ctx, key)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != 3 {
		t.Errorf("expected count 3, got %d", count)
	}
}

func TestGenerateKeyWithWindow(t *testing.T) {
	ip := "192.168.1.1"
	path := "/api/auth/signin"
	window := 10

	// Generate keys at different times in the same window
	key1 := GenerateKeyWithWindow(ip, path, window)
	time.Sleep(100 * time.Millisecond)
	key2 := GenerateKeyWithWindow(ip, path, window)

	// Should be the same key within the same window
	if key1 != key2 {
		t.Errorf("expected keys to be the same within window, got %s and %s", key1, key2)
	}

	// Generate key in different window (simulate by using a much larger window)
	// This is a simplistic test - in reality would need to wait for actual window to pass
	key3 := GenerateKeyWithWindow(ip, path, 1)
	time.Sleep(1100 * time.Millisecond)
	key4 := GenerateKeyWithWindow(ip, path, 1)

	// Should be different keys in different windows
	if key3 == key4 {
		t.Errorf("expected keys to be different in different windows, got %s and %s", key3, key4)
	}
}

func TestLimiter_CheckWithAlgorithm_FixedWindow(t *testing.T) {
	secondary := storage.NewInMemorySecondaryStorage()
	limiter := NewLimiter(secondary)
	ctx := context.Background()

	key := "test-key-fixed"
	window := 10
	max := 3

	// Test fixed window algorithm
	for i := 0; i < max; i++ {
		remaining, allowed, err := limiter.CheckWithAlgorithm(ctx, key, window, max, "fixed-window")
		if err != nil {
			t.Fatalf("expected no error on request %d, got %v", i+1, err)
		}
		if !allowed {
			t.Errorf("expected request %d to be allowed", i+1)
		}
		expectedRemaining := max - (i + 1)
		if remaining != expectedRemaining {
			t.Errorf("expected remaining %d on request %d, got %d", expectedRemaining, i+1, remaining)
		}
	}

	// Next request should be blocked
	_, allowed, err := limiter.CheckWithAlgorithm(ctx, key, window, max, "fixed-window")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if allowed {
		t.Error("expected request to be blocked")
	}
}

func TestLimiter_CheckWithAlgorithm_SlidingWindow(t *testing.T) {
	secondary := storage.NewInMemorySecondaryStorage()
	limiter := NewLimiter(secondary)
	ctx := context.Background()

	key := "test-key-sliding"
	window := 2 // 2 seconds for faster testing
	max := 5

	// Make 5 requests in the first window (should all be allowed)
	for i := 0; i < max; i++ {
		_, allowed, err := limiter.CheckWithAlgorithm(ctx, key, window, max, "sliding-window")
		if err != nil {
			t.Fatalf("expected no error on request %d, got %v", i+1, err)
		}
		if !allowed {
			t.Errorf("expected request %d to be allowed", i+1)
		}
	}

	// Next request should be blocked in current window
	_, allowed, err := limiter.CheckWithAlgorithm(ctx, key, window, max, "sliding-window")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if allowed {
		t.Error("expected request to be blocked when limit reached")
	}

	// Wait for the window to advance significantly (75% into the next window)
	// This ensures more predictable timing for the sliding window calculation
	time.Sleep(3500 * time.Millisecond) // 1.5 seconds past the window boundary

	// At this point we should be well into the new window:
	// - Previous window contribution should be minimal (~25% or less)
	// - Weighted count: 5 * 0.25 + 0 = 1.25 (casted to 1)
	// - Should have room for 4 more requests (5 - 1 = 4)
	successCount := 0
	for i := 0; i < 4; i++ {
		_, allowed, err := limiter.CheckWithAlgorithm(ctx, key, window, max, "sliding-window")
		if err != nil {
			t.Fatalf("expected no error on mid-window request %d, got %v", i+1, err)
		}
		if allowed {
			successCount++
		} else {
			// Log some debug info if we get blocked unexpectedly
			t.Logf("Request %d was blocked, stopping test", i+1)
			break
		}
	}

	// With more generous timing, we should get at least 2-3 requests through
	if successCount < 2 {
		t.Errorf("expected at least 2 requests to succeed in mid-window, got %d", successCount)
	}
}

func TestLimiter_CheckWithAlgorithm_SlidingWindow_SmoothTransition(t *testing.T) {
	secondary := storage.NewInMemorySecondaryStorage()
	limiter := NewLimiter(secondary)
	ctx := context.Background()

	key := "test-key-smooth"
	window := 2
	max := 4

	// Fill up the first window
	for i := 0; i < max; i++ {
		_, allowed, err := limiter.CheckWithAlgorithm(ctx, key, window, max, "sliding-window")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if !allowed {
			t.Fatalf("expected request %d to be allowed in first window", i+1)
		}
	}

	// Next request should be blocked
	_, allowed, err := limiter.CheckWithAlgorithm(ctx, key, window, max, "sliding-window")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if allowed {
		t.Error("expected request to be blocked at end of first window")
	}

	// Wait longer to ensure we're well into the next window
	// This also helps previous window weight to decrease significantly
	time.Sleep(3 * time.Second)

	// After 3 seconds (1.5 windows):
	// - We're now 1 second into the new window (50% through)
	// - Previous window weight: 4 * 0.5 = 2.0
	// - Current window: 0
	// - Weighted: 2.0 + 0 = 2.0
	// - Should have room for 2 more requests
	remaining, allowed, err := limiter.CheckWithAlgorithm(ctx, key, window, max, "sliding-window")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !allowed {
		t.Error("expected request to be allowed after window transition")
	}
	if remaining < 1 {
		t.Errorf("expected at least 1 remaining after window transition, got %d", remaining)
	}
}

func TestLimiter_CheckWithAlgorithm_InvalidAlgorithm(t *testing.T) {
	secondary := storage.NewInMemorySecondaryStorage()
	limiter := NewLimiter(secondary)
	ctx := context.Background()

	key := "test-key-invalid"
	window := 10
	max := 5

	_, _, err := limiter.CheckWithAlgorithm(ctx, key, window, max, "invalid-algorithm")
	if err == nil {
		t.Error("expected error for invalid algorithm")
	}
}

func TestLimiter_CheckWithAlgorithm_EmptyAlgorithm(t *testing.T) {
	secondary := storage.NewInMemorySecondaryStorage()
	limiter := NewLimiter(secondary)
	ctx := context.Background()

	key := "test-key-empty"
	window := 10
	max := 3

	// Empty algorithm should default to fixed-window
	for i := 0; i < max; i++ {
		_, allowed, err := limiter.CheckWithAlgorithm(ctx, key, window, max, "")
		if err != nil {
			t.Fatalf("expected no error with empty algorithm, got %v", err)
		}
		if !allowed {
			t.Errorf("expected request %d to be allowed", i+1)
		}
	}

	// Next request should be blocked
	_, allowed, err := limiter.CheckWithAlgorithm(ctx, key, window, max, "")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if allowed {
		t.Error("expected request to be blocked")
	}
}

func TestLimiter_SlidingWindow_WindowBoundary(t *testing.T) {
	secondary := storage.NewInMemorySecondaryStorage()
	limiter := NewLimiter(secondary)
	ctx := context.Background()

	key := "test-key-boundary"
	window := 2 // 2 second window for more stable testing
	max := 3

	// Make requests at the start of a window
	for i := 0; i < max; i++ {
		_, allowed, err := limiter.CheckWithAlgorithm(ctx, key, window, max, "sliding-window")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if !allowed {
			t.Fatalf("expected request %d to be allowed", i+1)
		}
	}

	// Wait for 3 seconds to move well into next window (1 second past transition)
	// This gives more margin for timing variations
	time.Sleep(3 * time.Second)

	// Now well into next window (1s elapsed in 2s window = 50%):
	// - Previous window: 3 requests
	// - Current window: 0 requests
	// - Weighted count: 3 * 0.5 + 0 = 1.5 (casted to 1)
	// We should have room for 2 more requests (3 - 1 = 2)
	remaining, allowed, err := limiter.CheckWithAlgorithm(ctx, key, window, max, "sliding-window")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !allowed {
		t.Error("expected at least one request to be allowed at window boundary")
	}
	if remaining < 1 {
		t.Errorf("expected at least 1 remaining count, got %d", remaining)
	}
}
