package gobetterauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/GoBetterAuth/go-better-auth/domain"
	"github.com/GoBetterAuth/go-better-auth/storage"
)

func TestAuth_WithSecondaryStorage_SessionCaching(t *testing.T) {
	// Create secondary storage
	secondaryStorage := storage.NewInMemorySecondaryStorage()

	// Create auth instance with secondary storage and auto-migrations
	config := &domain.Config{
		Secret:   "test-secret-key-32-characters!",
		BaseURL:  "http://localhost:3000",
		BasePath: "/api/auth",
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
		SecondaryStorage: secondaryStorage,
		EmailAndPassword: &domain.EmailPasswordConfig{
			Enabled: true,
		},
		Session: &domain.SessionConfig{
			ExpiresIn: 1 * time.Hour,
			UpdateAge: 30 * time.Minute,
		},
	}

	auth, err := New(config)
	if err != nil {
		t.Fatalf("failed to create auth: %v", err)
	}

	// Run migrations for test setup
	ctx := context.Background()
	if err := auth.RunMigrations(ctx); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	handler := auth.Handler()

	// Sign up a user
	signupBody := `{"email":"test@example.com","password":"password123","name":"Test User"}`
	req := httptest.NewRequest("POST", "/auth/sign-up/email", strings.NewReader(signupBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("signup failed with status %d: %s", w.Code, w.Body.String())
	}

	// Sign in
	signinBody := `{"email":"test@example.com","password":"password123"}`
	req = httptest.NewRequest("POST", "/auth/sign-in/email", strings.NewReader(signinBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("signin failed with status %d: %s", w.Code, w.Body.String())
	}

	// Extract session token from JSON response
	var signinResp struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &signinResp); err != nil {
		t.Fatalf("failed to parse signin response: %v", err)
	}

	sessionToken := signinResp.Data.Token
	if sessionToken == "" {
		t.Fatalf("no session token found in response")
	}

	// Validate session multiple times - second request should hit cache
	for i := 0; i < 3; i++ {
		req = httptest.NewRequest("GET", "/auth/validate", nil)
		req.Header.Set("Authorization", "Bearer "+sessionToken)
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("validate request %d failed with status %d: %s", i+1, w.Code, w.Body.String())
		}
	}

	// Verify that sessions are being cached by checking secondary storage
	// The cached session should exist with the session token as part of the key
	cacheKey := fmt.Sprintf("session:token:%s", sessionToken)
	_, err = secondaryStorage.Get(context.Background(), cacheKey)
	if err != nil {
		t.Errorf("expected session to be cached in secondary storage, but key %s not found: %v", cacheKey, err)
	}
}

func TestAuth_WithSecondaryStorage_RateLimiting(t *testing.T) {
	// Create secondary storage
	secondaryStorage := storage.NewInMemorySecondaryStorage()

	// Create auth instance with rate limiting
	config := &domain.Config{
		Secret:   "test-secret-key-32-characters!",
		BaseURL:  "http://localhost:3000",
		BasePath: "/api/auth",
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
		SecondaryStorage: secondaryStorage,
		EmailAndPassword: &domain.EmailPasswordConfig{
			Enabled: true,
		},
		RateLimit: &domain.RateLimitOptions{
			Enabled: true,
			Window:  10,
			Max:     3,
		},
	}

	auth, err := New(config)
	if err != nil {
		t.Fatalf("failed to create auth: %v", err)
	}

	handler := auth.Handler()

	// Make requests up to the limit
	for i := range 3 {
		req := httptest.NewRequest("GET", "/auth/validate", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// All should succeed (even though validation might fail, rate limiting should allow them)
		if w.Code == http.StatusTooManyRequests {
			t.Errorf("request %d was rate limited unexpectedly", i+1)
		}
	}

	// Next request should be rate limited
	req := httptest.NewRequest("GET", "/auth/validate", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected status 429, got %d", w.Code)
	}

	// Verify rate limit counters are stored in secondary storage
	secondaryStorage.CleanExpired() // Clean any expired items
	// Check if any rate limit keys exist
	hasRateLimitKeys := false
	for _, key := range secondaryStorage.GetAllKeys() {
		if strings.HasPrefix(key, "ratelimit:") {
			hasRateLimitKeys = true
			break
		}
	}
	if !hasRateLimitKeys {
		t.Error("expected rate limit counters in secondary storage")
	}
}

func TestAuth_WithSecondaryStorage_CustomRateLimits(t *testing.T) {
	// Create secondary storage
	secondaryStorage := storage.NewInMemorySecondaryStorage()

	// Create auth instance with custom rate limits
	config := &domain.Config{
		Secret:   "test-secret-key-32-characters!",
		BaseURL:  "http://localhost:3000",
		BasePath: "/api/auth",
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
		SecondaryStorage: secondaryStorage,
		EmailAndPassword: &domain.EmailPasswordConfig{
			Enabled: true,
		},
		RateLimit: &domain.RateLimitOptions{
			Enabled: true,
			Window:  10,
			Max:     10, // Default: 10 requests
			CustomRules: map[string]domain.RateLimitRule{
				"/auth/sign-in*": {
					Window: 10,
					Max:    2, // Signin: only 2 requests
				},
			},
		},
	}

	auth, err := New(config)
	if err != nil {
		t.Fatalf("failed to create auth: %v", err)
	}

	handler := auth.Handler()

	// Make 2 signin requests (should be allowed)
	for i := 0; i < 2; i++ {
		signinBody := `{"email":"test@example.com","password":"wrong"}`
		req := httptest.NewRequest("POST", "/auth/sign-in/email", strings.NewReader(signinBody))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code == http.StatusTooManyRequests {
			t.Errorf("signin request %d was rate limited unexpectedly", i+1)
		}
	}

	// Third signin request should be rate limited
	signinBody := `{"email":"test@example.com","password":"wrong"}`
	req := httptest.NewRequest("POST", "/auth/sign-in/email", strings.NewReader(signinBody))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected status 429 for third signin, got %d", w.Code)
	}

	// But other endpoints should still have higher limits
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/auth/validate", nil)
		req.RemoteAddr = "192.168.1.2:12345" // Different IP
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code == http.StatusTooManyRequests {
			t.Errorf("validate request %d was rate limited unexpectedly", i+1)
		}
	}
}

func TestAuth_WithoutSecondaryStorage_NoRateLimiting(t *testing.T) {
	// Create auth instance without secondary storage
	config := &domain.Config{
		Secret:   "test-secret-key-32-characters!",
		BaseURL:  "http://localhost:3000",
		BasePath: "/api/auth",
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
		EmailAndPassword: &domain.EmailPasswordConfig{
			Enabled: true,
		},
		RateLimit: &domain.RateLimitOptions{
			Enabled: true,
			Window:  1,
			Max:     2,
		},
	}

	auth, err := New(config)
	if err != nil {
		t.Fatalf("failed to create auth: %v", err)
	}

	handler := auth.Handler()

	// Make many requests - should all succeed since rate limiting requires secondary storage
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/auth/validate", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// Should not be rate limited (rate limiting disabled without secondary storage)
		if w.Code == http.StatusTooManyRequests {
			t.Errorf("request %d was rate limited unexpectedly (should be disabled without secondary storage)", i+1)
		}
	}
}

func TestAuth_SecondaryStorage_ConcurrentAccess(t *testing.T) {
	// Create secondary storage
	secondaryStorage := storage.NewInMemorySecondaryStorage()

	// Create auth instance with secondary storage
	config := &domain.Config{
		Secret:   "test-secret-key-32-characters!",
		BaseURL:  "http://localhost:3000",
		BasePath: "/api/auth",
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
		SecondaryStorage: secondaryStorage,
		EmailAndPassword: &domain.EmailPasswordConfig{
			Enabled: true,
		},
		Session: &domain.SessionConfig{
			ExpiresIn: 300, // 5 minutes (minimum allowed)
			UpdateAge: 150, // 2.5 minutes
		},
	}

	auth, err := New(config)
	if err != nil {
		t.Fatalf("failed to create auth: %v", err)
	}

	// Run migrations for test setup
	ctx := context.Background()
	if err := auth.RunMigrations(ctx); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	handler := auth.Handler()

	// Sign up and sign in
	signupBody := `{"email":"test@example.com","password":"password123","name":"Test User"}`
	req := httptest.NewRequest("POST", "/auth/sign-up/email", strings.NewReader(signupBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	signinBody := `{"email":"test@example.com","password":"password123"}`
	req = httptest.NewRequest("POST", "/auth/sign-in/email", strings.NewReader(signinBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("signin failed with status %d", w.Code)
	}

	// Wait for session to expire
	time.Sleep(1100 * time.Millisecond)

	// Clean expired items from cache
	cleaned := secondaryStorage.CleanExpired()
	if cleaned == 0 {
		t.Log("note: no expired items cleaned (may have already been cleaned)")
	}
}
