package gobetterauth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/GoBetterAuth/go-better-auth/domain"
	"github.com/GoBetterAuth/go-better-auth/infrastructure/migration"
	gormrepo "github.com/GoBetterAuth/go-better-auth/repository/gorm"
)

// setupTestDatabase runs migrations on a temporary SQLite database and returns the connection string and cleanup function
func setupTestDatabase(t *testing.T) (string, func()) {
	t.Helper()

	// Create a temporary database file
	tmpFile, err := os.CreateTemp("", fmt.Sprintf("test_db_%d_*.db", time.Now().UnixNano()))
	if err != nil {
		t.Fatalf("failed to create temporary database file: %v", err)
	}
	dbPath := tmpFile.Name()
	tmpFile.Close() // Close the file so SQLite can use it

	cleanup := func() {
		os.Remove(dbPath)
	}

	// Create repositories to get database connection
	gormCfg := &gormrepo.Config{
		Provider:         "sqlite",
		ConnectionString: dbPath,
		LogQueries:       false,
	}

	repos, err := gormrepo.NewRepositories(gormCfg)
	if err != nil {
		cleanup()
		t.Fatalf("failed to create repositories: %v", err)
	}

	// Run migrations
	err = migration.RunTestMigrations(repos.DB, "sqlite")
	if err != nil {
		repos.Close()
		cleanup()
		t.Fatalf("failed to run test migrations: %v", err)
	}

	// Close repositories - the Auth instance will create its own connection
	repos.Close()

	return dbPath, cleanup
}

// createTestAuth creates an Auth instance with a pre-migrated database
func createTestAuth(t *testing.T) (*Auth, func()) {
	t.Helper()

	dbPath, cleanup := setupTestDatabase(t)

	config := &domain.Config{
		BaseURL: "http://localhost:8080",
		Secret:  "very-secret-key-that-is-long-enough",
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: dbPath,
		},
	}

	auth, err := New(config)
	if err != nil {
		cleanup()
		t.Fatalf("failed to create auth instance: %v", err)
	}

	return auth, cleanup
}

func TestNew_ValidConfig(t *testing.T) {
	auth, cleanup := createTestAuth(t)
	defer cleanup()

	assert.NotNil(t, auth)
	assert.NotNil(t, auth.Config())
	assert.NotNil(t, auth.SecretGenerator())
	assert.NotNil(t, auth.PasswordHasher())
	assert.NotNil(t, auth.CipherManager())
}

func TestNew_NilConfig(t *testing.T) {
	auth, err := New(nil)
	assert.Error(t, err)
	assert.Nil(t, auth)
}

func TestNew_InvalidConfig(t *testing.T) {
	config := &domain.Config{
		// Missing required fields
	}

	auth, err := New(config)
	assert.Error(t, err)
	assert.Nil(t, auth)
}

func TestNew_AppliesDefaults(t *testing.T) {
	config := &domain.Config{
		Secret: "very-secret-key-that-is-long-enough",
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
	}

	auth, err := New(config)
	if err != nil {
		t.Skip("sqlite adapter not available:", err)
	}
	require.NotNil(t, auth)

	// Check that defaults were applied
	assert.NotEmpty(t, auth.Config().BaseURL)
	assert.NotEmpty(t, auth.Config().BasePath)
}

func TestAuth_PasswordHashing(t *testing.T) {
	config := &domain.Config{
		BaseURL: "http://localhost:8080",
		Secret:  "very-secret-key-that-is-long-enough",
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
	}

	auth, err := New(config)
	if err != nil {
		t.Skip("sqlite adapter not available:", err)
	}

	password := "my-secure-password"
	hasher := auth.PasswordHasher()

	// Hash password
	hash, err := hasher.Hash(password)
	assert.NoError(t, err)
	assert.NotEmpty(t, hash)

	// Verify password
	verified, err := hasher.Verify(password, hash)
	assert.NoError(t, err)
	assert.True(t, verified)
}

func TestAuth_SecretGeneration(t *testing.T) {
	config := &domain.Config{
		BaseURL: "http://localhost:8080",
		Secret:  "very-secret-key-that-is-long-enough",
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
	}

	auth, err := New(config)
	if err != nil {
		t.Skip("sqlite adapter not available:", err)
	}

	generator := auth.SecretGenerator()

	// Generate secret
	secret, err := generator.GenerateSecretDefault()
	assert.NoError(t, err)
	assert.NotEmpty(t, secret)

	// Validate secret
	err = generator.ValidateSecret(secret)
	assert.NoError(t, err)
}

func TestAuth_Handler(t *testing.T) {
	config := &domain.Config{
		BaseURL: "http://localhost:8080",
		Secret:  "very-secret-key-that-is-long-enough",
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
	}

	auth, err := New(config)
	if err != nil {
		t.Skip("sqlite adapter not available:", err)
	}

	// Get the handler
	handler := auth.Handler()
	assert.NotNil(t, handler)

	// Test that it implements http.Handler
	var _ http.Handler = handler

	// Test basic HTTP request
	req := httptest.NewRequest("GET", "/auth/validate", nil)
	w := httptest.NewRecorder()

	// Handler should respond (even if 401 since no session token)
	handler.ServeHTTP(w, req)
	assert.NotZero(t, w.Code)
}

func TestAuth_HandlerWithStdlibMux(t *testing.T) {
	config := &domain.Config{
		BaseURL: "http://localhost:8080",
		Secret:  "very-secret-key-that-is-long-enough",
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
	}

	auth, err := New(config)
	if err != nil {
		t.Skip("sqlite adapter not available:", err)
	}

	// Test that handler can be mounted on stdlib mux
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", auth.Handler())

	// Make a test request
	req := httptest.NewRequest("GET", "/api/auth/me", nil)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)
	assert.NotZero(t, w.Code)
}

func TestAuth_AuthMiddleware_Returns(t *testing.T) {
	config := &domain.Config{
		BaseURL: "http://localhost:8080",
		Secret:  "very-secret-key-that-is-long-enough",
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
	}

	auth, err := New(config)
	if err != nil {
		t.Skip("sqlite adapter not available:", err)
	}

	// Test that AuthMiddleware returns a valid middleware
	middleware := auth.AuthMiddleware()
	assert.NotNil(t, middleware)
	assert.NotNil(t, middleware.Handler)
	assert.NotNil(t, middleware.HandlerFunc)
}

func TestAuth_AuthMiddlewareWithCookie_Returns(t *testing.T) {
	config := &domain.Config{
		BaseURL: "http://localhost:8080",
		Secret:  "very-secret-key-that-is-long-enough",
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
	}

	auth, err := New(config)
	if err != nil {
		t.Skip("sqlite adapter not available:", err)
	}

	// Test that AuthMiddlewareWithCookie returns a valid middleware with custom cookie name
	middleware := auth.AuthMiddlewareWithCookie("custom_session")
	assert.NotNil(t, middleware)
	assert.NotNil(t, middleware.Handler)
	assert.NotNil(t, middleware.HandlerFunc)
}

func TestAuth_OptionalAuthMiddleware_Returns(t *testing.T) {
	config := &domain.Config{
		BaseURL: "http://localhost:8080",
		Secret:  "very-secret-key-that-is-long-enough",
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
	}

	auth, err := New(config)
	if err != nil {
		t.Skip("sqlite adapter not available:", err)
	}

	// Test that OptionalAuthMiddleware returns a valid middleware
	middleware := auth.OptionalAuthMiddleware()
	assert.NotNil(t, middleware)
	assert.NotNil(t, middleware.Handler)
	assert.NotNil(t, middleware.HandlerFunc)
}

func TestAuth_OptionalAuthMiddlewareWithCookie_Returns(t *testing.T) {
	config := &domain.Config{
		BaseURL: "http://localhost:8080",
		Secret:  "very-secret-key-that-is-long-enough",
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
	}

	auth, err := New(config)
	if err != nil {
		t.Skip("sqlite adapter not available:", err)
	}

	// Test that OptionalAuthMiddlewareWithCookie returns a valid middleware with custom cookie name
	middleware := auth.OptionalAuthMiddlewareWithCookie("custom_auth")
	assert.NotNil(t, middleware)
	assert.NotNil(t, middleware.Handler)
	assert.NotNil(t, middleware.HandlerFunc)
}

func TestAuth_MiddlewareChaining(t *testing.T) {
	config := &domain.Config{
		BaseURL: "http://localhost:8080",
		Secret:  "very-secret-key-that-is-long-enough",
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
	}

	auth, err := New(config)
	if err != nil {
		t.Skip("sqlite adapter not available:", err)
	}

	// Test that middleware can be chained with handlers
	authMW := auth.AuthMiddleware()
	optionalMW := auth.OptionalAuthMiddleware()

	// Create test handlers
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Chain middlewares - should not panic
	chainedHandler := authMW.Handler(optionalMW.Handler(testHandler))
	assert.NotNil(t, chainedHandler)

	// Test the chained handler with a test request
	req := httptest.NewRequest("GET", "/api/test", nil)
	w := httptest.NewRecorder()

	// Should return 401 because no token provided and auth middleware requires one
	chainedHandler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuth_MiddlewareWithMux(t *testing.T) {
	config := &domain.Config{
		BaseURL: "http://localhost:8080",
		Secret:  "very-secret-key-that-is-long-enough",
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
	}

	auth, err := New(config)
	if err != nil {
		t.Skip("sqlite adapter not available:", err)
	}

	// Test that middleware works with stdlib mux
	mux := http.NewServeMux()

	// Mount auth handler
	mux.Handle("/api/auth/", auth.Handler())

	// Mount protected endpoint
	mux.Handle("/api/protected", auth.AuthMiddleware().Handler(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("protected"))
		}),
	))

	// Mount public endpoint with optional auth
	mux.Handle("/api/public", auth.OptionalAuthMiddleware().Handler(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("public"))
		}),
	))

	// Test protected endpoint without token - should fail
	req := httptest.NewRequest("GET", "/api/protected", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Test public endpoint without token - should succeed
	req = httptest.NewRequest("GET", "/api/public", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "public", w.Body.String())
}
