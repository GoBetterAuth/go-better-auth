package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/GoBetterAuth/go-better-auth/domain"
	"github.com/GoBetterAuth/go-better-auth/repository/gorm"
	gobetterauthtests "github.com/GoBetterAuth/go-better-auth/tests"
	"github.com/GoBetterAuth/go-better-auth/usecase/auth"
)

const (
	authTestsCookieName = "test_session_token"
)

// setupTestRepositories creates GORM repositories with SQLite in-memory database for testing
func setupTestRepositories(t *testing.T) *gorm.Repositories {
	t.Helper()

	cfg := &gorm.Config{
		Provider:         "sqlite",
		ConnectionString: ":memory:",
		LogQueries:       false,
	}

	repos, err := gorm.NewRepositories(cfg)
	require.NoError(t, err, "Failed to create test repositories")

	// Run migrations
	err = gobetterauthtests.RunTestMigrations(t, repos)
	require.NoError(t, err, "Failed to run test migrations")

	// Clean up after test
	t.Cleanup(func() {
		if repos != nil {
			repos.Close()
		}
	})

	return repos
}

// ===== Context Tests =====

func TestGetUserID_Success(t *testing.T) {
	ctx := SetUserID(context.Background(), "user-123")

	userID, err := GetUserID(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "user-123", userID)
}

func TestGetUserID_Missing(t *testing.T) {
	ctx := context.Background()

	userID, err := GetUserID(ctx)
	assert.Empty(t, userID)
	assert.Nil(t, err)
}

func TestGetUserID_Empty(t *testing.T) {
	ctx := SetUserID(context.Background(), "")

	userID, err := GetUserID(ctx)
	assert.Empty(t, userID)
	assert.Error(t, err)
}

func TestMustGetUserID_Success(t *testing.T) {
	ctx := SetUserID(context.Background(), "user-123")

	userID, err := MustGetUserID(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "user-123", userID)
}

func TestMustGetUserID_Error(t *testing.T) {
	ctx := context.Background()

	userID, err := MustGetUserID(ctx)
	assert.Error(t, err)
	assert.Equal(t, "", userID)
	assert.Contains(t, err.Error(), "user ID not found in context")
}

func TestGetSessionToken_Success(t *testing.T) {
	ctx := SetSessionToken(context.Background(), "token-123")

	token, err := GetSessionToken(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "token-123", token)
}

func TestGetSessionToken_Missing(t *testing.T) {
	ctx := context.Background()

	token, err := GetSessionToken(ctx)
	assert.Empty(t, "", token)
	assert.Nil(t, err)
}

// ===== AuthMiddleware Tests =====

func TestAuthMiddleware_ValidBearerToken(t *testing.T) {
	// Setup
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := auth.NewService(
		&domain.Config{},
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	// Create a user and sign in to get a session
	signupResp, err := service.SignUp(context.Background(), &auth.SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	})
	require.NoError(t, err)

	signinResp, err := service.SignIn(context.Background(), &auth.SignInRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
	})
	require.NoError(t, err)

	token := signinResp.Session.Token

	// Create middleware and protected handler
	middleware := NewAuthMiddleware(service, authTestsCookieName)
	protectedHandler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, err := GetUserID(r.Context())
		assert.NoError(t, err)
		assert.Equal(t, signupResp.User.ID, userID)
		w.WriteHeader(http.StatusOK)
	}))

	// Create request with Bearer token
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	protectedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthMiddleware_MissingToken(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := auth.NewService(
		&domain.Config{},
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	middleware := NewAuthMiddleware(service, authTestsCookieName)
	protectedHandler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	protectedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "unauthorized")
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := auth.NewService(
		&domain.Config{},
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	middleware := NewAuthMiddleware(service, authTestsCookieName)
	protectedHandler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")

	w := httptest.NewRecorder()
	protectedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_InvalidBearerFormat(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := auth.NewService(
		&domain.Config{},
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	middleware := NewAuthMiddleware(service, authTestsCookieName)
	protectedHandler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "invalid-format")

	w := httptest.NewRecorder()
	protectedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_CookieToken(t *testing.T) {
	// Setup
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := auth.NewService(
		&domain.Config{},
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	// Create a user and sign in to get a session
	signupResp, err := service.SignUp(context.Background(), &auth.SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	})
	require.NoError(t, err)

	signinResp, err := service.SignIn(context.Background(), &auth.SignInRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
	})
	require.NoError(t, err)

	token := signinResp.Session.Token

	// Create middleware with custom cookie name
	middleware := NewAuthMiddleware(service, authTestsCookieName)
	protectedHandler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, err := GetUserID(r.Context())
		assert.NoError(t, err)
		assert.Equal(t, signupResp.User.ID, userID)
		w.WriteHeader(http.StatusOK)
	}))

	// Create request with cookie
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  authTestsCookieName,
		Value: token,
	})

	w := httptest.NewRecorder()
	protectedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthMiddleware_HandlerFunc(t *testing.T) {
	// Setup
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := auth.NewService(
		&domain.Config{},
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	// Create a user and sign in
	signupResp, err := service.SignUp(context.Background(), &auth.SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	})
	require.NoError(t, err)

	signinResp, err := service.SignIn(context.Background(), &auth.SignInRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
	})
	require.NoError(t, err)

	token := signinResp.Session.Token

	// Create middleware
	middleware := NewAuthMiddleware(service, authTestsCookieName)

	// Create handler with HandlerFunc
	var capturedUserID string
	handler := middleware.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, err := GetUserID(r.Context())
		assert.NoError(t, err)
		capturedUserID = uid
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, signupResp.User.ID, capturedUserID)
}

// ===== OptionalAuthMiddleware Tests =====

func TestOptionalAuthMiddleware_ValidToken(t *testing.T) {
	// Setup
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := auth.NewService(
		&domain.Config{},
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	// Create a user and sign in
	signupResp, err := service.SignUp(context.Background(), &auth.SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	})
	require.NoError(t, err)

	signinResp, err := service.SignIn(context.Background(), &auth.SignInRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
	})
	require.NoError(t, err)

	token := signinResp.Session.Token

	// Create optional middleware
	middleware := NewOptionalAuthMiddleware(service, authTestsCookieName)
	protectedHandler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, err := GetUserID(r.Context())
		assert.NoError(t, err)
		assert.Equal(t, signupResp.User.ID, userID)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/public", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	protectedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestOptionalAuthMiddleware_NoToken(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := auth.NewService(
		&domain.Config{},
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	middleware := NewOptionalAuthMiddleware(service, authTestsCookieName)
	protectedHandler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Should be able to check if user ID exists without error
		_, err := GetUserID(r.Context())
		assert.Nil(t, err) // UserID won't be present

		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/public", nil)
	w := httptest.NewRecorder()
	protectedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestOptionalAuthMiddleware_InvalidToken(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := auth.NewService(
		&domain.Config{},
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	middleware := NewOptionalAuthMiddleware(service, authTestsCookieName)
	protectedHandler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Should still be able to access without error
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/public", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")

	w := httptest.NewRecorder()
	protectedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ===== Integration Tests =====

func TestAuthMiddleware_SetSessionTokenInContext(t *testing.T) {
	// Setup
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := auth.NewService(
		&domain.Config{},
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	// Create a user and sign in
	_, err := service.SignUp(context.Background(), &auth.SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	})
	require.NoError(t, err)

	signinResp, err := service.SignIn(context.Background(), &auth.SignInRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
	})
	require.NoError(t, err)

	token := signinResp.Session.Token

	// Create middleware
	middleware := NewAuthMiddleware(service, authTestsCookieName)
	var capturedToken string
	protectedHandler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionToken, err := GetSessionToken(r.Context())
		assert.NoError(t, err)
		capturedToken = sessionToken
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	protectedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, token, capturedToken)
}

func TestAuthMiddleware_ExpiredSession(t *testing.T) {
	// Setup
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := auth.NewService(
		&domain.Config{},
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	// Create a user and sign in
	_, err := service.SignUp(context.Background(), &auth.SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	})
	require.NoError(t, err)

	signinResp, err := service.SignIn(context.Background(), &auth.SignInRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
	})
	require.NoError(t, err)

	// Manually expire the session by updating it in the repository
	token := signinResp.Session.Token

	// Update the session to be expired
	sess := signinResp.Session
	sess.ExpiresAt = time.Now().Add(-1 * time.Hour)
	err = repos.SessionRepo.Update(sess)
	require.NoError(t, err)

	// Create middleware
	middleware := NewAuthMiddleware(service, authTestsCookieName)
	protectedHandler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	protectedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
