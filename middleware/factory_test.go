package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/GoBetterAuth/go-better-auth/domain"
	gobetterauthtests "github.com/GoBetterAuth/go-better-auth/tests"
	"github.com/GoBetterAuth/go-better-auth/usecase/auth"
	"github.com/stretchr/testify/assert"
)

const (
	factoryTestsCookieName = "test_session_token"
)

func setupTestService(t *testing.T) *auth.Service {
	t.Helper()

	// Use migration-enabled test helpers instead of direct repository creation
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	t.Cleanup(cleanup)

	return auth.NewService(
		&domain.Config{},
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)
}

func TestNewAuthMiddlewareFactory(t *testing.T) {
	logger := slog.Default()
	service := setupTestService(t)

	factory := NewAuthMiddlewareFactory(service, factoryTestsCookieName, logger)

	assert.NotNil(t, factory)
	assert.Equal(t, service, factory.service)
	assert.Equal(t, factoryTestsCookieName, factory.cookieName)
	assert.NotNil(t, factory.logger)
}

func TestNewAuthMiddlewareFactory_NilLogger(t *testing.T) {
	service := setupTestService(t)

	factory := NewAuthMiddlewareFactory(service, factoryTestsCookieName, nil)

	assert.NotNil(t, factory)
	assert.NotNil(t, factory.logger)
}

func TestAuthMiddlewareFactory_AuthHandler_Returns(t *testing.T) {
	logger := slog.Default()
	service := setupTestService(t)
	factory := NewAuthMiddlewareFactory(service, factoryTestsCookieName, logger)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := factory.AuthHandler(handler)
	assert.NotNil(t, middleware)
}

func TestAuthMiddlewareFactory_AuthHandlerFunc_Returns(t *testing.T) {
	logger := slog.Default()
	service := setupTestService(t)
	factory := NewAuthMiddlewareFactory(service, factoryTestsCookieName, logger)

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	middleware := factory.AuthHandlerFunc(handler)
	assert.NotNil(t, middleware)
}

func TestAuthMiddlewareFactory_OptionalAuthHandler_Returns(t *testing.T) {
	logger := slog.Default()
	service := setupTestService(t)
	factory := NewAuthMiddlewareFactory(service, factoryTestsCookieName, logger)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := factory.OptionalAuthHandler(handler)
	assert.NotNil(t, middleware)
}

func TestAuthMiddlewareFactory_OptionalAuthHandlerFunc_Returns(t *testing.T) {
	logger := slog.Default()
	service := setupTestService(t)
	factory := NewAuthMiddlewareFactory(service, factoryTestsCookieName, logger)

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	middleware := factory.OptionalAuthHandlerFunc(handler)
	assert.NotNil(t, middleware)
}

func TestAuthMiddlewareFactory_MultipleHandlers(t *testing.T) {
	logger := slog.Default()
	service := setupTestService(t)
	factory := NewAuthMiddlewareFactory(service, factoryTestsCookieName, logger)

	handler1 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("handler1"))
	})

	handler2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("handler2"))
	})

	mw1 := factory.AuthHandler(handler1)
	mw2 := factory.OptionalAuthHandler(handler2)

	assert.NotNil(t, mw1)
	assert.NotNil(t, mw2)
	// Verify they create different middleware by testing them
	req1 := httptest.NewRequest("GET", "/test", nil)
	w1 := httptest.NewRecorder()
	mw1.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusUnauthorized, w1.Code) // Auth required

	req2 := httptest.NewRequest("GET", "/test", nil)
	w2 := httptest.NewRecorder()
	mw2.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code) // Optional auth allows
}

func TestAuthMiddlewareFactory_Integration_WithMux(t *testing.T) {
	logger := slog.Default()
	service := setupTestService(t)
	factory := NewAuthMiddlewareFactory(service, factoryTestsCookieName, logger)

	mux := http.NewServeMux()

	protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("protected"))
	})

	publicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("public"))
	})

	mux.Handle("/protected", factory.AuthHandler(protectedHandler))
	mux.Handle("/public", factory.OptionalAuthHandler(publicHandler))

	// Test protected endpoint - should fail with 401 due to missing token
	req := httptest.NewRequest("GET", "/protected", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Test public endpoint - should succeed even without token
	req = httptest.NewRequest("GET", "/public", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "public", w.Body.String())
}

func TestAuthMiddlewareFactory_ContextUtilities(t *testing.T) {
	logger := slog.Default()
	service := setupTestService(t)
	factory := NewAuthMiddlewareFactory(service, factoryTestsCookieName, logger)

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, err := GetUserID(r.Context())
		if err != nil || userID == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("no user"))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(userID))
	})

	middleware := factory.OptionalAuthHandler(testHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	middleware.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, "no user", w.Body.String())
}

func TestAuthMiddlewareFactory_WithValidSession(t *testing.T) {
	logger := slog.Default()
	service := setupTestService(t)
	factory := NewAuthMiddlewareFactory(service, factoryTestsCookieName, logger)

	// Create a user and sign in to get a session
	signupResp, err := service.SignUp(context.Background(), &auth.SignUpRequest{
		Email:    "factory@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	})
	assert.NoError(t, err)

	signinResp, err := service.SignIn(context.Background(), &auth.SignInRequest{
		Email:    "factory@example.com",
		Password: "ValidPassword123!",
	})
	assert.NoError(t, err)

	token := signinResp.Session.Token

	// Test handler that accesses context
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, err := GetUserID(r.Context())
		assert.NoError(t, err)
		assert.Equal(t, signupResp.User.ID, userID)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(userID))
	})

	// Create middleware with valid token
	middleware := factory.AuthHandler(testHandler)

	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  factoryTestsCookieName,
		Value: token,
	})

	w := httptest.NewRecorder()
	middleware.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, signupResp.User.ID, w.Body.String())
}
