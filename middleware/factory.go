package middleware

import (
	"log/slog"
	"net/http"

	"github.com/GoBetterAuth/go-better-auth/usecase/auth"
)

// AuthMiddlewareFactory provides functions to create initialized middleware instances.
// This is useful for applications that want to defer middleware creation until after
// the library has been initialized, particularly when using dependency injection.
type AuthMiddlewareFactory struct {
	service    *auth.Service
	cookieName string
	logger     *slog.Logger
}

// NewAuthMiddlewareFactory creates a new factory with an auth service, cookie name, and logger.
func NewAuthMiddlewareFactory(service *auth.Service, cookieName string, logger *slog.Logger) *AuthMiddlewareFactory {
	if logger == nil {
		logger = slog.Default()
	}
	return &AuthMiddlewareFactory{
		service:    service,
		cookieName: cookieName,
		logger:     logger,
	}
}

// AuthHandler returns the auth middleware's Handler method bound to this factory's service.
func (f *AuthMiddlewareFactory) AuthHandler(next http.Handler) http.Handler {
	mw := NewAuthMiddleware(f.service, f.cookieName)
	return mw.Handler(next)
}

// AuthHandlerFunc returns the auth middleware's HandlerFunc method bound to this factory's service.
func (f *AuthMiddlewareFactory) AuthHandlerFunc(next http.HandlerFunc) http.HandlerFunc {
	mw := NewAuthMiddleware(f.service, f.cookieName)
	return mw.HandlerFunc(next)
}

// OptionalAuthHandler returns the optional auth middleware's Handler method bound to this factory's service.
func (f *AuthMiddlewareFactory) OptionalAuthHandler(next http.Handler) http.Handler {
	mw := NewOptionalAuthMiddleware(f.service, f.cookieName)
	return mw.Handler(next)
}

// OptionalAuthHandlerFunc returns the optional auth middleware's HandlerFunc method bound to this factory's service.
func (f *AuthMiddlewareFactory) OptionalAuthHandlerFunc(next http.HandlerFunc) http.HandlerFunc {
	mw := NewOptionalAuthMiddleware(f.service, f.cookieName)
	return mw.HandlerFunc(next)
}
