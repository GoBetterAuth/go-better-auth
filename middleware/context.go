package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/GoBetterAuth/go-better-auth/domain/session"
)

// Context keys for storing values in request context
type ContextKey string

const (
	// UserIDKey is the context key for storing the authenticated user ID
	UserIDKey ContextKey = "user_id"

	// SessionTokenKey is the context key for storing the session token
	SessionTokenKey ContextKey = "session_token"

	// SessionKey is the context key for storing the full session object
	SessionKey ContextKey = "session"
)

// GetUserID retrieves the user ID from the request context
func GetUserID(ctx context.Context) (string, error) {
	userID, ok := ctx.Value(UserIDKey).(string)
	if !ok {
		return "", nil
	}
	if userID == "" {
		return "", fmt.Errorf("user ID is empty")
	}
	return userID, nil
}

// SetUserID sets the user ID in the request context
func SetUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, UserIDKey, userID)
}

// MustGetUserID retrieves the user ID from context and throws an error if not found
// Use this in handlers that are protected by AuthMiddleware
func MustGetUserID(ctx context.Context) (string, error) {
	userID, err := GetUserID(ctx)
	if userID == "" {
		return "", fmt.Errorf("user ID not found in context - ensure AuthMiddleware is applied")
	}
	if err != nil {
		return "", err
	}
	return userID, nil
}

// GetSession retrieves the session from the request context
func GetSession(ctx context.Context) (*session.Session, error) {
	session, ok := ctx.Value(SessionKey).(*session.Session)
	if !ok {
		return nil, nil
	}
	if session == nil {
		return nil, fmt.Errorf("session is nil")
	}
	return session, nil
}

// SetSession sets the session in the request context
func SetSession(ctx context.Context, session any) context.Context {
	return context.WithValue(ctx, SessionKey, session)
}

// MustGetSession retrieves the session from context and throws an error if not found
// Use this in handlers that are protected by AuthMiddleware
func MustGetSession(ctx context.Context) (any, error) {
	session, err := GetSession(ctx)
	if session == nil {
		return nil, fmt.Errorf("session not found in context - ensure AuthMiddleware is applied")
	}
	if err != nil {
		return nil, err
	}
	return session, nil
}

// GetSessionToken retrieves the session token from the request context
func GetSessionToken(ctx context.Context) (string, error) {
	token, ok := ctx.Value(SessionTokenKey).(string)
	if !ok {
		return "", nil
	}
	if token == "" {
		return "", fmt.Errorf("session token is empty")
	}
	return token, nil
}

// SetSessionToken sets the session token in the request context
func SetSessionToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, SessionTokenKey, token)
}

// MustGetSessionToken retrieves the session token from context and throws an error if not found
// Use this in handlers that are protected by AuthMiddleware
func MustGetSessionToken(ctx context.Context) (string, error) {
	token, err := GetSessionToken(ctx)
	if token == "" {
		return "", fmt.Errorf("session token not found in context - ensure AuthMiddleware is applied")
	}
	if err != nil {
		return "", err
	}
	return token, nil
}

// ExtractSessionToken extracts the session token directly from an HTTP request
// It tries Authorization header first (Bearer token), then falls back to the specified cookie name
func ExtractSessionToken(r *http.Request, cookieName string) (string, error) {
	// Try Authorization header first (Bearer token)
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && parts[0] == "Bearer" {
			return parts[1], nil
		}
	}

	// Try cookie
	cookie, err := r.Cookie(cookieName)
	if err == nil && cookie.Value != "" {
		return cookie.Value, nil
	}

	return "", fmt.Errorf("session token not found in Authorization header or cookie")
}

// SessionTokenExtractor provides a common interface for extracting session tokens
type SessionTokenExtractor interface {
	GetSessionCookieName() string
}

// ExtractSessionTokenFromManager extracts the session token using a cookie manager's configuration
// This is the preferred method when you have access to a cookie manager instance
func ExtractSessionTokenFromManager(r *http.Request, manager SessionTokenExtractor) (string, error) {
	return ExtractSessionToken(r, manager.GetSessionCookieName())
}
