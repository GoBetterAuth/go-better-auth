package handler

import (
	"fmt"
	"net/http"
	"time"

	"github.com/GoBetterAuth/go-better-auth/domain"
)

const (
	// DefaultCookiePrefix is the default prefix for all cookies.
	DefaultCookiePrefix = "go-better-auth"
	// SessionCookieName is the default name for the session cookie.
	SessionCookieName = "session_token"
)

// CookieManager handles setting and clearing cookies with configurable options.
type CookieManager struct {
	sessionCookieName string
	domain            string
	path              string
	secure            bool
	sameSite          http.SameSite
}

// NewCookieManager creates a new CookieManager based on the application configuration.
// It centralizes the logic for determining cookie names, security, and domain settings.
func NewCookieManager(cfg *domain.Config) *CookieManager {
	cm := &CookieManager{
		sessionCookieName: SessionCookieName,
		path:              "/",
		sameSite:          http.SameSiteLaxMode,
	}

	if cfg.Advanced != nil {
		cm.secure = cfg.Advanced.UseSecureCookies

		if cfg.Advanced.CrossSubDomainCookies != nil && cfg.Advanced.CrossSubDomainCookies.Enabled {
			cm.domain = cfg.Advanced.CrossSubDomainCookies.Domain
		}

		prefix := DefaultCookiePrefix
		if cfg.Advanced.CookiePrefix != "" {
			prefix = cfg.Advanced.CookiePrefix
		}
		cm.sessionCookieName = fmt.Sprintf("%s.%s", prefix, cm.sessionCookieName)

		if customCookie, ok := cfg.Advanced.Cookies[SessionCookieName]; ok {
			if customCookie.Name != "" {
				cm.sessionCookieName = customCookie.Name
			}
		}
	}

	return cm
}

// SetSessionCookie sets the session token as a cookie using the configured settings.
func (cm *CookieManager) SetSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     cm.sessionCookieName,
		Value:    token,
		Expires:  expiresAt,
		Domain:   cm.domain,
		Path:     cm.path,
		HttpOnly: true,
		Secure:   cm.secure,
		SameSite: cm.sameSite,
	})
}

// ClearSessionCookie clears the session cookie using the configured settings.
func (cm *CookieManager) ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cm.sessionCookieName,
		Value:    "",
		Expires:  time.Unix(0, 0),
		Domain:   cm.domain,
		Path:     cm.path,
		HttpOnly: true,
		Secure:   cm.secure,
		SameSite: cm.sameSite,
	})
}

// GetSessionCookieName returns the configured name for the session cookie.
// This is useful for middleware or other parts of the app that need to read the cookie.
func (cm *CookieManager) GetSessionCookieName() string {
	return cm.sessionCookieName
}
