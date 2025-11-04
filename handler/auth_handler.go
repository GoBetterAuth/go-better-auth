package handler

import (
	"net/http"
	"strings"

	"github.com/GoBetterAuth/go-better-auth/domain/session"
	"github.com/GoBetterAuth/go-better-auth/domain/user"
	"github.com/GoBetterAuth/go-better-auth/usecase/auth"
)

// AuthHandler implements http.Handler for all auth endpoints
type AuthHandler struct {
	service       *auth.Service
	cookieManager *CookieManager
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(service *auth.Service, cookieManager *CookieManager) http.Handler {
	return &AuthHandler{
		service:       service,
		cookieManager: cookieManager,
	}
}

// ServeHTTP dispatches requests to appropriate handlers
func (h *AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	method := r.Method

	// Extract the endpoint by splitting on "/auth/"
	parts := strings.SplitN(path, "/auth/", 2)
	endpoint := ""
	if len(parts) == 2 {
		endpoint = parts[1]
	}

	switch method {
	case "GET":
		switch endpoint {
		case "validate":
			h.ValidateSessionHandler(w, r)
		case "me":
			h.GetMeHandler(w, r)
		case "verify-email":
			h.VerifyEmailHandler(w, r)
		default:
			http.NotFound(w, r)
		}
	case "POST":
		switch endpoint {
		case "sign-up/email":
			h.SignUpHandler(w, r)
		case "sign-in/email":
			h.SignInHandler(w, r)
		case "sign-out":
			h.SignOutHandler(w, r)
		case "validate":
			h.ValidateSessionHandler(w, r)
		case "refresh":
			h.RefreshTokenHandler(w, r)
		case "email-verification":
			h.SendEmailVerificationHandler(w, r)
		case "password-reset":
			h.SendPasswordResetHandler(w, r)
		case "reset-password":
			h.ResetPasswordHandler(w, r)
		case "change-email":
			h.ChangeEmailHandler(w, r)
		default:
			http.NotFound(w, r)
		}
	default:
		http.NotFound(w, r)
	}
}

// checkExistingSession checks if the user has a valid session from cookies
// Returns the session and user if valid, nil otherwise
func (h *AuthHandler) checkExistingSession(r *http.Request) (*session.Session, *user.User, error) {
	cookie, err := r.Cookie(h.cookieManager.GetSessionCookieName())
	if err != nil {
		// No cookie found, not an error
		return nil, nil, nil
	}

	validateResp, err := h.service.ValidateSession(&auth.ValidateSessionRequest{
		SessionToken: cookie.Value,
	})
	if err != nil {
		return nil, nil, err
	}

	if !validateResp.Valid || validateResp.Session == nil {
		return nil, nil, nil
	}

	userResp, err := h.service.GetMe(&auth.GetMeRequest{
		UserID: validateResp.Session.UserID,
	})
	if err != nil {
		return nil, nil, err
	}

	return validateResp.Session, userResp.User, nil
}
