package handler

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/GoBetterAuth/go-better-auth/usecase/auth"
)

type SendEmailVerificationRequest struct {
	Email       string `json:"email"`
	CallbackURL string `json:"callback_url,omitempty"`
}

type SendEmailVerificationResponse struct {
	Status bool `json:"status"`
}

// SendEmailVerificationHandler handles POST /auth/email-verification
func (h *AuthHandler) SendEmailVerificationHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		ErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req SendEmailVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := h.service.SendEmailVerification(r.Context(), &auth.SendEmailVerificationRequest{
		Email:       req.Email,
		CallbackURL: req.CallbackURL,
	})
	if err != nil {
		// Map error to HTTP status
		switch err.Error() {
		case "email is required":
			ErrorResponse(w, http.StatusBadRequest, err.Error())
		default:
			ErrorResponse(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	SuccessResponse(w, http.StatusOK, &SendEmailVerificationResponse{
		Status: resp.Status,
	})
}

type VerifyEmailResponse struct {
	Status bool   `json:"status"`
	Type   string `json:"type"`
}

// VerifyEmailHandler handles GET /auth/verify-email?token={token}&callbackURL={callbackURL} OR POST /auth/verify-email
// This unified handler verifies all types of verification tokens:
// - Email verification
// - Email change confirmation
// - Password reset confirmation
// It extracts the token from query parameters or POST body, validates it, and redirects to a success page or returns a response.
func (h *AuthHandler) VerifyEmailHandler(w http.ResponseWriter, r *http.Request) {
	var token string

	switch r.Method {
	case http.MethodGet:
		token = r.URL.Query().Get("token")
		if token == "" {
			ErrorResponse(w, http.StatusBadRequest, "verification token is required")
			return
		}
	case http.MethodPost:
		var req struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ErrorResponse(w, http.StatusBadRequest, "invalid request body")
			return
		}
		token = req.Token
		if token == "" {
			ErrorResponse(w, http.StatusBadRequest, "verification token is required")
			return
		}
	default:
		ErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	resp, err := h.service.VerifyEmail(r.Context(), &auth.VerifyEmailRequest{
		VerificationToken: token,
	})
	if err != nil {
		switch err.Error() {
		case "verification token is required":
			ErrorResponse(w, http.StatusBadRequest, err.Error())
		case "invalid verification token":
			ErrorResponse(w, http.StatusUnauthorized, "invalid or expired verification token")
		case "verification token has expired":
			ErrorResponse(w, http.StatusUnauthorized, "verification token has expired")
		case "user not found":
			ErrorResponse(w, http.StatusNotFound, "user not found")
		case "email is already in use":
			ErrorResponse(w, http.StatusConflict, err.Error())
		default:
			ErrorResponse(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	if r.Method == http.MethodGet {
		callbackURL := r.URL.Query().Get("callbackURL")
		if callbackURL != "" {
			redirectURL, err := url.Parse(callbackURL)
			if err != nil {
				ErrorResponse(w, http.StatusBadRequest, "invalid callback url")
				return
			}

			query := redirectURL.Query()
			query.Set("token", token)
			if resp != nil && resp.Type != "" {
				query.Set("type", string(resp.Type))
			}
			redirectURL.RawQuery = query.Encode()

			http.Redirect(w, r, redirectURL.String(), http.StatusSeeOther)
			return
		}
	}

	SuccessResponse(w, http.StatusOK, &VerifyEmailResponse{
		Status: resp.Status,
		Type:   string(resp.Type),
	})
}
