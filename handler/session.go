package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/GoBetterAuth/go-better-auth/usecase/auth"
)

type ValidateSessionRequest struct {
	Token string `json:"token"`
}

type ValidateSessionResponse struct {
	Valid     bool      `json:"valid"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ValidateSessionHandler handles GET /auth/validate
func (h *AuthHandler) ValidateSessionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		ErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	authHeader := r.Header.Get("Authorization")
	var token string

	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && parts[0] == "Bearer" {
			token = parts[1]
		}
	}

	if token == "" {
		ErrorResponse(w, http.StatusBadRequest, "session token required")
		return
	}

	resp, err := h.service.ValidateSession(&auth.ValidateSessionRequest{
		SessionToken: token,
	})
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}

	if !resp.Valid {
		ErrorResponse(w, http.StatusUnauthorized, "invalid or expired session")
		return
	}

	SuccessResponse(w, http.StatusOK, ValidateSessionResponse{
		Valid:     resp.Valid,
		UserID:    resp.Session.UserID,
		ExpiresAt: resp.Session.ExpiresAt,
	})
}

type RefreshTokenRequest struct {
	Token string `json:"token"`
}

type RefreshTokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// RefreshTokenHandler handles POST /auth/refresh
func (h *AuthHandler) RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		ErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ipAddress := r.RemoteAddr
	userAgent := r.Header.Get("User-Agent")

	// Call use case
	resp, err := h.service.RefreshToken(&auth.RefreshTokenRequest{
		SessionToken: req.Token,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
	})
	if err != nil {
		switch err.Error() {
		case "session token is required":
			ErrorResponse(w, http.StatusBadRequest, err.Error())
		case "session not found":
			ErrorResponse(w, http.StatusUnauthorized, "invalid session")
		case "session has expired":
			ErrorResponse(w, http.StatusUnauthorized, "session expired")
		default:
			ErrorResponse(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	SuccessResponse(w, http.StatusOK, RefreshTokenResponse{
		Token:     resp.Session.Token,
		ExpiresAt: resp.Session.ExpiresAt,
	})
}
