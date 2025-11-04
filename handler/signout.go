package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/GoBetterAuth/go-better-auth/usecase/auth"
)

type SignOutRequest struct {
	Token string `json:"token"`
}

// SignOutHandler handles POST /auth/signout
func (h *AuthHandler) SignOutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
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
		var req SignOutRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil && req.Token != "" {
			token = req.Token
		}
	}

	if token == "" {
		cookie, err := r.Cookie(h.cookieManager.GetSessionCookieName())
		if err == nil {
			token = cookie.Value
		}
	}

	if token == "" {
		ErrorResponse(w, http.StatusBadRequest, "session token required")
		return
	}

	err := h.service.SignOut(&auth.SignOutRequest{
		SessionToken: token,
	})
	if err != nil {
		switch err.Error() {
		case "session not found":
			ErrorResponse(w, http.StatusUnauthorized, "invalid session")
		default:
			ErrorResponse(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	h.cookieManager.ClearSessionCookie(w)

	SuccessResponse(w, http.StatusOK, map[string]string{
		"message": "signed out successfully",
	})
}
