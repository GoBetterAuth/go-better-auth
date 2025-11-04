package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/GoBetterAuth/go-better-auth/middleware"
	"github.com/GoBetterAuth/go-better-auth/usecase/auth"
)

type ChangeEmailRequest struct {
	NewEmail    string `json:"new_email"`
	CallbackURL string `json:"callback_url,omitempty"`
}

type ChangeEmailResponse struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
}

// ChangeEmailHandler handles POST /auth/change-email
// Requires AuthMiddleware to be applied to extract user ID from context
// Initiates an email change by sending a verification token to the new email
func (h *AuthHandler) ChangeEmailHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		ErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	userID, err := middleware.MustGetUserID(r.Context())
	if err != nil {
		ErrorResponse(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req ChangeEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := h.service.ChangeEmail(r.Context(), &auth.ChangeEmailRequest{
		UserID:      userID,
		NewEmail:    req.NewEmail,
		CallbackURL: req.CallbackURL,
	})
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "user ID is required"):
			ErrorResponse(w, http.StatusBadRequest, err.Error())
		case strings.Contains(err.Error(), "new email is required"):
			ErrorResponse(w, http.StatusBadRequest, "new_email is required")
		case strings.Contains(err.Error(), "invalid email"):
			ErrorResponse(w, http.StatusBadRequest, err.Error())
		case strings.Contains(err.Error(), "user not found"):
			ErrorResponse(w, http.StatusNotFound, "user not found")
		case strings.Contains(err.Error(), "new email is the same as current email"):
			ErrorResponse(w, http.StatusBadRequest, err.Error())
		case strings.Contains(err.Error(), "email is already in use"):
			ErrorResponse(w, http.StatusConflict, err.Error())
		default:
			ErrorResponse(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	SuccessResponse(w, http.StatusOK, resp)
}
