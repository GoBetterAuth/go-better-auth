package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/GoBetterAuth/go-better-auth/domain/user"
	"github.com/GoBetterAuth/go-better-auth/usecase/auth"
)

type SignUpRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	Name        string `json:"name"`
	CallbackURL string `json:"callback_url,omitempty"`
}

type SignUpResponse struct {
	Token string     `json:"token"`
	User  *user.User `json:"user"`
}

// SignUpHandler handles POST /auth/signup
func (h *AuthHandler) SignUpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		ErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	existingSession, existingUser, err := h.checkExistingSession(r)
	if err == nil && existingSession != nil && existingUser != nil {
		SuccessResponse(w, http.StatusOK, &SignUpResponse{
			Token: existingSession.Token,
			User:  existingUser,
		})
		return
	}

	var req SignUpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := h.service.SignUp(r.Context(), &auth.SignUpRequest{
		Email:       req.Email,
		Password:    req.Password,
		Name:        req.Name,
		CallbackURL: req.CallbackURL,
	})
	if err != nil {
		errMsg := err.Error()
		if errMsg == "sign up is disabled" {
			ErrorResponse(w, http.StatusForbidden, "sign up is disabled")
		} else if errMsg == "user with this email already exists" {
			ErrorResponse(w, http.StatusConflict, "email already registered")
		} else if strings.HasPrefix(errMsg, "invalid request:") {
			ErrorResponse(w, http.StatusBadRequest, errMsg)
		} else {
			ErrorResponse(w, http.StatusBadRequest, err.Error())
		}
		return
	}

	h.cookieManager.SetSessionCookie(w, resp.Session.Token, resp.Session.ExpiresAt)

	SuccessResponse(w, http.StatusCreated, &SignUpResponse{
		Token: resp.Session.Token,
		User:  resp.User,
	})
}
