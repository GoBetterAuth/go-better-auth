package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/GoBetterAuth/go-better-auth/domain/user"
	"github.com/GoBetterAuth/go-better-auth/usecase/auth"
)

type SignInRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	CallbackURL string `json:"callback_url,omitempty"`
}

type SignInResponse struct {
	Token string     `json:"token"`
	User  *user.User `json:"user"`
}

// SignInHandler handles POST /auth/signin
func (h *AuthHandler) SignInHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		ErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req SignInRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ipAddress := r.RemoteAddr
	userAgent := r.Header.Get("User-Agent")

	// Call use
	resp, err := h.service.SignIn(r.Context(), &auth.SignInRequest{
		Email:       req.Email,
		Password:    req.Password,
		CallbackURL: req.CallbackURL,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
	})
	if err != nil {
		errMsg := err.Error()
		switch errMsg {
		case "invalid request":
			ErrorResponse(w, http.StatusBadRequest, errMsg)
		case "user not found":
			ErrorResponse(w, http.StatusUnauthorized, "invalid email or password")
		case "account not found":
			ErrorResponse(w, http.StatusUnauthorized, "invalid email or password")
		case "account is temporarily locked":
			ErrorResponse(w, http.StatusTooManyRequests, "too many login attempts, try again later")
		default:
			if strings.Contains(errMsg, "locked") {
				ErrorResponse(w, http.StatusTooManyRequests, "too many login attempts, try again later")
			} else if strings.Contains(errMsg, "password") || strings.Contains(errMsg, "verify") {
				ErrorResponse(w, http.StatusUnauthorized, "invalid email or password")
			} else {
				ErrorResponse(w, http.StatusInternalServerError, err.Error())
			}
		}
		return
	}

	h.cookieManager.SetSessionCookie(w, resp.Session.Token, resp.Session.ExpiresAt)

	SuccessResponse(w, http.StatusOK, &SignInResponse{
		Token: resp.Session.Token,
		User:  resp.User,
	})
}
