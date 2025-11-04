package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/GoBetterAuth/go-better-auth/domain/user"
	"github.com/GoBetterAuth/go-better-auth/middleware"
	"github.com/GoBetterAuth/go-better-auth/usecase/auth"
)

type GetMeRequest struct {
	UserID string `json:"user_id"`
}

type GetMeResponse struct {
	User *user.User `json:"user"`
}

// GetMeHandler handles GET /auth/me
// If user is authenticated, it returns the user's profile information. Otherwise, it returns null.
func (h *AuthHandler) GetMeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		ErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	userID, err := middleware.GetUserID(r.Context())
	if err != nil {
		ErrorResponse(w, http.StatusUnauthorized, err.Error())
		return
	}
	if userID == "" {
		SuccessResponse(w, http.StatusOK, GetMeResponse{
			User: nil,
		})
		return
	}

	resp, err := h.service.GetMe(&auth.GetMeRequest{
		UserID: userID,
	})
	if err != nil {
		switch err.Error() {
		case "user ID is required":
			ErrorResponse(w, http.StatusBadRequest, err.Error())
		case "user not found":
			ErrorResponse(w, http.StatusNotFound, "user not found")
		default:
			ErrorResponse(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	SuccessResponse(w, http.StatusOK, GetMeResponse{
		User: resp.User,
	})
}

type UpdateProfileRequest struct {
	Name  *string `json:"name,omitempty"`
	Image *string `json:"image,omitempty"`
}

type UpdateProfileResponse struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	EmailVerified bool   `json:"email_verified"`
	Image         string `json:"image,omitempty"`
}

// UpdateProfileHandler handles PATCH /auth/me
// Requires AuthMiddleware to be applied to extract user ID from context
func (h *AuthHandler) UpdateProfileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		ErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	userID, err := middleware.MustGetUserID(r.Context())
	if err != nil {
		ErrorResponse(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	updateResp, err := h.service.UpdateUser(&auth.UpdateUserRequest{
		UserID: userID,
		Name:   req.Name,
		Image:  req.Image,
	})
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "user not found"):
			ErrorResponse(w, http.StatusNotFound, "user not found")
		case strings.Contains(err.Error(), "invalid request"):
			ErrorResponse(w, http.StatusBadRequest, err.Error())
		default:
			ErrorResponse(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	httpResp := UpdateProfileResponse{
		ID:            updateResp.User.ID,
		Email:         updateResp.User.Email,
		Name:          updateResp.User.Name,
		EmailVerified: updateResp.User.EmailVerified,
	}
	if updateResp.User.Image != nil {
		httpResp.Image = *updateResp.User.Image
	}

	SuccessResponse(w, http.StatusOK, httpResp)
}

type DeleteProfileRequest struct {
	ConfirmPassword string `json:"confirm_password"`
}

type DeleteProfileResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// DeleteProfileHandler handles DELETE /auth/me
// Requires AuthMiddleware to be applied to extract user ID from context
func (h *AuthHandler) DeleteProfileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		ErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	userID, err := middleware.MustGetUserID(r.Context())
	if err != nil {
		ErrorResponse(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req DeleteProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.ConfirmPassword == "" {
		ErrorResponse(w, http.StatusBadRequest, "confirm_password is required")
		return
	}

	_, err = h.service.DeleteUser(&auth.DeleteUserRequest{
		UserID: userID,
	})
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "user not found"):
			ErrorResponse(w, http.StatusNotFound, "user not found")
		default:
			ErrorResponse(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	SuccessResponse(w, http.StatusOK, DeleteProfileResponse{
		Message: "account successfully deleted",
	})
}
