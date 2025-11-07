package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/GoBetterAuth/go-better-auth/domain/user"
	"github.com/GoBetterAuth/go-better-auth/domain/verification"
	"github.com/GoBetterAuth/go-better-auth/vault"
)

// ChangeEmailRequest contains the request data for requesting an email change
type ChangeEmailRequest struct {
	UserID      string `json:"user_id" validate:"required"`
	NewEmail    string `json:"new_email" validate:"required,email"`
	CallbackURL string `json:"callback_url"`
}

// ChangeEmailResponse contains the response data for requesting an email change
type ChangeEmailResponse struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
}

// ChangeEmail is the use case for requesting an email change
// It generates a verification token that must be confirmed before the email is changed
func (s *Service) ChangeEmail(ctx context.Context, req *ChangeEmailRequest) (*ChangeEmailResponse, error) {
	if !s.config.User.ChangeEmail.Enabled {
		return nil, fmt.Errorf("change email feature is disabled")
	}

	if req == nil {
		return nil, fmt.Errorf("change email request cannot be nil")
	}

	if req.UserID == "" {
		return nil, fmt.Errorf("user ID is required")
	}

	if req.NewEmail == "" {
		return nil, fmt.Errorf("new email is required")
	}

	// Validate email format
	if err := user.ValidateEmail(req.NewEmail); err != nil {
		return nil, fmt.Errorf("invalid email: %w", err)
	}

	// Check if user exists
	existingUser, err := s.userRepo.FindByID(req.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	if existingUser == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Check if new email is the same as current email
	if existingUser.Email == req.NewEmail {
		return nil, fmt.Errorf("new email is the same as current email")
	}

	// Check if new email is already in use by another user
	emailExists, err := s.userRepo.ExistsByEmail(req.NewEmail)
	if err != nil {
		return nil, fmt.Errorf("failed to check email existence: %w", err)
	}

	if emailExists {
		return nil, fmt.Errorf("email is already in use")
	}

	// Generate verification token
	verificationToken, err := vault.GenerateVerificationToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate verification token: %w", err)
	}

	// Hash the token for secure storage
	hashedToken := vault.HashVerificationToken(verificationToken)

	// Create verification record with hashed token
	// Store the user ID and new email for confirmation without requiring auth
	verification := &verification.Verification{
		UserID:     req.UserID,
		Identifier: req.NewEmail,
		Token:      hashedToken,
		Type:       verification.TypeEmailChange,
		ExpiresAt:  time.Now().Add(24 * time.Hour), // 1 day
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if err := s.verificationRepo.Create(verification); err != nil {
		return nil, fmt.Errorf("failed to create email change verification token: %w", err)
	}

	if s.config.User != nil &&
		s.config.User.ChangeEmail != nil &&
		s.config.User.ChangeEmail.Enabled &&
		s.config.User.ChangeEmail.SendChangeEmailVerification != nil {
		go s.sendChangeEmailVerificationAsync(ctx, existingUser, req.NewEmail, verificationToken, req.CallbackURL)
	}

	return &ChangeEmailResponse{
		Status:  true,
		Message: "Verification email sent",
	}, nil
}

// sendChangeEmailVerificationAsync sends a verification email for email change asynchronously
func (s *Service) sendChangeEmailVerificationAsync(ctx context.Context, user *user.User, newEmail string, verificationToken string, callbackURL string) {
	// Build verification URL
	baseURL := s.config.BaseURL
	basePath := s.config.BasePath
	if basePath == "" {
		basePath = "/api/auth"
	}

	callbackURLValue := ""
	if callbackURL != "" {
		callbackURLValue = "&callbackURL=" + url.QueryEscape(callbackURL)
	}
	verifyURL := baseURL + basePath + "/verify-email?token=" + url.QueryEscape(verificationToken) + callbackURLValue

	// Send email to new email address
	if err := s.config.User.ChangeEmail.SendChangeEmailVerification(ctx, user, newEmail, verifyURL, verificationToken); err != nil {
		slog.ErrorContext(ctx, "failed to send change email verification", "user_id", user.ID, "new_email", newEmail, "error", err)
		return
	}

	slog.InfoContext(ctx, "change email verification sent", "user_id", user.ID, "new_email", newEmail)
}
