package auth

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/GoBetterAuth/go-better-auth/domain/account"
	"github.com/GoBetterAuth/go-better-auth/domain/user"
	"github.com/GoBetterAuth/go-better-auth/domain/verification"
	"github.com/GoBetterAuth/go-better-auth/internal/crypto"
)

// RequestPasswordResetRequest contains the request data for requesting a password reset
type RequestPasswordResetRequest struct {
	Email       string
	CallbackURL *string
}

// RequestPasswordResetResponse contains the response data for requesting a password reset
type RequestPasswordResetResponse struct {
	Verification *verification.Verification
}

// RequestPasswordReset is the use case for requesting a password reset
func (s *Service) RequestPasswordReset(ctx context.Context, req *RequestPasswordResetRequest) (*RequestPasswordResetResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request password reset request cannot be nil")
	}

	if strings.TrimSpace(req.Email) == "" {
		return nil, fmt.Errorf("email is required")
	}

	user, err := s.userRepo.FindByEmail(req.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	resetToken, err := crypto.GenerateVerificationToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate reset token: %w", err)
	}

	// Hash the token for secure storage
	hashedToken := crypto.HashVerificationToken(resetToken)

	expiresIn := 24 * time.Hour
	if s.config.EmailAndPassword != nil && s.config.EmailAndPassword.Enabled && s.config.EmailAndPassword.ResetPasswordTokenExpiresIn > 0 {
		expiresIn = s.config.EmailAndPassword.ResetPasswordTokenExpiresIn
	}

	now := time.Now()
	verification := &verification.Verification{
		UserID:     user.ID,
		Identifier: user.Email,
		Token:      hashedToken,
		Type:       verification.TypePasswordReset,
		ExpiresAt:  now.Add(expiresIn),
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := s.verificationRepo.Create(verification); err != nil {
		return nil, fmt.Errorf("failed to create password reset token: %w", err)
	}

	if s.config != nil && s.config.EmailAndPassword != nil && s.config.EmailAndPassword.SendResetPassword != nil {
		go s.sendResetPasswordEmail(ctx, user, resetToken, req.CallbackURL)
	}

	return &RequestPasswordResetResponse{
		Verification: verification,
	}, nil
}

// ResetPasswordRequest contains the request data for resetting a password
type ResetPasswordRequest struct {
	Token       string
	NewPassword string
}

// ResetPasswordResponse contains the response data for resetting a password
type ResetPasswordResponse struct {
	Message string `json:"message"`
}

// ResetPassword is the use case for resetting a user's password
func (s *Service) ResetPassword(req *ResetPasswordRequest) (*ResetPasswordResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("reset password request cannot be nil")
	}

	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	verificationRecord, err := s.verificationRepo.FindByHashedToken(req.Token)
	if err != nil {
		return nil, fmt.Errorf("failed to find reset token: %w", err)
	}

	if verificationRecord == nil || verificationRecord.Type != verification.TypePasswordReset {
		return nil, fmt.Errorf("invalid reset token")
	}

	if verificationRecord.IsExpired() {
		return nil, fmt.Errorf("reset token has expired")
	}

	user, err := s.userRepo.FindByEmail(verificationRecord.Identifier)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	acc, err := s.accountRepo.FindByUserIDAndProvider(user.ID, account.ProviderCredential)
	if err != nil {
		return nil, fmt.Errorf("failed to find account: %w", err)
	}

	if acc == nil {
		return nil, fmt.Errorf("account not found")
	}

	hashedPassword, err := s.passwordHasher.Hash(strings.TrimSpace(req.NewPassword))
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Update account password
	acc.Password = &hashedPassword
	acc.UpdatedAt = time.Now()

	if err := s.accountRepo.Update(acc); err != nil {
		return nil, fmt.Errorf("failed to update password: %w", err)
	}

	_ = s.verificationRepo.Delete(verificationRecord.ID)

	return &ResetPasswordResponse{
		Message: "Password has been reset successfully",
	}, nil
}

func (s *Service) sendResetPasswordEmail(ctx context.Context, user *user.User, token string, callbackURL *string) {
	if s.config.EmailAndPassword == nil || !s.config.EmailAndPassword.Enabled || s.config.EmailAndPassword.SendResetPassword == nil {
		return
	}

	if ctx == nil {
		ctx = context.Background()
	}

	verifyURL := s.buildVerificationURL(token, callbackURL)

	if err := s.config.EmailAndPassword.SendResetPassword(ctx, user, verifyURL, token); err != nil {
		slog.ErrorContext(ctx, "failed to send reset password email", "user_id", user.ID, "email", user.Email, "error", err)
		return
	}

	slog.InfoContext(ctx, "reset password email sent", "user_id", user.ID, "email", user.Email)
}

// Validate validates the reset password request
func (req *ResetPasswordRequest) Validate() error {
	if req.Token == "" {
		return fmt.Errorf("token is required")
	}

	if strings.TrimSpace(req.NewPassword) == "" {
		return fmt.Errorf("new password is required")
	}

	if len(strings.TrimSpace(req.NewPassword)) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}

	return nil
}
