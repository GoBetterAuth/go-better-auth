package auth

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/GoBetterAuth/go-better-auth/domain/user"
	"github.com/GoBetterAuth/go-better-auth/domain/verification"
	"github.com/GoBetterAuth/go-better-auth/vault"
)

// SendEmailVerificationRequest contains the request data for sending an email verification
type SendEmailVerificationRequest struct {
	Email       string  `json:"email"`
	CallbackURL *string `json:"callback_url,omitempty"`
}

// SendEmailVerificationResponse contains the response data for sending email verification
type SendEmailVerificationResponse struct {
	Status bool `json:"status"`
}

// SendEmailVerification is the use case for sending an email verification
func (s *Service) SendEmailVerification(ctx context.Context, req *SendEmailVerificationRequest) (*SendEmailVerificationResponse, error) {
	if !s.config.EmailVerification.Enabled {
		return nil, fmt.Errorf("send email verification feature is disabled")
	}

	if req == nil {
		return nil, fmt.Errorf("send email verification request cannot be nil")
	}

	if req.Email == "" {
		return nil, fmt.Errorf("email is required")
	}

	// Generate verification token
	verificationToken, err := vault.GenerateVerificationToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate verification token: %w", err)
	}

	// Hash the token for secure storage
	hashedToken := vault.HashVerificationToken(verificationToken)

	// Create verification record with hashed token
	verification := &verification.Verification{
		Identifier: req.Email,
		Token:      hashedToken,
		Type:       verification.TypeEmailVerification,
		ExpiresAt:  time.Now().Add(7 * 24 * time.Hour), // 7 days
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if err := s.verificationRepo.Create(verification); err != nil {
		return nil, fmt.Errorf("failed to create email verification token: %w", err)
	}

	// Send verification email if configured
	if s.config.EmailVerification != nil && s.config.EmailVerification.SendVerificationEmail != nil {
		// Find user by email
		user, err := s.userRepo.FindByEmail(req.Email)
		if err == nil && user != nil {
			go s.sendVerificationEmailForRequestAsync(ctx, user, verificationToken, req.CallbackURL)
		}
	}

	return &SendEmailVerificationResponse{
		Status: true,
	}, nil
}

// sendVerificationEmailForRequestAsync sends a verification email asynchronously for manual verification requests
func (s *Service) sendVerificationEmailForRequestAsync(ctx context.Context, user *user.User, verificationToken string, callbackURL *string) {
	verifyURL := s.buildVerificationURL(verificationToken, callbackURL)

	// Send email
	if err := s.config.EmailVerification.SendVerificationEmail(ctx, user, verifyURL, verificationToken); err != nil {
		slog.ErrorContext(ctx, "failed to send verification email", "user_id", user.ID, "email", user.Email, "error", err)
		return
	}

	slog.InfoContext(ctx, "verification email sent", "user_id", user.ID, "email", user.Email)
}
