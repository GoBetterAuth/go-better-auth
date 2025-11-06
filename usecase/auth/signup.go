package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/GoBetterAuth/go-better-auth/domain/account"
	"github.com/GoBetterAuth/go-better-auth/domain/session"
	"github.com/GoBetterAuth/go-better-auth/domain/user"
	"github.com/GoBetterAuth/go-better-auth/domain/verification"
	"github.com/GoBetterAuth/go-better-auth/internal/crypto"
)

// SignUpRequest contains the request data for sign up
type SignUpRequest struct {
	Email       string
	Password    string
	Name        string
	CallbackURL *string
}

// SignUpResponse contains the response data for sign up
type SignUpResponse struct {
	Session *session.Session
	User    *user.User
}

type PasswordLengthRequirementOptions struct {
	MinLength int
	MaxLength int
}

// SignUp is the use case for user sign up with email and password
func (s *Service) SignUp(ctx context.Context, req *SignUpRequest) (*SignUpResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("sign up request cannot be nil")
	}

	// Check if email/password auth is disabled
	if s.config.EmailAndPassword != nil && s.config.EmailAndPassword.DisableSignUp {
		return nil, fmt.Errorf("email/password is disabled")
	}

	var options *PasswordLengthRequirementOptions = nil
	if s.config.EmailAndPassword != nil {
		options = &PasswordLengthRequirementOptions{
			MinLength: s.config.EmailAndPassword.MinPasswordLength,
			MaxLength: s.config.EmailAndPassword.MaxPasswordLength,
		}
	}
	if err := req.Validate(options); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	exists, err := s.userRepo.ExistsByEmail(req.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to check if user exists: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("user with this email already exists")
	}

	hashedPassword, err := s.passwordHasher.Hash(strings.TrimSpace(req.Password))
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	userToCreate := &user.User{
		ID:    uuid.New().String(),
		Email: strings.TrimSpace(req.Email),
		Name:  strings.TrimSpace(req.Name),
		// If email verification is not enabled, mark as verified automatically
		EmailVerified: s.config.EmailVerification == nil || !s.config.EmailVerification.Enabled,
		Image:         nil,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	accountToCreate := &account.Account{
		ID:         uuid.New().String(),
		UserID:     userToCreate.ID,
		ProviderID: account.ProviderCredential,
		AccountID:  userToCreate.ID,
		Password:   &hashedPassword,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	// Save user and account
	if err := s.userRepo.Create(userToCreate); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	if err := s.accountRepo.Create(accountToCreate); err != nil {
		// Cleanup on failure
		_ = s.userRepo.Delete(userToCreate.ID)
		return nil, fmt.Errorf("failed to create account: %w", err)
	}

	// Generate session token
	sessionToken, err := crypto.GenerateSessionToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	// Create session
	sessionCreated := &session.Session{
		ID:        uuid.New().String(),
		UserID:    userToCreate.ID,
		Token:     sessionToken,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour), // 7 day session
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Save session
	if err := s.sessionRepo.Create(sessionCreated); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Send verification email if configured
	if s.config.EmailVerification != nil && s.config.EmailVerification.SendOnSignUp && s.config.EmailVerification.SendVerificationEmail != nil {
		go s.sendVerificationEmailAsync(ctx, userToCreate, req.CallbackURL)
	}

	return &SignUpResponse{Session: sessionCreated, User: userToCreate}, nil
}

// sendVerificationEmailAsync sends the verification email asynchronously
func (s *Service) sendVerificationEmailAsync(ctx context.Context, user *user.User, callbackURL *string) {
	// Generate verification token
	verificationToken, err := crypto.GenerateVerificationToken()
	if err != nil {
		slog.ErrorContext(ctx, "failed to generate verification token", "user_id", user.ID, "error", err)
		return
	}

	// Hash the token for secure storage
	hashedToken := crypto.HashVerificationToken(verificationToken)

	// Create verification record with hashed token
	newVerification := &verification.Verification{
		UserID:     user.ID,
		Identifier: user.Email,
		Token:      hashedToken,
		Type:       verification.TypeEmailVerification,
		ExpiresAt:  time.Now().Add(s.config.EmailVerification.ExpiresIn),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if err := s.verificationRepo.Create(newVerification); err != nil {
		slog.ErrorContext(ctx, "failed to create email verification token", "user_id", user.ID, "error", err)
		return
	}

	// Build verification URL using the plain token (not the hashed one)
	baseURL := s.config.BaseURL
	basePath := s.config.BasePath
	if basePath == "" {
		basePath = "/auth"
	}
	callbackURLValue := ""
	if callbackURL != nil && *callbackURL != "" {
		callbackURLValue = "&callbackURL=" + url.QueryEscape(*callbackURL)
	}
	verifyURL := baseURL + basePath + "/verify-email?token=" + url.QueryEscape(verificationToken) + callbackURLValue

	// Send email with the plain token
	if err := s.config.EmailVerification.SendVerificationEmail(ctx, user, verifyURL, verificationToken); err != nil {
		slog.ErrorContext(ctx, "failed to send verification email", "user_id", user.ID, "email", user.Email, "error", err)
		return
	}

	slog.InfoContext(ctx, "verification email sent", "user_id", user.ID, "email", user.Email)
}

// Validate validates the sign up request
func (req *SignUpRequest) Validate(options *PasswordLengthRequirementOptions) error {
	if strings.TrimSpace(req.Email) == "" {
		return fmt.Errorf("email is required")
	}

	if strings.TrimSpace(req.Password) == "" {
		return fmt.Errorf("password is required")
	}

	if strings.TrimSpace(req.Name) == "" {
		return fmt.Errorf("name is required")
	}

	password := strings.TrimSpace(req.Password)
	passwordLen := len(password)

	minPasswordLengthValue := 8 // Default
	if options != nil {
		minPasswordLengthValue = options.MinLength
	}
	if passwordLen < minPasswordLengthValue {
		return fmt.Errorf("password must be at least %d characters", minPasswordLengthValue)
	}

	maxPasswordLengthValue := 128 // Default
	if options != nil {
		maxPasswordLengthValue = options.MaxLength
	}
	if passwordLen > maxPasswordLengthValue {
		return fmt.Errorf("password must not exceed %d characters", maxPasswordLengthValue)
	}

	return nil
}
