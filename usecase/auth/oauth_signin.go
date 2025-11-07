package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/GoBetterAuth/go-better-auth/domain/account"
	"github.com/GoBetterAuth/go-better-auth/domain/session"
	"github.com/GoBetterAuth/go-better-auth/domain/user"
	"github.com/GoBetterAuth/go-better-auth/vault"
	"github.com/google/uuid"
)

// OAuthSignInRequest represents a request to sign in via OAuth
type OAuthSignInRequest struct {
	ProviderID  account.ProviderType `validate:"required"`
	OAuthUser   *account.OAuthUser   `validate:"required"`
	OAuthTokens *account.OAuthTokens `validate:"required"`
}

// OAuthSignInResponse represents the response from OAuth sign in
type OAuthSignInResponse struct {
	User      *user.User       `json:"user"`
	Session   *session.Session `json:"session"`
	Account   *account.Account `json:"account"`
	IsNewUser bool             `json:"is_new_user"`
}

// findOrCreateUserForOAuth finds or creates a user for OAuth sign-in
// Returns the user, whether it's a new user, and any error
func (s *Service) findOrCreateUserForOAuth(ctx context.Context, oauthUser *account.OAuthUser) (*user.User, bool, error) {
	// Try to find existing user by email
	existingUser, err := s.userRepo.FindByEmail(oauthUser.Email)
	if err != nil && !errors.Is(err, user.ErrUserNotFound) {
		return nil, false, fmt.Errorf("failed to lookup user: %w", err)
	}

	if existingUser != nil {
		slog.InfoContext(ctx, "found existing user for oauth signin",
			"user_id", existingUser.ID,
			"email", existingUser.Email,
		)
		return existingUser, false, nil
	}

	// Create new user from OAuth profile
	newUser, err := s.createUserFromOAuth(ctx, oauthUser)
	if err != nil {
		return nil, false, fmt.Errorf("failed to create user from oauth: %w", err)
	}

	slog.InfoContext(ctx, "created new user from oauth",
		"user_id", newUser.ID,
		"email", newUser.Email,
	)

	return newUser, true, nil
}

// linkOrUpdateOAuthAccount links a new OAuth account or updates an existing one
func (s *Service) linkOrUpdateOAuthAccount(ctx context.Context, userID string, providerID account.ProviderType, oauthUser *account.OAuthUser, tokens *account.OAuthTokens) (*account.Account, error) {
	// Check if OAuth account is already linked
	existingAccount, err := s.accountRepo.FindByUserIDAndProvider(userID, providerID)
	if err != nil && !errors.Is(err, account.ErrAccountNotFound) {
		return nil, fmt.Errorf("failed to check existing account: %w", err)
	}

	if existingAccount == nil {
		// Link new OAuth account
		accountRecord, err := s.linkOAuthAccountInternal(ctx, userID, providerID, oauthUser, tokens)
		if err != nil {
			return nil, fmt.Errorf("failed to link oauth account: %w", err)
		}

		slog.InfoContext(ctx, "linked oauth account to user",
			"user_id", userID,
			"provider", providerID,
			"account_id", accountRecord.ID,
		)

		return accountRecord, nil
	}

	// Update existing account with new tokens
	existingAccount.AccessToken = &tokens.AccessToken
	existingAccount.RefreshToken = tokens.RefreshToken
	existingAccount.IDToken = tokens.IDToken
	if tokens.AccessTokenExpiresAt != nil {
		existingAccount.AccessTokenExpiresAt = tokens.AccessTokenExpiresAt
	}
	existingAccount.Scope = &tokens.Scope
	existingAccount.UpdatedAt = time.Now()

	err = s.accountRepo.Update(existingAccount)
	if err != nil {
		return nil, fmt.Errorf("failed to update account tokens: %w", err)
	}

	slog.InfoContext(ctx, "updated oauth account tokens",
		"user_id", userID,
		"provider", providerID,
		"account_id", existingAccount.ID,
	)

	return existingAccount, nil
}

// syncOAuthProfileData syncs user profile data from OAuth provider
func (s *Service) syncOAuthProfileData(ctx context.Context, userRecord *user.User, providerID account.ProviderType, oauthUser *account.OAuthUser) error {
	syncReq := &SyncProviderDataRequest{
		UserID:     userRecord.ID,
		ProviderID: providerID,
		OAuthUser:  oauthUser,
		UpdateUser: true,
	}

	_, err := s.SyncProviderData(ctx, syncReq)
	return err
}

// createSessionForUser creates a new session for a user
func (s *Service) createSessionForUser(userID string) (*session.Session, error) {
	sessionToken, err := vault.GenerateSessionToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	// Use configured session expiration time, default to 24 hours if not set
	expiresIn := 24 * time.Hour
	if s.config != nil && s.config.Session != nil && s.config.Session.ExpiresIn > 0 {
		expiresIn = s.config.Session.ExpiresIn
	}

	sess := &session.Session{
		ID:        uuid.New().String(),
		UserID:    userID,
		Token:     sessionToken,
		ExpiresAt: time.Now().Add(expiresIn),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	err = s.sessionRepo.Create(sess)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return sess, nil
}

// OAuthSignIn handles OAuth signin/signup flow
// It will:
// 1. Look up existing user by email from OAuth provider
// 2. If user exists, link the OAuth account if not already linked
// 3. If user doesn't exist, create a new user and link the OAuth account
// 4. Create a new session for the user
// 5. Sync user profile data from OAuth provider
func (s *Service) OAuthSignIn(ctx context.Context, req *OAuthSignInRequest) (*OAuthSignInResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}

	if req.ProviderID == "" {
		return nil, fmt.Errorf("provider_id cannot be empty")
	}

	if req.OAuthUser == nil {
		return nil, fmt.Errorf("oauth_user cannot be nil")
	}

	if req.OAuthUser.Email == "" {
		return nil, fmt.Errorf("oauth user email cannot be empty")
	}

	if req.OAuthTokens == nil {
		return nil, fmt.Errorf("oauth_tokens cannot be nil")
	}

	// Step 1: Find or create user
	userRecord, isNewUser, err := s.findOrCreateUserForOAuth(ctx, req.OAuthUser)
	if err != nil {
		return nil, err
	}

	// Step 2: Link or update OAuth account
	accountRecord, err := s.linkOrUpdateOAuthAccount(ctx, userRecord.ID, req.ProviderID, req.OAuthUser, req.OAuthTokens)
	if err != nil {
		return nil, err
	}

	// Step 3: Sync user profile data if not a new user
	if !isNewUser {
		if err := s.syncOAuthProfileData(ctx, userRecord, req.ProviderID, req.OAuthUser); err != nil {
			// Log the error but don't fail the signin
			slog.WarnContext(
				ctx,
				"failed to sync provider data during oauth signin",
				"user_id", userRecord.ID,
				"provider", req.ProviderID,
				"error", err,
			)
		} else {
			// Reload user after sync
			reloadedUser, err := s.userRepo.FindByID(userRecord.ID)
			if err != nil {
				return nil, fmt.Errorf("failed to reload user after sync: %w", err)
			}
			userRecord = reloadedUser
		}
	}

	// Step 4: Create a new session
	session, err := s.createSessionForUser(userRecord.ID)
	if err != nil {
		return nil, err
	}

	return &OAuthSignInResponse{
		User:      userRecord,
		Session:   session,
		Account:   accountRecord,
		IsNewUser: isNewUser,
	}, nil
}

// createUserFromOAuth creates a new user from OAuth profile data
func (s *Service) createUserFromOAuth(ctx context.Context, oauthUser *account.OAuthUser) (*user.User, error) {
	newUser := &user.User{
		ID:            uuid.New().String(),
		Email:         oauthUser.Email,
		Name:          oauthUser.Name,
		EmailVerified: true,
		Image:         oauthUser.Picture,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	err := s.userRepo.Create(newUser)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return newUser, nil
}

// linkOAuthAccountInternal links an OAuth account to a user (internal helper)
func (s *Service) linkOAuthAccountInternal(ctx context.Context, userID string, providerID account.ProviderType, oauthUser *account.OAuthUser, tokens *account.OAuthTokens) (*account.Account, error) {
	newAccount := &account.Account{
		ID:                    uuid.New().String(),
		UserID:                userID,
		ProviderID:            providerID,
		AccountID:             oauthUser.ID,
		AccessToken:           &tokens.AccessToken,
		RefreshToken:          tokens.RefreshToken,
		IDToken:               tokens.IDToken,
		AccessTokenExpiresAt:  tokens.AccessTokenExpiresAt,
		RefreshTokenExpiresAt: tokens.RefreshTokenExpiresAt,
		Scope:                 &tokens.Scope,
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
	}

	err := s.accountRepo.Create(newAccount)
	if err != nil {
		return nil, fmt.Errorf("failed to create account: %w", err)
	}

	return newAccount, nil
}
