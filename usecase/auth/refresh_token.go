package auth

import (
	"fmt"
	"time"

	"github.com/GoBetterAuth/go-better-auth/domain/session"
	"github.com/GoBetterAuth/go-better-auth/vault"
)

// RefreshTokenRequest contains the request data for refreshing a session token
type RefreshTokenRequest struct {
	SessionToken string
	IPAddress    string
	UserAgent    string
}

// RefreshTokenResponse contains the response data for refreshing a session token
type RefreshTokenResponse struct {
	Session *session.Session
}

// RefreshToken is the use case for refreshing a user's session token
func (s *Service) RefreshToken(req *RefreshTokenRequest) (*RefreshTokenResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("refresh token request cannot be nil")
	}

	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// Find session by token
	sess, err := s.sessionRepo.FindByToken(req.SessionToken)
	if err != nil {
		return nil, fmt.Errorf("failed to find session: %w", err)
	}

	if sess == nil {
		return nil, fmt.Errorf("session not found")
	}

	// Check if session has expired
	if sess.IsExpired() {
		return nil, fmt.Errorf("session has expired")
	}

	// Generate new token
	newToken, err := vault.GenerateVerificationToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate new token: %w", err)
	}

	// Delete old session
	if err := s.sessionRepo.Delete(sess.ID); err != nil {
		return nil, fmt.Errorf("failed to delete old session: %w", err)
	}

	// Update session with new token and expiration
	sess.Token = newToken
	sess.ExpiresAt = time.Now().Add(24 * time.Hour)

	if req.IPAddress != "" {
		sess.IPAddress = &req.IPAddress
	}
	if req.UserAgent != "" {
		sess.UserAgent = &req.UserAgent
	}

	sess.UpdatedAt = time.Now()

	// Save new session
	if err := s.sessionRepo.Create(sess); err != nil {
		return nil, fmt.Errorf("failed to create new session: %w", err)
	}

	return &RefreshTokenResponse{
		Session: sess,
	}, nil
}

// Validate validates the refresh token request
func (req *RefreshTokenRequest) Validate() error {
	if req.SessionToken == "" {
		return fmt.Errorf("session token is required")
	}

	return nil
}
