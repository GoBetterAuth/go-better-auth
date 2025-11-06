package auth

import (
	"fmt"
)

// SignOutRequest contains the request data for sign out
type SignOutRequest struct {
	SessionToken string
}

// SignOut is the use case for user sign out
func (s *Service) SignOut(req *SignOutRequest) error {
	if req == nil {
		return fmt.Errorf("sign out request cannot be nil")
	}

	if req.SessionToken == "" {
		return fmt.Errorf("session token is required")
	}

	// Find session by token
	session, err := s.sessionRepo.FindByToken(req.SessionToken)
	if err != nil {
		return fmt.Errorf("failed to find session: %w", err)
	}

	if session == nil {
		return fmt.Errorf("session not found")
	}

	// Delete session
	if err := s.sessionRepo.Delete(session.ID); err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	return nil
}
