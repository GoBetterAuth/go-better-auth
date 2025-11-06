package auth

import (
	"fmt"
	"net/http"

	"github.com/GoBetterAuth/go-better-auth/domain/session"
	"github.com/GoBetterAuth/go-better-auth/domain/user"
)

// ValidateSessionRequest contains the request data for validating a session
type ValidateSessionRequest struct {
	SessionToken string `json:"session_token"`
}

// ValidateSessionResponse contains the response data for validating a session
type ValidateSessionResponse struct {
	Session *session.Session `json:"session"`
	Valid   bool             `json:"valid"`
}

// ValidateSession is the use case for validating a user's session
func (s *Service) ValidateSession(req *ValidateSessionRequest) (*ValidateSessionResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("validate session request cannot be nil")
	}

	if req.SessionToken == "" {
		return nil, fmt.Errorf("session token is required")
	}

	// Find session by token
	session, err := s.sessionRepo.FindByToken(req.SessionToken)
	if err != nil {
		// Database error occurred
		return nil, fmt.Errorf("failed to find session: %w", err)
	}

	if session == nil {
		// Session not found, return invalid (not an error condition)
		return &ValidateSessionResponse{
			Session: nil,
			Valid:   false,
		}, nil
	}

	// Check if session has expired
	if session.IsExpired() {
		return &ValidateSessionResponse{
			Session: session,
			Valid:   false,
		}, nil
	}

	return &ValidateSessionResponse{
		Session: session,
		Valid:   true,
	}, nil
}

// checkExistingSession checks if the user has a valid session from cookies
// Returns the session and user if valid, nil otherwise
func (s *Service) CheckExistingSessionFromCookie(cookie *http.Cookie) (*session.Session, *user.User, error) {
	validateResp, err := s.ValidateSession(&ValidateSessionRequest{
		SessionToken: cookie.Value,
	})
	if err != nil {
		return nil, nil, err
	}

	if !validateResp.Valid || validateResp.Session == nil {
		return nil, nil, nil
	}

	userResp, err := s.GetMe(&GetMeRequest{
		UserID: validateResp.Session.UserID,
	})
	if err != nil {
		return nil, nil, err
	}

	return validateResp.Session, userResp.User, nil
}
