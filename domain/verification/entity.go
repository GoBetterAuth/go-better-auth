package verification

import (
	"errors"
	"fmt"
	"time"
)

// Error types for verification operations
var (
	ErrVerificationNotFound = errors.New("verification not found")
)

// VerificationType defines the type of verification
type VerificationType string

const (
	TypeEmailVerification VerificationType = "email_verification"
	TypePasswordReset     VerificationType = "password_reset"
	TypeEmailChange       VerificationType = "email_change"
)

// Verification represents a verification token (email verification, password reset, etc.)
type Verification struct {
	ID         string           `json:"id"`
	UserID     string           `json:"user_id,omitempty"` // User ID (optional, used for email change)
	Identifier string           `json:"identifier"`        // Email or other identifier
	Token      string           `json:"token"`
	Type       VerificationType `json:"type"`
	ExpiresAt  time.Time        `json:"expires_at"`
	CreatedAt  time.Time        `json:"created_at"`
	UpdatedAt  time.Time        `json:"updated_at"`
}

// CreateVerificationRequest represents a request to create a verification token
type CreateVerificationRequest struct {
	UserID     string           `json:"user_id"`
	Identifier string           `json:"identifier"`
	Token      string           `json:"token"`
	Type       VerificationType `json:"type"`
	ExpiresAt  time.Time        `json:"expires_at"`
}

// ValidateCreateVerificationRequest validates a create verification request
func ValidateCreateVerificationRequest(req *CreateVerificationRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}

	if req.Identifier == "" {
		return fmt.Errorf("identifier cannot be empty")
	}

	if len(req.Identifier) > 255 {
		return fmt.Errorf("identifier is too long (max 255 characters)")
	}

	if req.Token == "" {
		return fmt.Errorf("token cannot be empty")
	}

	if len(req.Token) > 512 {
		return fmt.Errorf("token is too long (max 512 characters)")
	}

	if req.Type == "" {
		return fmt.Errorf("type cannot be empty")
	}

	if !isValidType(req.Type) {
		return fmt.Errorf("invalid type: %s", req.Type)
	}

	if req.ExpiresAt.IsZero() {
		return fmt.Errorf("expiration time is required")
	}

	if req.ExpiresAt.Before(time.Now()) {
		return fmt.Errorf("expiration time must be in the future")
	}

	return nil
}

// IsExpired checks if the verification has expired
func (v *Verification) IsExpired() bool {
	return time.Now().After(v.ExpiresAt)
}

// isValidType checks if the verification type is valid
func isValidType(t VerificationType) bool {
	switch t {
	case TypeEmailVerification, TypePasswordReset, TypeEmailChange:
		return true
	default:
		return false
	}
}

// Repository defines the interface for verification data access
type Repository interface {
	// Create creates a new verification token
	Create(verification *Verification) error

	// FindByToken retrieves a verification by token
	FindByToken(token string) (*Verification, error)

	// FindByHashedToken retrieves a verification by matching a plain token against a hashed token
	// It takes a plain token and finds the verification where the hashed token matches
	FindByHashedToken(plainToken string) (*Verification, error)

	// FindByIdentifierAndType retrieves a verification by identifier and type
	FindByIdentifierAndType(identifier string, verType VerificationType) (*Verification, error)

	// Delete deletes a verification by ID
	Delete(id string) error

	// DeleteByToken deletes a verification by token
	DeleteByToken(token string) error

	// DeleteExpired deletes all expired verifications
	DeleteExpired() error

	// Count returns the total number of verifications
	Count() (int, error)

	// ExistsByToken checks if a verification exists by token
	ExistsByToken(token string) (bool, error)

	// ExistsByIdentifierAndType checks if a verification exists by identifier and type
	ExistsByIdentifierAndType(identifier string, verType VerificationType) (bool, error)
}
