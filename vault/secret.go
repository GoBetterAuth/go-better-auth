package vault

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// SecretGenerator provides utilities for generating and validating secrets
type SecretGenerator struct {
	minLength int
}

// NewSecretGenerator creates a new secret generator with default minimum length of 32
func NewSecretGenerator() *SecretGenerator {
	return &SecretGenerator{
		minLength: 32,
	}
}

// GenerateSecret generates a cryptographically secure random secret of the specified length
// Length is in bytes, and it will be base64 encoded (resulting in ~1.33x longer string)
func (sg *SecretGenerator) GenerateSecret(length int) (string, error) {
	if length < 16 {
		return "", fmt.Errorf("secret length must be at least 16 bytes")
	}

	if length > 1024 {
		return "", fmt.Errorf("secret length must not exceed 1024 bytes")
	}

	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return base64.StdEncoding.EncodeToString(randomBytes), nil
}

// GenerateSecretDefault generates a secret with the default length (32 bytes)
func (sg *SecretGenerator) GenerateSecretDefault() (string, error) {
	return sg.GenerateSecret(32)
}

// ValidateSecret validates that a secret meets minimum requirements
func (sg *SecretGenerator) ValidateSecret(secret string) error {
	if secret == "" {
		return fmt.Errorf("secret cannot be empty")
	}

	if len(secret) < sg.minLength {
		return fmt.Errorf("secret must be at least %d characters long", sg.minLength)
	}

	return nil
}

// GenerateToken generates a secure random token of the specified length
// This is useful for verification tokens, reset tokens, etc.
func GenerateToken(length int) (string, error) {
	if length < 8 {
		return "", fmt.Errorf("token length must be at least 8 bytes")
	}

	if length > 512 {
		return "", fmt.Errorf("token length must not exceed 512 bytes")
	}

	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}

	return base64.URLEncoding.EncodeToString(randomBytes), nil
}

// GenerateSessionToken generates a session token (32 bytes)
func GenerateSessionToken() (string, error) {
	return GenerateToken(32)
}

// GenerateVerificationToken generates a verification token (24 bytes)
func GenerateVerificationToken() (string, error) {
	return GenerateToken(24)
}

// GenerateCSRFToken generates a CSRF token (32 bytes)
func GenerateCSRFToken() (string, error) {
	return GenerateToken(32)
}

// HashVerificationToken hashes a verification token using SHA256
// This is used to securely store the token in the database
func HashVerificationToken(token string) string {
	if token == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(token))
	return base64.URLEncoding.EncodeToString(hash[:])
}

// VerifyVerificationToken verifies a plain token against its hash
// Returns true if the token matches the hash, false otherwise
func VerifyVerificationToken(plainToken, hashedToken string) bool {
	if plainToken == "" || hashedToken == "" {
		return false
	}
	return HashVerificationToken(plainToken) == hashedToken
}
