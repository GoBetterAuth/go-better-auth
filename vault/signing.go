package vault

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// Signer provides HMAC-SHA256 signing utilities for data integrity verification
type Signer struct {
	key []byte
}

// NewSigner creates a new signer with the provided key
// For HMAC, any key size is acceptable, but at least 32 bytes is recommended
func NewSigner(key []byte) (*Signer, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("signing key cannot be empty")
	}

	if len(key) < 16 {
		return nil, fmt.Errorf("signing key should be at least 16 bytes for security, got %d", len(key))
	}

	return &Signer{
		key: key,
	}, nil
}

// Sign creates an HMAC-SHA256 signature for the given data and returns it as base64
func (s *Signer) Sign(data string) (string, error) {
	if data == "" {
		return "", fmt.Errorf("data cannot be empty")
	}

	h := hmac.New(sha256.New, s.key)
	h.Write([]byte(data))
	signature := h.Sum(nil)

	return base64.StdEncoding.EncodeToString(signature), nil
}

// SignBytes creates an HMAC-SHA256 signature for the given bytes
func (s *Signer) SignBytes(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data cannot be empty")
	}

	h := hmac.New(sha256.New, s.key)
	h.Write(data)
	return h.Sum(nil), nil
}

// Verify verifies that the given signature matches the data
// Returns true if the signature is valid, false otherwise
func (s *Signer) Verify(data string, signatureB64 string) (bool, error) {
	if data == "" || signatureB64 == "" {
		return false, fmt.Errorf("data and signature cannot be empty")
	}

	// Decode the provided signature
	providedSignature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}

	// Compute the expected signature
	expectedSignature, _ := s.SignBytes([]byte(data))

	// Use constant-time comparison to prevent timing attacks
	return hmac.Equal(providedSignature, expectedSignature), nil
}

// VerifyBytes verifies that the given signature matches the data (byte version)
func (s *Signer) VerifyBytes(data []byte, signature []byte) (bool, error) {
	if len(data) == 0 || len(signature) == 0 {
		return false, fmt.Errorf("data and signature cannot be empty")
	}

	// Compute the expected signature
	expectedSignature, _ := s.SignBytes(data)

	// Use constant-time comparison to prevent timing attacks
	return hmac.Equal(signature, expectedSignature), nil
}

// SignAndEncrypt signs the data and returns "data.signature" format
// This is useful for tokens where you want to send both data and signature
func (s *Signer) SignAndFormat(data string) (string, error) {
	if data == "" {
		return "", fmt.Errorf("data cannot be empty")
	}

	signature, err := s.Sign(data)
	if err != nil {
		return "", err
	}

	// Format: base64(data).signature
	encodedData := base64.StdEncoding.EncodeToString([]byte(data))
	return encodedData + "." + signature, nil
}

// VerifyAndExtract extracts the data from a "data.signature" format and verifies it
func (s *Signer) VerifyAndExtract(token string) (string, error) {
	if token == "" {
		return "", fmt.Errorf("token cannot be empty")
	}

	// Split on last dot
	lastDotIndex := len(token) - 1
	for i := len(token) - 1; i >= 0; i-- {
		if token[i] == '.' {
			lastDotIndex = i
			break
		}
	}

	if lastDotIndex == len(token)-1 {
		return "", fmt.Errorf("invalid token format: missing signature")
	}

	encodedData := token[:lastDotIndex]
	signature := token[lastDotIndex+1:]

	// Decode the data
	data, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return "", fmt.Errorf("failed to decode token data: %w", err)
	}

	// Verify the signature
	valid, err := s.Verify(string(data), signature)
	if err != nil {
		return "", err
	}

	if !valid {
		return "", fmt.Errorf("signature verification failed")
	}

	return string(data), nil
}
