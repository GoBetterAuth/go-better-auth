package vault

import (
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2PasswordHasher provides utilities for hashing and verifying passwords using Argon2
type Argon2PasswordHasher struct {
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
}

// NewArgon2PasswordHasher creates a new password hasher with secure defaults
// Time: 1 iteration (recommended minimum is 1-4)
// Memory: 64 MB
// Threads: 4 (number of parallel threads)
// KeyLen: 32 bytes
func NewArgon2PasswordHasher() *Argon2PasswordHasher {
	return &Argon2PasswordHasher{
		time:    1,
		memory:  64 * 1024, // 64 MB in KiB
		threads: 4,
		keyLen:  32,
	}
}

// NewArgon2PasswordHasherCustom creates a password hasher with custom parameters
func NewArgon2PasswordHasherCustom(time, memory uint32, threads uint8, keyLen uint32) *Argon2PasswordHasher {
	return &Argon2PasswordHasher{
		time:    time,
		memory:  memory,
		threads: threads,
		keyLen:  keyLen,
	}
}

// Hash hashes a password using Argon2id and returns a base64-encoded hash
func (ph *Argon2PasswordHasher) Hash(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}

	if len(password) > 72 {
		return "", fmt.Errorf("password is too long (max 72 characters)")
	}

	// Generate a random salt (16 bytes)
	salt, err := GenerateToken(16)
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Hash the password with Argon2id
	hash := argon2.IDKey(
		[]byte(password),
		[]byte(salt),
		ph.time,
		ph.memory,
		ph.threads,
		ph.keyLen,
	)

	// Return format: "$argon2id$v=19$m=<memory>,t=<time>,p=<threads>$<salt>$<hash>"
	return fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		ph.memory,
		ph.time,
		ph.threads,
		salt,
		base64URLEncode(hash),
	), nil
}

// Verify verifies a password against a hash
func (ph *Argon2PasswordHasher) Verify(password, hash string) (bool, error) {
	if password == "" || hash == "" {
		return false, fmt.Errorf("password and hash cannot be empty")
	}

	// Parse the hash to extract salt and parameters
	var params argon2Params
	salt, hashed, err := parseArgon2Hash(hash)
	if err != nil {
		return false, fmt.Errorf("invalid hash format: %w", err)
	}

	// Extract parameters from the existing hash if needed
	params, err = extractArgon2Params(hash)
	if err != nil {
		return false, fmt.Errorf("failed to extract parameters: %w", err)
	}

	// Hash the provided password with the same salt
	computed := argon2.IDKey(
		[]byte(password),
		[]byte(salt),
		params.time,
		params.memory,
		params.threads,
		params.keyLen,
	)

	// Use constant-time comparison to prevent timing attacks
	return constantTimeCompare(computed, hashed), nil
}

type argon2Params struct {
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
}

// parseArgon2Hash parses the Argon2 hash format and returns salt and hash bytes
func parseArgon2Hash(hash string) (string, []byte, error) {
	// Expected format: $argon2id$v=19$m=<memory>,t=<time>,p=<threads>$<salt>$<hash>
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return "", nil, fmt.Errorf("invalid hash format")
	}

	salt := parts[4]
	hashStr := parts[5]

	hashBytes, err := base64URLDecode(hashStr)
	if err != nil {
		return "", nil, fmt.Errorf("failed to decode hash: %w", err)
	}

	return salt, hashBytes, nil
}

// extractArgon2Params extracts parameters from the Argon2 hash
func extractArgon2Params(hash string) (argon2Params, error) {
	// Expected format: $argon2id$v=19$m=<memory>,t=<time>,p=<threads>$<salt>$<hash>
	parts := strings.Split(hash, "$")
	if len(parts) < 4 {
		return argon2Params{}, fmt.Errorf("invalid hash format")
	}

	// Parse the parameters part: m=<memory>,t=<time>,p=<threads>
	var memory, time uint32
	var threads uint8
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads)
	if err != nil {
		return argon2Params{}, fmt.Errorf("failed to parse parameters: %w", err)
	}

	return argon2Params{
		time:    time,
		memory:  memory,
		threads: threads,
		keyLen:  32, // Default keyLen
	}, nil
}

// constantTimeCompare compares two byte slices in constant time
func constantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}

	return result == 0
}

// base64URLEncode encodes bytes to standard base64 encoding
func base64URLEncode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// base64URLDecode decodes base64 encoded string to bytes
func base64URLDecode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// HashPassword is a convenience function to hash a password using the default hasher
func HashPassword(password string) (string, error) {
	hasher := NewArgon2PasswordHasher()
	return hasher.Hash(password)
}

// VerifyPassword is a convenience function to verify a password using the default hasher
func VerifyPassword(password, hash string) (bool, error) {
	hasher := NewArgon2PasswordHasher()
	return hasher.Verify(password, hash)
}
