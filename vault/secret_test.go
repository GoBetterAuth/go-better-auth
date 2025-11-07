package vault

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSecretGenerator(t *testing.T) {
	sg := NewSecretGenerator()
	assert.NotNil(t, sg)
	assert.Equal(t, 32, sg.minLength)
}

func TestGenerateSecret_Valid(t *testing.T) {
	sg := NewSecretGenerator()

	secret, err := sg.GenerateSecret(32)
	assert.NoError(t, err)
	assert.NotEmpty(t, secret)

	// Verify it's valid base64
	decoded, err := base64.StdEncoding.DecodeString(secret)
	assert.NoError(t, err)
	assert.Equal(t, 32, len(decoded))
}

func TestGenerateSecret_DifferentLengths(t *testing.T) {
	sg := NewSecretGenerator()

	lengths := []int{16, 32, 64, 128, 256}
	for _, length := range lengths {
		secret, err := sg.GenerateSecret(length)
		assert.NoError(t, err, "should generate secret of length %d", length)
		assert.NotEmpty(t, secret)

		decoded, err := base64.StdEncoding.DecodeString(secret)
		assert.NoError(t, err)
		assert.Equal(t, length, len(decoded))
	}
}

func TestGenerateSecret_TooShort(t *testing.T) {
	sg := NewSecretGenerator()

	secret, err := sg.GenerateSecret(8)
	assert.Error(t, err)
	assert.Empty(t, secret)
}

func TestGenerateSecret_TooLong(t *testing.T) {
	sg := NewSecretGenerator()

	secret, err := sg.GenerateSecret(2048)
	assert.Error(t, err)
	assert.Empty(t, secret)
}

func TestGenerateSecret_Uniqueness(t *testing.T) {
	sg := NewSecretGenerator()

	secret1, err := sg.GenerateSecret(32)
	assert.NoError(t, err)

	secret2, err := sg.GenerateSecret(32)
	assert.NoError(t, err)

	// Secrets should be different (probability of collision is negligible)
	assert.NotEqual(t, secret1, secret2)
}

func TestGenerateSecretDefault(t *testing.T) {
	sg := NewSecretGenerator()

	secret, err := sg.GenerateSecretDefault()
	assert.NoError(t, err)
	assert.NotEmpty(t, secret)

	decoded, err := base64.StdEncoding.DecodeString(secret)
	assert.NoError(t, err)
	assert.Equal(t, 32, len(decoded))
}

func TestValidateSecret_Valid(t *testing.T) {
	sg := NewSecretGenerator()

	secret := "this-is-a-very-secure-secret-that-is-long-enough"
	err := sg.ValidateSecret(secret)
	assert.NoError(t, err)
}

func TestValidateSecret_Empty(t *testing.T) {
	sg := NewSecretGenerator()

	err := sg.ValidateSecret("")
	assert.Error(t, err)
}

func TestValidateSecret_TooShort(t *testing.T) {
	sg := NewSecretGenerator()

	err := sg.ValidateSecret("short")
	assert.Error(t, err)
}

func TestGenerateToken_Valid(t *testing.T) {
	token, err := GenerateToken(32)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Verify it's valid base64 URL encoding
	decoded, err := base64.URLEncoding.DecodeString(token)
	assert.NoError(t, err)
	assert.Equal(t, 32, len(decoded))
}

func TestGenerateToken_DifferentLengths(t *testing.T) {
	lengths := []int{8, 16, 32, 64, 128, 256}
	for _, length := range lengths {
		token, err := GenerateToken(length)
		assert.NoError(t, err, "should generate token of length %d", length)
		assert.NotEmpty(t, token)

		decoded, err := base64.URLEncoding.DecodeString(token)
		assert.NoError(t, err)
		assert.Equal(t, length, len(decoded))
	}
}

func TestGenerateToken_TooShort(t *testing.T) {
	token, err := GenerateToken(4)
	assert.Error(t, err)
	assert.Empty(t, token)
}

func TestGenerateToken_TooLong(t *testing.T) {
	token, err := GenerateToken(1024)
	assert.Error(t, err)
	assert.Empty(t, token)
}

func TestGenerateToken_Uniqueness(t *testing.T) {
	token1, err := GenerateToken(32)
	assert.NoError(t, err)

	token2, err := GenerateToken(32)
	assert.NoError(t, err)

	assert.NotEqual(t, token1, token2)
}

func TestGenerateSessionToken(t *testing.T) {
	token, err := GenerateSessionToken()
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	decoded, err := base64.URLEncoding.DecodeString(token)
	assert.NoError(t, err)
	assert.Equal(t, 32, len(decoded))
}

func TestGenerateVerificationToken(t *testing.T) {
	token, err := GenerateVerificationToken()
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	decoded, err := base64.URLEncoding.DecodeString(token)
	assert.NoError(t, err)
	assert.Equal(t, 24, len(decoded))
}

func TestGenerateCSRFToken(t *testing.T) {
	token, err := GenerateCSRFToken()
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	decoded, err := base64.URLEncoding.DecodeString(token)
	assert.NoError(t, err)
	assert.Equal(t, 32, len(decoded))
}
