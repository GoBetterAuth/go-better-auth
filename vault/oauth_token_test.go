package vault

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOAuthTokenEncrypter(t *testing.T) {
	secret := "test-secret-key-for-oauth-token-encryption"

	encrypter, err := NewOAuthTokenEncrypter(secret)
	require.NoError(t, err)
	assert.NotNil(t, encrypter)
}

func TestNewOAuthTokenEncrypter_EmptySecret(t *testing.T) {
	encrypter, err := NewOAuthTokenEncrypter("")
	assert.Error(t, err)
	assert.Nil(t, encrypter)
	assert.Contains(t, err.Error(), "secret cannot be empty")
}

func TestOAuthTokenEncrypter_EncryptAccessToken(t *testing.T) {
	secret := "test-secret-key"
	encrypter, err := NewOAuthTokenEncrypter(secret)
	require.NoError(t, err)

	token := "access_token_12345"
	encrypted, err := encrypter.EncryptAccessToken(token)
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)
	assert.NotEqual(t, token, encrypted)
}

func TestOAuthTokenEncrypter_EncryptAccessToken_EmptyToken(t *testing.T) {
	secret := "test-secret-key"
	encrypter, err := NewOAuthTokenEncrypter(secret)
	require.NoError(t, err)

	encrypted, err := encrypter.EncryptAccessToken("")
	assert.Error(t, err)
	assert.Empty(t, encrypted)
}

func TestOAuthTokenEncrypter_DecryptAccessToken(t *testing.T) {
	secret := "test-secret-key"
	encrypter, err := NewOAuthTokenEncrypter(secret)
	require.NoError(t, err)

	originalToken := "access_token_12345"
	encrypted, err := encrypter.EncryptAccessToken(originalToken)
	require.NoError(t, err)

	decrypted, err := encrypter.DecryptAccessToken(encrypted)
	require.NoError(t, err)
	assert.Equal(t, originalToken, decrypted)
}

func TestOAuthTokenEncrypter_DecryptAccessToken_InvalidCiphertext(t *testing.T) {
	secret := "test-secret-key"
	encrypter, err := NewOAuthTokenEncrypter(secret)
	require.NoError(t, err)

	decrypted, err := encrypter.DecryptAccessToken(base64.StdEncoding.EncodeToString([]byte("invalid")))
	assert.Error(t, err)
	assert.Empty(t, decrypted)
}

func TestOAuthTokenEncrypter_EncryptRefreshToken(t *testing.T) {
	secret := "test-secret-key"
	encrypter, err := NewOAuthTokenEncrypter(secret)
	require.NoError(t, err)

	token := "refresh_token_98765"
	encrypted, err := encrypter.EncryptRefreshToken(token)
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)
	assert.NotEqual(t, token, encrypted)
}

func TestOAuthTokenEncrypter_DecryptRefreshToken(t *testing.T) {
	secret := "test-secret-key"
	encrypter, err := NewOAuthTokenEncrypter(secret)
	require.NoError(t, err)

	originalToken := "refresh_token_98765"
	encrypted, err := encrypter.EncryptRefreshToken(originalToken)
	require.NoError(t, err)

	decrypted, err := encrypter.DecryptRefreshToken(encrypted)
	require.NoError(t, err)
	assert.Equal(t, originalToken, decrypted)
}

func TestOAuthTokenEncrypter_EncryptIDToken(t *testing.T) {
	secret := "test-secret-key"
	encrypter, err := NewOAuthTokenEncrypter(secret)
	require.NoError(t, err)

	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
	encrypted, err := encrypter.EncryptIDToken(token)
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)
	assert.NotEqual(t, token, encrypted)
}

func TestOAuthTokenEncrypter_DecryptIDToken(t *testing.T) {
	secret := "test-secret-key"
	encrypter, err := NewOAuthTokenEncrypter(secret)
	require.NoError(t, err)

	originalToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
	encrypted, err := encrypter.EncryptIDToken(originalToken)
	require.NoError(t, err)

	decrypted, err := encrypter.DecryptIDToken(encrypted)
	require.NoError(t, err)
	assert.Equal(t, originalToken, decrypted)
}

func TestOAuthTokenEncrypter_EncryptTokens(t *testing.T) {
	secret := "test-secret-key"
	encrypter, err := NewOAuthTokenEncrypter(secret)
	require.NoError(t, err)

	accessToken := "access_token_123"
	refreshToken := "refresh_token_456"
	idToken := "id_token_789"
	expiresAt := time.Now().Add(time.Hour).Unix()

	data := &OAuthTokenData{
		AccessToken:          &accessToken,
		RefreshToken:         &refreshToken,
		IDToken:              &idToken,
		AccessTokenExpiresAt: &expiresAt,
	}

	encrypted, err := encrypter.EncryptTokens(data)
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)
}

func TestOAuthTokenEncrypter_EncryptTokens_Nil(t *testing.T) {
	secret := "test-secret-key"
	encrypter, err := NewOAuthTokenEncrypter(secret)
	require.NoError(t, err)

	encrypted, err := encrypter.EncryptTokens(nil)
	assert.Error(t, err)
	assert.Empty(t, encrypted)
}

func TestOAuthTokenEncrypter_DecryptTokens(t *testing.T) {
	secret := "test-secret-key"
	encrypter, err := NewOAuthTokenEncrypter(secret)
	require.NoError(t, err)

	accessToken := "access_token_123"
	refreshToken := "refresh_token_456"
	idToken := "id_token_789"
	expiresAt := time.Now().Add(time.Hour).Unix()

	originalData := &OAuthTokenData{
		AccessToken:          &accessToken,
		RefreshToken:         &refreshToken,
		IDToken:              &idToken,
		AccessTokenExpiresAt: &expiresAt,
	}

	encrypted, err := encrypter.EncryptTokens(originalData)
	require.NoError(t, err)

	decrypted, err := encrypter.DecryptTokens(encrypted)
	require.NoError(t, err)
	assert.Equal(t, originalData.AccessToken, decrypted.AccessToken)
	assert.Equal(t, originalData.RefreshToken, decrypted.RefreshToken)
	assert.Equal(t, originalData.IDToken, decrypted.IDToken)
	assert.Equal(t, originalData.AccessTokenExpiresAt, decrypted.AccessTokenExpiresAt)
}

func TestOAuthTokenEncrypter_DecryptTokens_InvalidData(t *testing.T) {
	secret := "test-secret-key"
	encrypter, err := NewOAuthTokenEncrypter(secret)
	require.NoError(t, err)

	decrypted, err := encrypter.DecryptTokens(base64.StdEncoding.EncodeToString([]byte("invalid")))
	assert.Error(t, err)
	assert.Nil(t, decrypted)
}

func TestOAuthTokenEncrypter_DifferentSecrets(t *testing.T) {
	secret1 := "secret-key-1"
	secret2 := "secret-key-2"

	encrypter1, err := NewOAuthTokenEncrypter(secret1)
	require.NoError(t, err)

	encrypter2, err := NewOAuthTokenEncrypter(secret2)
	require.NoError(t, err)

	token := "access_token_xyz"
	encrypted, err := encrypter1.EncryptAccessToken(token)
	require.NoError(t, err)

	// Trying to decrypt with different secret should fail
	decrypted, err := encrypter2.DecryptAccessToken(encrypted)
	assert.Error(t, err)
	assert.Empty(t, decrypted)
}

func TestOAuthTokenEncrypter_MultipleEncryptions(t *testing.T) {
	secret := "test-secret-key"
	encrypter, err := NewOAuthTokenEncrypter(secret)
	require.NoError(t, err)

	token1 := "token_1"
	token2 := "token_2"

	encrypted1, err := encrypter.EncryptAccessToken(token1)
	require.NoError(t, err)

	encrypted2, err := encrypter.EncryptAccessToken(token2)
	require.NoError(t, err)

	// Same plaintext should produce different ciphertexts (due to random nonce)
	assert.NotEqual(t, encrypted1, encrypted2)

	// But both should decrypt correctly
	decrypted1, err := encrypter.DecryptAccessToken(encrypted1)
	require.NoError(t, err)
	assert.Equal(t, token1, decrypted1)

	decrypted2, err := encrypter.DecryptAccessToken(encrypted2)
	require.NoError(t, err)
	assert.Equal(t, token2, decrypted2)
}
