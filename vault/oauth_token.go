package vault

import (
	"encoding/json"
	"fmt"
)

// OAuthTokenData represents encrypted OAuth token data
type OAuthTokenData struct {
	AccessToken           *string `json:"access_token,omitempty"`
	RefreshToken          *string `json:"refresh_token,omitempty"`
	IDToken               *string `json:"id_token,omitempty"`
	AccessTokenExpiresAt  *int64  `json:"access_token_expires_at,omitempty"`
	RefreshTokenExpiresAt *int64  `json:"refresh_token_expires_at,omitempty"`
	Scope                 *string `json:"scope,omitempty"`
}

// OAuthTokenEncrypter provides encryption/decryption for OAuth tokens
type OAuthTokenEncrypter struct {
	encrypter *Encrypter
}

// NewOAuthTokenEncrypter creates a new OAuth token encrypter
func NewOAuthTokenEncrypter(secretStr string) (*OAuthTokenEncrypter, error) {
	if secretStr == "" {
		return nil, fmt.Errorf("secret cannot be empty")
	}

	// Generate a 32-byte key from the secret using SHA-256
	key := deriveKey(secretStr, "oauth-token", 32)

	encrypter, err := NewEncrypter(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create encrypter: %w", err)
	}

	return &OAuthTokenEncrypter{
		encrypter: encrypter,
	}, nil
}

// EncryptTokens encrypts OAuth token data and returns a single encrypted string
func (ote *OAuthTokenEncrypter) EncryptTokens(data *OAuthTokenData) (string, error) {
	if data == nil {
		return "", fmt.Errorf("token data cannot be nil")
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal token data: %w", err)
	}

	// Encrypt the JSON
	encrypted, err := ote.encrypter.Encrypt(string(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt tokens: %w", err)
	}

	return encrypted, nil
}

// DecryptTokens decrypts an encrypted token string and returns the token data
func (ote *OAuthTokenEncrypter) DecryptTokens(encryptedData string) (*OAuthTokenData, error) {
	if encryptedData == "" {
		return nil, fmt.Errorf("encrypted data cannot be empty")
	}

	// Decrypt
	decrypted, err := ote.encrypter.Decrypt(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt tokens: %w", err)
	}

	// Unmarshal JSON
	var data OAuthTokenData
	err = json.Unmarshal([]byte(decrypted), &data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal token data: %w", err)
	}

	return &data, nil
}

// EncryptAccessToken encrypts just the access token
func (ote *OAuthTokenEncrypter) EncryptAccessToken(token string) (string, error) {
	if token == "" {
		return "", fmt.Errorf("token cannot be empty")
	}

	return ote.encrypter.Encrypt(token)
}

// DecryptAccessToken decrypts an access token
func (ote *OAuthTokenEncrypter) DecryptAccessToken(encryptedToken string) (string, error) {
	if encryptedToken == "" {
		return "", fmt.Errorf("encrypted token cannot be empty")
	}

	return ote.encrypter.Decrypt(encryptedToken)
}

// EncryptRefreshToken encrypts just the refresh token
func (ote *OAuthTokenEncrypter) EncryptRefreshToken(token string) (string, error) {
	if token == "" {
		return "", fmt.Errorf("token cannot be empty")
	}

	return ote.encrypter.Encrypt(token)
}

// DecryptRefreshToken decrypts a refresh token
func (ote *OAuthTokenEncrypter) DecryptRefreshToken(encryptedToken string) (string, error) {
	if encryptedToken == "" {
		return "", fmt.Errorf("encrypted token cannot be empty")
	}

	return ote.encrypter.Decrypt(encryptedToken)
}

// EncryptIDToken encrypts just the ID token
func (ote *OAuthTokenEncrypter) EncryptIDToken(token string) (string, error) {
	if token == "" {
		return "", fmt.Errorf("token cannot be empty")
	}

	return ote.encrypter.Encrypt(token)
}

// DecryptIDToken decrypts an ID token
func (ote *OAuthTokenEncrypter) DecryptIDToken(encryptedToken string) (string, error) {
	if encryptedToken == "" {
		return "", fmt.Errorf("encrypted token cannot be empty")
	}

	return ote.encrypter.Decrypt(encryptedToken)
}
