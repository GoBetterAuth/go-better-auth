package vault

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// CipherManager is a high-level interface that combines encryption and signing
// It derives separate keys for encryption and signing from a base secret using HKDF
type CipherManager struct {
	encrypter *Encrypter
	signer    *Signer
}

// NewCipherManager creates a new cipher manager from a base secret string
// It derives encryption and signing keys from the secret using SHA256-based key derivation
func NewCipherManager(secret string) (*CipherManager, error) {
	if secret == "" {
		return nil, fmt.Errorf("secret cannot be empty")
	}

	// Derive keys from the secret
	encryptionKey := deriveKey(secret, "encryption", 32)
	signingKey := deriveKey(secret, "signing", 32)

	// Create encrypter and signer
	encrypter, err := NewEncrypter(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create encrypter: %w", err)
	}

	signer, err := NewSigner(signingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	return &CipherManager{
		encrypter: encrypter,
		signer:    signer,
	}, nil
}

// deriveKey derives a cryptographic key from a secret and context using SHA256
// This is a simple HKDF-like approach for key derivation
func deriveKey(secret, context string, length int) []byte {
	h := sha256.New()
	h.Write([]byte(secret))
	h.Write([]byte(context))

	hash := h.Sum(nil)

	// If we need more bytes than SHA256 produces, hash again with counter
	result := hash
	counter := 1
	for len(result) < length {
		h := sha256.New()
		h.Write([]byte(secret))
		h.Write([]byte(context))
		h.Write([]byte{byte(counter)})
		result = append(result, h.Sum(nil)...)
		counter++
	}

	return result[:length]
}

// Encrypt encrypts plaintext and signs the ciphertext for integrity
// Returns encrypted data and a signature in the format: base64(ciphertext).base64(signature)
func (cm *CipherManager) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", fmt.Errorf("plaintext cannot be empty")
	}

	// Encrypt the data
	ciphertext, err := cm.encrypter.Encrypt(plaintext)
	if err != nil {
		return "", err
	}

	// Sign the ciphertext for integrity
	signature, err := cm.signer.Sign(ciphertext)
	if err != nil {
		return "", err
	}

	// Return in format: ciphertext.signature
	return ciphertext + "." + signature, nil
}

// Decrypt verifies the signature and decrypts the data
// Input should be in the format created by Encrypt: ciphertext.signature
func (cm *CipherManager) Decrypt(encryptedData string) (string, error) {
	if encryptedData == "" {
		return "", fmt.Errorf("encrypted data cannot be empty")
	}

	// Split on last dot
	lastDotIndex := -1
	for i := len(encryptedData) - 1; i >= 0; i-- {
		if encryptedData[i] == '.' {
			lastDotIndex = i
			break
		}
	}

	if lastDotIndex == -1 {
		return "", fmt.Errorf("invalid format: missing signature separator")
	}

	ciphertext := encryptedData[:lastDotIndex]
	signature := encryptedData[lastDotIndex+1:]

	// Verify the signature
	valid, err := cm.signer.Verify(ciphertext, signature)
	if err != nil {
		return "", fmt.Errorf("signature verification error: %w", err)
	}

	if !valid {
		return "", fmt.Errorf("signature verification failed: data may have been tampered with")
	}

	// Decrypt the data
	plaintext, err := cm.encrypter.Decrypt(ciphertext)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// EncryptBytes encrypts raw bytes and signs the ciphertext
// Returns encrypted data as bytes
func (cm *CipherManager) EncryptBytes(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("plaintext cannot be empty")
	}

	// Encrypt the data
	ciphertext, err := cm.encrypter.EncryptBytes(plaintext)
	if err != nil {
		return nil, err
	}

	// Sign the ciphertext for integrity
	signature, err := cm.signer.SignBytes(ciphertext)
	if err != nil {
		return nil, err
	}

	// Combine ciphertext and signature: ciphertext + signature (no separator for binary)
	// Use length prefix to separate them
	result := make([]byte, 4+len(ciphertext)+len(signature))
	result[0] = byte(len(ciphertext) >> 24)
	result[1] = byte(len(ciphertext) >> 16)
	result[2] = byte(len(ciphertext) >> 8)
	result[3] = byte(len(ciphertext))
	copy(result[4:], ciphertext)
	copy(result[4+len(ciphertext):], signature)

	return result, nil
}

// DecryptBytes verifies the signature and decrypts the data
func (cm *CipherManager) DecryptBytes(encryptedData []byte) ([]byte, error) {
	if len(encryptedData) < 4+16+32 { // 4 bytes length + min ciphertext + signature
		return nil, fmt.Errorf("encrypted data too short")
	}

	// Extract ciphertext length (first 4 bytes, big-endian)
	ciphertextLen := (int(encryptedData[0]) << 24) | (int(encryptedData[1]) << 16) | (int(encryptedData[2]) << 8) | int(encryptedData[3])

	if ciphertextLen < 12 || ciphertextLen > len(encryptedData)-4 {
		return nil, fmt.Errorf("invalid ciphertext length")
	}

	// Extract ciphertext and signature
	ciphertext := encryptedData[4 : 4+ciphertextLen]
	signature := encryptedData[4+ciphertextLen:]

	if len(signature) != 32 { // SHA256 produces 32 bytes
		return nil, fmt.Errorf("invalid signature size")
	}

	// Verify the signature
	valid, err := cm.signer.VerifyBytes(ciphertext, signature)
	if err != nil {
		return nil, fmt.Errorf("signature verification error: %w", err)
	}

	if !valid {
		return nil, fmt.Errorf("signature verification failed: data may have been tampered with")
	}

	// Decrypt the data
	plaintext, err := cm.encrypter.DecryptBytes(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// Hash generates a SHA256 hash of the data and returns it as base64
// Useful for one-way hashing like passwords, tokens, etc.
func (cm *CipherManager) Hash(data string) string {
	h := sha256.New()
	h.Write([]byte(data))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// GetSigner returns the signer for low-level signing operations
func (cm *CipherManager) GetSigner() *Signer {
	return cm.signer
}

// GetEncrypter returns the encrypter for low-level encryption operations
func (cm *CipherManager) GetEncrypter() *Encrypter {
	return cm.encrypter
}
