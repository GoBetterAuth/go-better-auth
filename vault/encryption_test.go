package vault

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestKey() []byte {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return key
}

func TestNewEncrypter_ValidKey(t *testing.T) {
	key := generateTestKey()
	encrypter, err := NewEncrypter(key)

	assert.NoError(t, err)
	assert.NotNil(t, encrypter)
}

func TestNewEncrypter_InvalidKeyLength(t *testing.T) {
	tests := []struct {
		name        string
		keyLength   int
		expectError bool
	}{
		{"16-byte key", 16, true},
		{"24-byte key", 24, true},
		{"32-byte key", 32, false},
		{"48-byte key", 48, true},
		{"0-byte key", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keyLength)
			rand.Read(key)

			encrypter, err := NewEncrypter(key)
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, encrypter)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, encrypter)
			}
		})
	}
}

func TestEncrypt_Success(t *testing.T) {
	key := generateTestKey()
	encrypter, _ := NewEncrypter(key)

	plaintext := "hello world"
	ciphertext, err := encrypter.Encrypt(plaintext)

	assert.NoError(t, err)
	assert.NotEmpty(t, ciphertext)
	assert.NotEqual(t, plaintext, ciphertext)

	// Verify it's valid base64
	_, err = base64.StdEncoding.DecodeString(ciphertext)
	assert.NoError(t, err)
}

func TestEncrypt_EmptyPlaintext(t *testing.T) {
	key := generateTestKey()
	encrypter, _ := NewEncrypter(key)

	ciphertext, err := encrypter.Encrypt("")
	assert.Error(t, err)
	assert.Empty(t, ciphertext)
}

func TestEncrypt_DifferentPlaintexts(t *testing.T) {
	key := generateTestKey()
	encrypter, _ := NewEncrypter(key)

	plaintexts := []string{
		"short",
		"a much longer plaintext with spaces and special characters!@#$%",
		"password123",
		`{"email":"user@example.com","id":"12345"}`,
	}

	for _, plaintext := range plaintexts {
		ciphertext, err := encrypter.Encrypt(plaintext)
		assert.NoError(t, err)
		assert.NotEmpty(t, ciphertext)
		assert.NotEqual(t, plaintext, ciphertext)
	}
}

func TestEncryptDecrypt_Roundtrip(t *testing.T) {
	key := generateTestKey()
	encrypter, _ := NewEncrypter(key)

	plaintext := "hello world"
	ciphertext, err := encrypter.Encrypt(plaintext)
	require.NoError(t, err)

	decrypted, err := encrypter.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestEncryptDecrypt_MultipleRoundtrips(t *testing.T) {
	key := generateTestKey()
	encrypter, _ := NewEncrypter(key)

	plaintexts := []string{
		"test",
		"longer test message",
		`{"user":"john","email":"john@example.com"}`,
		"special chars: !@#$%^&*()",
	}

	for _, plaintext := range plaintexts {
		t.Run(plaintext, func(t *testing.T) {
			ciphertext, err := encrypter.Encrypt(plaintext)
			require.NoError(t, err)

			decrypted, err := encrypter.Decrypt(ciphertext)
			require.NoError(t, err)
			assert.Equal(t, plaintext, decrypted)
		})
	}
}

func TestEncrypt_GeneratesDifferentCiphertexts(t *testing.T) {
	key := generateTestKey()
	encrypter, _ := NewEncrypter(key)

	plaintext := "same plaintext"
	ciphertext1, _ := encrypter.Encrypt(plaintext)
	ciphertext2, _ := encrypter.Encrypt(plaintext)

	// Due to random nonce, ciphertexts should be different
	assert.NotEqual(t, ciphertext1, ciphertext2)

	// But both should decrypt to the same plaintext
	decrypted1, _ := encrypter.Decrypt(ciphertext1)
	decrypted2, _ := encrypter.Decrypt(ciphertext2)
	assert.Equal(t, plaintext, decrypted1)
	assert.Equal(t, plaintext, decrypted2)
}

func TestDecrypt_InvalidCiphertext(t *testing.T) {
	key := generateTestKey()
	encrypter, _ := NewEncrypter(key)

	tests := []struct {
		name       string
		ciphertext string
	}{
		{"empty ciphertext", ""},
		{"invalid base64", "!!!invalid!!!"},
		{"too short", base64.StdEncoding.EncodeToString([]byte("short"))},
		{"random garbage", base64.StdEncoding.EncodeToString([]byte("random data that is not encrypted"))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encrypter.Decrypt(tt.ciphertext)
			assert.Error(t, err)
		})
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	key1 := generateTestKey()
	key2 := generateTestKey()

	encrypter1, _ := NewEncrypter(key1)
	encrypter2, _ := NewEncrypter(key2)

	plaintext := "secret message"
	ciphertext, _ := encrypter1.Encrypt(plaintext)

	// Trying to decrypt with different key should fail
	_, err := encrypter2.Decrypt(ciphertext)
	assert.Error(t, err)
}

func TestEncryptBytes_Success(t *testing.T) {
	key := generateTestKey()
	encrypter, _ := NewEncrypter(key)

	plaintext := []byte("hello world")
	ciphertext, err := encrypter.EncryptBytes(plaintext)

	assert.NoError(t, err)
	assert.NotEmpty(t, ciphertext)
	assert.NotEqual(t, plaintext, ciphertext)
}

func TestEncryptBytes_EmptyData(t *testing.T) {
	key := generateTestKey()
	encrypter, _ := NewEncrypter(key)

	ciphertext, err := encrypter.EncryptBytes([]byte{})
	assert.Error(t, err)
	assert.Nil(t, ciphertext)
}

func TestEncryptBytesDecryptBytes_Roundtrip(t *testing.T) {
	key := generateTestKey()
	encrypter, _ := NewEncrypter(key)

	plaintext := []byte("hello world with bytes")
	ciphertext, err := encrypter.EncryptBytes(plaintext)
	require.NoError(t, err)

	decrypted, err := encrypter.DecryptBytes(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestDecryptBytes_InvalidCiphertext(t *testing.T) {
	key := generateTestKey()
	encrypter, _ := NewEncrypter(key)

	tests := []struct {
		name       string
		ciphertext []byte
	}{
		{"empty ciphertext", []byte{}},
		{"too short", []byte("short")},
		{"invalid data", []byte("random data that is not encrypted properly with aes")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encrypter.DecryptBytes(tt.ciphertext)
			assert.Error(t, err)
		})
	}
}

func TestEncryptDecrypt_LargeData(t *testing.T) {
	key := generateTestKey()
	encrypter, _ := NewEncrypter(key)

	// Create a large plaintext (1MB)
	plaintext := make([]byte, 1024*1024)
	rand.Read(plaintext)

	ciphertext, err := encrypter.EncryptBytes(plaintext)
	require.NoError(t, err)

	decrypted, err := encrypter.DecryptBytes(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestEncryptDecrypt_StringVsBytes(t *testing.T) {
	key := generateTestKey()
	encrypter, _ := NewEncrypter(key)

	plaintext := "test message for comparison"
	plaintextBytes := []byte(plaintext)

	// Encrypt as string
	ciphertextStr, _ := encrypter.Encrypt(plaintext)
	decryptedStr, _ := encrypter.Decrypt(ciphertextStr)

	// Encrypt as bytes
	ciphertextBytes, _ := encrypter.EncryptBytes(plaintextBytes)
	decryptedBytes, _ := encrypter.DecryptBytes(ciphertextBytes)

	assert.Equal(t, plaintext, decryptedStr)
	assert.Equal(t, plaintextBytes, decryptedBytes)
	assert.Equal(t, plaintext, string(decryptedBytes))
}
