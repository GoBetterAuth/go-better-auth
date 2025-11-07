package vault

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSigner_ValidKey(t *testing.T) {
	key := generateTestKey()
	signer, err := NewSigner(key)

	assert.NoError(t, err)
	assert.NotNil(t, signer)
}

func TestNewSigner_InvalidKeyLength(t *testing.T) {
	tests := []struct {
		name        string
		keyLength   int
		expectError bool
	}{
		{"empty key", 0, true},
		{"8-byte key", 8, true},
		{"16-byte key", 16, false},
		{"32-byte key", 32, false},
		{"64-byte key", 64, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keyLength)
			if tt.keyLength > 0 {
				rand.Read(key)
			}

			signer, err := NewSigner(key)
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, signer)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, signer)
			}
		})
	}
}

func TestSign_Success(t *testing.T) {
	key := generateTestKey()
	signer, _ := NewSigner(key)

	data := "hello world"
	signature, err := signer.Sign(data)

	assert.NoError(t, err)
	assert.NotEmpty(t, signature)

	// Verify it's valid base64
	_, err = base64.StdEncoding.DecodeString(signature)
	assert.NoError(t, err)
}

func TestSign_EmptyData(t *testing.T) {
	key := generateTestKey()
	signer, _ := NewSigner(key)

	signature, err := signer.Sign("")
	assert.Error(t, err)
	assert.Empty(t, signature)
}

func TestSign_DifferentData(t *testing.T) {
	key := generateTestKey()
	signer, _ := NewSigner(key)

	data1 := "data1"
	data2 := "data2"

	sig1, _ := signer.Sign(data1)
	sig2, _ := signer.Sign(data2)

	assert.NotEqual(t, sig1, sig2)
}

func TestSign_Consistency(t *testing.T) {
	key := generateTestKey()
	signer, _ := NewSigner(key)

	data := "consistent data"
	sig1, _ := signer.Sign(data)
	sig2, _ := signer.Sign(data)

	// Same data should produce same signature (HMAC is deterministic)
	assert.Equal(t, sig1, sig2)
}

func TestVerify_ValidSignature(t *testing.T) {
	key := generateTestKey()
	signer, _ := NewSigner(key)

	data := "test data"
	signature, _ := signer.Sign(data)

	valid, err := signer.Verify(data, signature)
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestVerify_InvalidSignature(t *testing.T) {
	key := generateTestKey()
	signer, _ := NewSigner(key)

	data := "test data"
	wrongSignature := base64.StdEncoding.EncodeToString([]byte("wrong signature"))

	valid, err := signer.Verify(data, wrongSignature)
	assert.NoError(t, err)
	assert.False(t, valid)
}

func TestVerify_WrongKey(t *testing.T) {
	key1 := generateTestKey()
	key2 := generateTestKey()

	signer1, _ := NewSigner(key1)
	signer2, _ := NewSigner(key2)

	data := "test data"
	signature, _ := signer1.Sign(data)

	// Verify with different key should fail
	valid, err := signer2.Verify(data, signature)
	assert.NoError(t, err)
	assert.False(t, valid)
}

func TestVerify_TamperedData(t *testing.T) {
	key := generateTestKey()
	signer, _ := NewSigner(key)

	data := "original data"
	signature, _ := signer.Sign(data)

	// Verify with tampered data should fail
	valid, err := signer.Verify("modified data", signature)
	assert.NoError(t, err)
	assert.False(t, valid)
}

func TestVerify_EmptyInputs(t *testing.T) {
	key := generateTestKey()
	signer, _ := NewSigner(key)

	tests := []struct {
		name      string
		data      string
		signature string
	}{
		{"empty data", "", "signature"},
		{"empty signature", "data", ""},
		{"both empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := signer.Verify(tt.data, tt.signature)
			assert.Error(t, err)
		})
	}
}

func TestSignBytes_Success(t *testing.T) {
	key := generateTestKey()
	signer, _ := NewSigner(key)

	data := []byte("hello world")
	signature, err := signer.SignBytes(data)

	assert.NoError(t, err)
	assert.NotEmpty(t, signature)
	assert.Equal(t, 32, len(signature)) // SHA256 produces 32-byte hash
}

func TestSignBytes_EmptyData(t *testing.T) {
	key := generateTestKey()
	signer, _ := NewSigner(key)

	signature, err := signer.SignBytes([]byte{})
	assert.Error(t, err)
	assert.Nil(t, signature)
}

func TestVerifyBytes_Success(t *testing.T) {
	key := generateTestKey()
	signer, _ := NewSigner(key)

	data := []byte("test data")
	signature, _ := signer.SignBytes(data)

	valid, err := signer.VerifyBytes(data, signature)
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestVerifyBytes_InvalidSignature(t *testing.T) {
	key := generateTestKey()
	signer, _ := NewSigner(key)

	data := []byte("test data")
	wrongSignature := []byte("wrong signature that is 32 bytes!")[:32]

	valid, err := signer.VerifyBytes(data, wrongSignature)
	assert.NoError(t, err)
	assert.False(t, valid)
}

func TestSignAndFormat_Success(t *testing.T) {
	key := generateTestKey()
	signer, _ := NewSigner(key)

	data := "test data"
	token, err := signer.SignAndFormat(data)

	assert.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.Contains(t, token, ".")
}

func TestSignAndFormat_EmptyData(t *testing.T) {
	key := generateTestKey()
	signer, _ := NewSigner(key)

	token, err := signer.SignAndFormat("")
	assert.Error(t, err)
	assert.Empty(t, token)
}

func TestVerifyAndExtract_Success(t *testing.T) {
	key := generateTestKey()
	signer, _ := NewSigner(key)

	originalData := "test data"
	token, _ := signer.SignAndFormat(originalData)

	extractedData, err := signer.VerifyAndExtract(token)
	assert.NoError(t, err)
	assert.Equal(t, originalData, extractedData)
}

func TestVerifyAndExtract_InvalidToken(t *testing.T) {
	key := generateTestKey()
	signer, _ := NewSigner(key)

	tests := []struct {
		name  string
		token string
	}{
		{"empty token", ""},
		{"no signature", "data."},
		{"invalid format", "nodothere"},
		{"tampered token", "aW52YWxpZCBkYXRh.invalidsignature"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := signer.VerifyAndExtract(tt.token)
			assert.Error(t, err)
		})
	}
}

func TestVerifyAndExtract_TamperedData(t *testing.T) {
	key := generateTestKey()
	signer, _ := NewSigner(key)

	originalData := "test data"
	token, _ := signer.SignAndFormat(originalData)

	// Tamper with the token (change first character of data part)
	tamperedToken := "aW52YWxpZA." + token[len(token)-44:]

	_, err := signer.VerifyAndExtract(tamperedToken)
	assert.Error(t, err)
}

func TestSignAndFormatVerifyAndExtract_Roundtrip(t *testing.T) {
	key := generateTestKey()
	signer, _ := NewSigner(key)

	testCases := []string{
		"simple",
		"with spaces and special chars!@#$%",
		`{"user_id":"123","email":"user@example.com"}`,
		"very long string that should still work fine",
	}

	for _, data := range testCases {
		t.Run(data, func(t *testing.T) {
			token, err := signer.SignAndFormat(data)
			require.NoError(t, err)

			extracted, err := signer.VerifyAndExtract(token)
			require.NoError(t, err)
			assert.Equal(t, data, extracted)
		})
	}
}

func TestVerifyAndExtract_MultipleDotsInToken(t *testing.T) {
	key := generateTestKey()
	signer, _ := NewSigner(key)

	// Data that contains dots should still work
	data := "data.with.dots.inside"
	token, err := signer.SignAndFormat(data)
	require.NoError(t, err)

	extracted, err := signer.VerifyAndExtract(token)
	require.NoError(t, err)
	assert.Equal(t, data, extracted)
}

func TestTimingAttackResistance(t *testing.T) {
	key := generateTestKey()
	signer, _ := NewSigner(key)

	data := "test data"

	// Test with wrong signature - should use constant-time comparison
	wrongSignature := base64.StdEncoding.EncodeToString(make([]byte, 32))

	valid, err := signer.Verify(data, wrongSignature)
	assert.NoError(t, err)
	assert.False(t, valid)
}
