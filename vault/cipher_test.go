package vault

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCipherManager_ValidSecret(t *testing.T) {
	secret := "my-super-secret-key-12345"
	cm, err := NewCipherManager(secret)

	assert.NoError(t, err)
	assert.NotNil(t, cm)
	assert.NotNil(t, cm.encrypter)
	assert.NotNil(t, cm.signer)
}

func TestNewCipherManager_EmptySecret(t *testing.T) {
	cm, err := NewCipherManager("")

	assert.Error(t, err)
	assert.Nil(t, cm)
}

func TestDeriveKey_Consistency(t *testing.T) {
	secret := "test-secret"

	key1 := deriveKey(secret, "context", 32)
	key2 := deriveKey(secret, "context", 32)

	assert.Equal(t, key1, key2)
	assert.Equal(t, 32, len(key1))
}

func TestDeriveKey_DifferentContexts(t *testing.T) {
	secret := "test-secret"

	key1 := deriveKey(secret, "encryption", 32)
	key2 := deriveKey(secret, "signing", 32)

	assert.NotEqual(t, key1, key2)
}

func TestDeriveKey_VariousLengths(t *testing.T) {
	secret := "test-secret"

	lengths := []int{16, 32, 64, 128}
	for _, length := range lengths {
		key := deriveKey(secret, "context", length)
		assert.Equal(t, length, len(key), "key should be %d bytes", length)
	}
}

func TestCipherManagerEncrypt_Success(t *testing.T) {
	cm, _ := NewCipherManager("test-secret")

	plaintext := "hello world"
	encrypted, err := cm.Encrypt(plaintext)

	assert.NoError(t, err)
	assert.NotEmpty(t, encrypted)
	assert.NotEqual(t, plaintext, encrypted)
	assert.Contains(t, encrypted, ".")
}

func TestCipherManagerEncrypt_EmptyPlaintext(t *testing.T) {
	cm, _ := NewCipherManager("test-secret")

	encrypted, err := cm.Encrypt("")

	assert.Error(t, err)
	assert.Empty(t, encrypted)
}

func TestCipherManagerEncryptDecrypt_Roundtrip(t *testing.T) {
	cm, _ := NewCipherManager("test-secret")

	plaintext := "secret message"
	encrypted, err := cm.Encrypt(plaintext)
	require.NoError(t, err)

	decrypted, err := cm.Decrypt(encrypted)
	require.NoError(t, err)

	assert.Equal(t, plaintext, decrypted)
}

func TestCipherManagerEncryptDecrypt_MultipleMessages(t *testing.T) {
	cm, _ := NewCipherManager("test-secret")

	messages := []string{
		"short",
		"a longer message with more content",
		`{"user_id":"123","email":"test@example.com","role":"admin"}`,
		"message with special chars: !@#$%^&*()",
	}

	for _, message := range messages {
		t.Run(message, func(t *testing.T) {
			encrypted, err := cm.Encrypt(message)
			require.NoError(t, err)

			decrypted, err := cm.Decrypt(encrypted)
			require.NoError(t, err)

			assert.Equal(t, message, decrypted)
		})
	}
}

func TestCipherManagerDecrypt_InvalidFormat(t *testing.T) {
	cm, _ := NewCipherManager("test-secret")

	tests := []struct {
		name string
		data string
	}{
		{"empty", ""},
		{"no signature", "onlyencrypted"},
		{"invalid format", "data.with.multiple.dots"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := cm.Decrypt(tt.data)
			assert.Error(t, err)
		})
	}
}

func TestCipherManagerDecrypt_TamperedData(t *testing.T) {
	cm, _ := NewCipherManager("test-secret")

	plaintext := "original message"
	encrypted, _ := cm.Encrypt(plaintext)

	// Tamper with the ciphertext (change first character)
	tamperedData := "x" + encrypted[1:]

	_, err := cm.Decrypt(tamperedData)
	assert.Error(t, err)
}

func TestCipherManagerDecrypt_WrongSecret(t *testing.T) {
	cm1, _ := NewCipherManager("secret1")
	cm2, _ := NewCipherManager("secret2")

	plaintext := "message"
	encrypted, _ := cm1.Encrypt(plaintext)

	// Try to decrypt with different secret
	_, err := cm2.Decrypt(encrypted)
	assert.Error(t, err)
}

func TestCipherManagerEncryptBytes_Success(t *testing.T) {
	cm, _ := NewCipherManager("test-secret")

	plaintext := []byte("binary data")
	encrypted, err := cm.EncryptBytes(plaintext)

	assert.NoError(t, err)
	assert.NotEmpty(t, encrypted)
	assert.NotEqual(t, plaintext, encrypted)
}

func TestCipherManagerEncryptBytes_EmptyData(t *testing.T) {
	cm, _ := NewCipherManager("test-secret")

	encrypted, err := cm.EncryptBytes([]byte{})

	assert.Error(t, err)
	assert.Nil(t, encrypted)
}

func TestCipherManagerEncryptBytesDecryptBytes_Roundtrip(t *testing.T) {
	cm, _ := NewCipherManager("test-secret")

	plaintext := []byte("binary message data")
	encrypted, err := cm.EncryptBytes(plaintext)
	require.NoError(t, err)

	decrypted, err := cm.DecryptBytes(encrypted)
	require.NoError(t, err)

	assert.Equal(t, plaintext, decrypted)
}

func TestCipherManagerEncryptBytesDecryptBytes_LargeData(t *testing.T) {
	cm, _ := NewCipherManager("test-secret")

	// Create 10MB of data
	plaintext := make([]byte, 10*1024*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	encrypted, err := cm.EncryptBytes(plaintext)
	require.NoError(t, err)

	decrypted, err := cm.DecryptBytes(encrypted)
	require.NoError(t, err)

	assert.Equal(t, plaintext, decrypted)
}

func TestCipherManagerDecryptBytes_InvalidData(t *testing.T) {
	cm, _ := NewCipherManager("test-secret")

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"too short", []byte("short")},
		{"random", []byte("this is just random data that is not encrypted properly")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := cm.DecryptBytes(tt.data)
			assert.Error(t, err)
		})
	}
}

func TestCipherManagerHash_Success(t *testing.T) {
	cm, _ := NewCipherManager("test-secret")

	data := "data to hash"
	hash := cm.Hash(data)

	assert.NotEmpty(t, hash)
	assert.NotEqual(t, data, hash)
}

func TestCipherManagerHash_Consistency(t *testing.T) {
	cm, _ := NewCipherManager("test-secret")

	data := "consistent data"
	hash1 := cm.Hash(data)
	hash2 := cm.Hash(data)

	assert.Equal(t, hash1, hash2)
}

func TestCipherManagerHash_DifferentInputs(t *testing.T) {
	cm, _ := NewCipherManager("test-secret")

	hash1 := cm.Hash("input1")
	hash2 := cm.Hash("input2")

	assert.NotEqual(t, hash1, hash2)
}

func TestGetSigner(t *testing.T) {
	cm, _ := NewCipherManager("test-secret")

	signer := cm.GetSigner()
	assert.NotNil(t, signer)

	// Verify it works
	sig, err := signer.Sign("test")
	assert.NoError(t, err)
	assert.NotEmpty(t, sig)
}

func TestGetEncrypter(t *testing.T) {
	cm, _ := NewCipherManager("test-secret")

	encrypter := cm.GetEncrypter()
	assert.NotNil(t, encrypter)

	// Verify it works
	encrypted, err := encrypter.Encrypt("test")
	assert.NoError(t, err)
	assert.NotEmpty(t, encrypted)
}

func TestCipherManager_SignatureProtection(t *testing.T) {
	cm, _ := NewCipherManager("test-secret")

	plaintext := "important data"
	encrypted, _ := cm.Encrypt(plaintext)

	// Tamper with the signature part
	idx := len(encrypted) - 1
	for idx > 0 && encrypted[idx-1] != '.' {
		idx--
	}
	if idx > 0 {
		// Change one character in the signature
		tamperedSig := encrypted[:idx] + "x" + encrypted[idx+1:]
		_, err := cm.Decrypt(tamperedSig)
		assert.Error(t, err)
	}
}

func TestCipherManager_DifferentSecretsProduceDifferentKeys(t *testing.T) {
	cm1, _ := NewCipherManager("secret1")
	cm2, _ := NewCipherManager("secret2")

	plaintext := "test"
	encrypted2, _ := cm2.Encrypt(plaintext)

	// Even though it's the same plaintext, cm1 shouldn't be able to decrypt cm2's encryption
	_, err := cm1.Decrypt(encrypted2)
	assert.Error(t, err)
}

func TestCipherManager_StressTest(t *testing.T) {
	cm, _ := NewCipherManager("test-secret")

	// Encrypt and decrypt 1000 different messages
	for i := 0; i < 1000; i++ {
		plaintext := "message number 1000000" // Will be formatted with i
		encrypted, err := cm.Encrypt(plaintext)
		assert.NoError(t, err)

		decrypted, err := cm.Decrypt(encrypted)
		assert.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	}
}
