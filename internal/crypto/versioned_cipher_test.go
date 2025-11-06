package crypto

import (
	"strings"
	"testing"
)

func TestVersionedCipherManager_NewVersionedCipherManager(t *testing.T) {
	secret := "test-secret-key-for-testing"

	vcm, err := NewVersionedCipherManager(secret, 5)
	if err != nil {
		t.Fatalf("failed to create versioned cipher manager: %v", err)
	}

	if vcm.GetCurrentVersion() != 1 {
		t.Errorf("expected current version to be 1, got %d", vcm.GetCurrentVersion())
	}

	versions := vcm.GetAvailableVersions()
	if len(versions) != 1 || versions[0] != 1 {
		t.Errorf("expected available versions to be [1], got %v", versions)
	}
}

func TestVersionedCipherManager_NewVersionedCipherManager_EmptySecret(t *testing.T) {
	_, err := NewVersionedCipherManager("", 5)
	if err == nil {
		t.Error("expected error for empty secret")
	}
}

func TestVersionedCipherManager_EncryptDecrypt(t *testing.T) {
	secret := "test-secret-key-for-testing"
	plaintext := "hello world test message"

	vcm, err := NewVersionedCipherManager(secret, 5)
	if err != nil {
		t.Fatalf("failed to create versioned cipher manager: %v", err)
	}

	encrypted, err := vcm.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	// Check that encrypted data has version prefix
	if !strings.HasPrefix(encrypted, "v1.") {
		t.Errorf("expected encrypted data to have version prefix 'v1.', got: %s", encrypted[:10])
	}

	decrypted, err := vcm.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("expected decrypted text to be '%s', got '%s'", plaintext, decrypted)
	}
}

func TestVersionedCipherManager_SecretRotation(t *testing.T) {
	secret1 := "test-secret-key-1"
	secret2 := "test-secret-key-2"
	plaintext := "test message for rotation"

	vcm, err := NewVersionedCipherManager(secret1, 5)
	if err != nil {
		t.Fatalf("failed to create versioned cipher manager: %v", err)
	}

	// Encrypt with version 1
	encrypted1, err := vcm.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt with version 1: %v", err)
	}

	// Add new secret (version 2)
	err = vcm.AddSecret(secret2)
	if err != nil {
		t.Fatalf("failed to add new secret: %v", err)
	}

	// Check current version is now 2
	if vcm.GetCurrentVersion() != 2 {
		t.Errorf("expected current version to be 2, got %d", vcm.GetCurrentVersion())
	}

	// Encrypt with version 2
	encrypted2, err := vcm.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt with version 2: %v", err)
	}

	// Check version prefixes
	if !strings.HasPrefix(encrypted1, "v1.") {
		t.Errorf("expected encrypted1 to have version prefix 'v1.', got: %s", encrypted1[:10])
	}
	if !strings.HasPrefix(encrypted2, "v2.") {
		t.Errorf("expected encrypted2 to have version prefix 'v2.', got: %s", encrypted2[:10])
	}

	// Both should decrypt successfully
	decrypted1, err := vcm.Decrypt(encrypted1)
	if err != nil {
		t.Fatalf("failed to decrypt version 1: %v", err)
	}

	decrypted2, err := vcm.Decrypt(encrypted2)
	if err != nil {
		t.Fatalf("failed to decrypt version 2: %v", err)
	}

	if decrypted1 != plaintext || decrypted2 != plaintext {
		t.Errorf("decryption mismatch: got '%s' and '%s', expected '%s'", decrypted1, decrypted2, plaintext)
	}

	// Check available versions
	versions := vcm.GetAvailableVersions()
	if len(versions) != 2 {
		t.Errorf("expected 2 available versions, got %v", versions)
	}
}

func TestVersionedCipherManager_MaxVersions(t *testing.T) {
	secret := "test-secret-key"
	maxVersions := 3

	vcm, err := NewVersionedCipherManager(secret, maxVersions)
	if err != nil {
		t.Fatalf("failed to create versioned cipher manager: %v", err)
	}

	// Add secrets up to maxVersions + 2 (should keep only maxVersions)
	for i := 2; i <= 5; i++ {
		err = vcm.AddSecret(secret + string(rune('0'+i)))
		if err != nil {
			t.Fatalf("failed to add secret version %d: %v", i, err)
		}
	}

	// Should have maxVersions available versions (versions 3, 4, 5)
	versions := vcm.GetAvailableVersions()
	if len(versions) != maxVersions {
		t.Errorf("expected %d available versions, got %d: %v", maxVersions, len(versions), versions)
	}

	// Current version should be 5
	if vcm.GetCurrentVersion() != 5 {
		t.Errorf("expected current version to be 5, got %d", vcm.GetCurrentVersion())
	}
}

func TestVersionedCipherManager_EncryptDecryptBytes(t *testing.T) {
	secret := "test-secret-key-for-bytes"
	plaintext := []byte("binary data test message 🚀")

	vcm, err := NewVersionedCipherManager(secret, 5)
	if err != nil {
		t.Fatalf("failed to create versioned cipher manager: %v", err)
	}

	encrypted, err := vcm.EncryptBytes(plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt bytes: %v", err)
	}

	// Check that encrypted data has version prefix (first 4 bytes)
	if len(encrypted) < 4 {
		t.Fatalf("encrypted data too short: %d bytes", len(encrypted))
	}

	// Version should be 1 (0x00000001)
	expectedVersion := []byte{0x00, 0x00, 0x00, 0x01}
	if !bytesEqual(encrypted[:4], expectedVersion) {
		t.Errorf("expected version bytes %v, got %v", expectedVersion, encrypted[:4])
	}

	decrypted, err := vcm.DecryptBytes(encrypted)
	if err != nil {
		t.Fatalf("failed to decrypt bytes: %v", err)
	}

	if !bytesEqual(decrypted, plaintext) {
		t.Errorf("decrypted bytes don't match original: got %v, expected %v", decrypted, plaintext)
	}
}

func TestVersionedCipherManager_InvalidVersion(t *testing.T) {
	secret := "test-secret-key"

	vcm, err := NewVersionedCipherManager(secret, 5)
	if err != nil {
		t.Fatalf("failed to create versioned cipher manager: %v", err)
	}

	// Try to decrypt data with invalid version prefix
	invalidData := "v999.someencrypteddata"
	_, err = vcm.Decrypt(invalidData)
	if err == nil {
		t.Error("expected error for unknown version")
	}

	if !strings.Contains(err.Error(), "unknown encryption version") {
		t.Errorf("expected error about unknown version, got: %v", err)
	}
}

func TestVersionedCipherManager_InvalidFormat(t *testing.T) {
	secret := "test-secret-key"

	vcm, err := NewVersionedCipherManager(secret, 5)
	if err != nil {
		t.Fatalf("failed to create versioned cipher manager: %v", err)
	}

	testCases := []struct {
		name string
		data string
	}{
		{"no version prefix", "someencrypteddata"},
		{"no separator", "v1someencrypteddata"},
		{"invalid version", "vabc.someencrypteddata"},
		{"negative version", "v-1.someencrypteddata"},
		{"zero version", "v0.someencrypteddata"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := vcm.Decrypt(tc.data)
			if err == nil {
				t.Errorf("expected error for invalid format: %s", tc.data)
			}
		})
	}
}

// Helper function to compare byte slices
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
