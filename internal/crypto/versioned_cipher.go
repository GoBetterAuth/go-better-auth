package crypto

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// VersionedCipherManager supports multiple secrets for seamless secret rotation.
// It can encrypt with the latest secret and decrypt with any configured secret,
// allowing for smooth transitions during secret rotation.
type VersionedCipherManager struct {
	mu             sync.RWMutex
	ciphers        map[int]*CipherManager // version -> cipher
	currentVersion int                    // latest version for encryption
	maxVersions    int                    // maximum number of versions to keep
}

// NewVersionedCipherManager creates a new versioned cipher manager
func NewVersionedCipherManager(initialSecret string, maxVersions int) (*VersionedCipherManager, error) {
	if initialSecret == "" {
		return nil, fmt.Errorf("initial secret cannot be empty")
	}

	if maxVersions <= 0 {
		maxVersions = 5 // Default to keeping 5 versions
	}

	cipher, err := NewCipherManager(initialSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create initial cipher: %w", err)
	}

	return &VersionedCipherManager{
		ciphers:        map[int]*CipherManager{1: cipher},
		currentVersion: 1,
		maxVersions:    maxVersions,
	}, nil
}

// AddSecret adds a new secret version, rotating to use it for new encryptions
func (vcm *VersionedCipherManager) AddSecret(secret string) error {
	if secret == "" {
		return fmt.Errorf("secret cannot be empty")
	}

	cipher, err := NewCipherManager(secret)
	if err != nil {
		return fmt.Errorf("failed to create cipher for new secret: %w", err)
	}

	vcm.mu.Lock()
	defer vcm.mu.Unlock()

	newVersion := vcm.currentVersion + 1
	vcm.ciphers[newVersion] = cipher
	vcm.currentVersion = newVersion

	// Remove old versions if we exceed maxVersions
	if len(vcm.ciphers) > vcm.maxVersions {
		oldestVersion := newVersion - vcm.maxVersions
		for version := range vcm.ciphers {
			if version <= oldestVersion {
				delete(vcm.ciphers, version)
			}
		}
	}

	return nil
}

// Encrypt encrypts data with the current (latest) secret version
// The output includes the version prefix: v{version}.{encrypted_data}
func (vcm *VersionedCipherManager) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", fmt.Errorf("plaintext cannot be empty")
	}

	vcm.mu.RLock()
	currentCipher := vcm.ciphers[vcm.currentVersion]
	currentVer := vcm.currentVersion
	vcm.mu.RUnlock()

	if currentCipher == nil {
		return "", fmt.Errorf("no current cipher available")
	}

	encrypted, err := currentCipher.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("encryption failed: %w", err)
	}

	// Prefix with version
	return fmt.Sprintf("v%d.%s", currentVer, encrypted), nil
}

// Decrypt decrypts data, automatically detecting the version and using the appropriate secret
func (vcm *VersionedCipherManager) Decrypt(encryptedData string) (string, error) {
	if encryptedData == "" {
		return "", fmt.Errorf("encrypted data cannot be empty")
	}

	version, data, err := vcm.parseVersionedData(encryptedData)
	if err != nil {
		return "", err
	}

	vcm.mu.RLock()
	cipher, exists := vcm.ciphers[version]
	vcm.mu.RUnlock()

	if !exists {
		return "", fmt.Errorf("unknown encryption version %d: secret may have been rotated out", version)
	}

	plaintext, err := cipher.Decrypt(data)
	if err != nil {
		return "", fmt.Errorf("decryption failed for version %d: %w", version, err)
	}

	return plaintext, nil
}

// EncryptBytes encrypts raw bytes with version prefix
func (vcm *VersionedCipherManager) EncryptBytes(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("plaintext cannot be empty")
	}

	vcm.mu.RLock()
	currentCipher := vcm.ciphers[vcm.currentVersion]
	currentVer := vcm.currentVersion
	vcm.mu.RUnlock()

	if currentCipher == nil {
		return nil, fmt.Errorf("no current cipher available")
	}

	encrypted, err := currentCipher.EncryptBytes(plaintext)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	// Prefix with version (4 bytes for version number)
	result := make([]byte, 4+len(encrypted))
	result[0] = byte(currentVer >> 24)
	result[1] = byte(currentVer >> 16)
	result[2] = byte(currentVer >> 8)
	result[3] = byte(currentVer)
	copy(result[4:], encrypted)

	return result, nil
}

// DecryptBytes decrypts versioned byte data
func (vcm *VersionedCipherManager) DecryptBytes(encryptedData []byte) ([]byte, error) {
	if len(encryptedData) < 4 {
		return nil, fmt.Errorf("encrypted data too short to contain version")
	}

	// Extract version (first 4 bytes, big-endian)
	version := (int(encryptedData[0]) << 24) | (int(encryptedData[1]) << 16) | (int(encryptedData[2]) << 8) | int(encryptedData[3])
	data := encryptedData[4:]

	vcm.mu.RLock()
	cipher, exists := vcm.ciphers[version]
	vcm.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("unknown encryption version %d: secret may have been rotated out", version)
	}

	plaintext, err := cipher.DecryptBytes(data)
	if err != nil {
		return nil, fmt.Errorf("decryption failed for version %d: %w", version, err)
	}

	return plaintext, nil
}

// GetCurrentVersion returns the current encryption version
func (vcm *VersionedCipherManager) GetCurrentVersion() int {
	vcm.mu.RLock()
	defer vcm.mu.RUnlock()
	return vcm.currentVersion
}

// GetAvailableVersions returns all available encryption versions
func (vcm *VersionedCipherManager) GetAvailableVersions() []int {
	vcm.mu.RLock()
	defer vcm.mu.RUnlock()

	versions := make([]int, 0, len(vcm.ciphers))
	for version := range vcm.ciphers {
		versions = append(versions, version)
	}
	return versions
}

// Hash generates a hash using the current cipher
func (vcm *VersionedCipherManager) Hash(data string) string {
	vcm.mu.RLock()
	currentCipher := vcm.ciphers[vcm.currentVersion]
	vcm.mu.RUnlock()

	if currentCipher == nil {
		return ""
	}

	return currentCipher.Hash(data)
}

// parseVersionedData parses version prefix from encrypted data
// Format: v{version}.{data}
func (vcm *VersionedCipherManager) parseVersionedData(encryptedData string) (int, string, error) {
	if !strings.HasPrefix(encryptedData, "v") {
		return 0, "", fmt.Errorf("invalid format: missing version prefix")
	}

	// Find the first dot after 'v'
	dotIndex := strings.Index(encryptedData[1:], ".")
	if dotIndex == -1 {
		return 0, "", fmt.Errorf("invalid format: missing version separator")
	}
	dotIndex += 1 // Adjust for skipped 'v'

	versionStr := encryptedData[1:dotIndex]
	data := encryptedData[dotIndex+1:]

	version, err := strconv.Atoi(versionStr)
	if err != nil {
		return 0, "", fmt.Errorf("invalid version format: %w", err)
	}

	if version <= 0 {
		return 0, "", fmt.Errorf("invalid version: must be positive")
	}

	return version, data, nil
}
