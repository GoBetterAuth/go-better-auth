package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/GoBetterAuth/go-better-auth/internal/crypto"
)

// OAuthState represents an OAuth state parameter with metadata
type OAuthState struct {
	State      string    `json:"state"`
	ProviderID string    `json:"provider_id"`
	RedirectTo string    `json:"redirect_to,omitempty"`
	UserID     string    `json:"user_id,omitempty"` // For account linking
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// OAuthStateManager manages OAuth state parameters with CSRF protection.
// It now supports pluggable storage backends and secret rotation for production deployments.
type OAuthStateManager struct {
	cipher  *crypto.VersionedCipherManager
	storage OAuthStateStorage
	ttl     time.Duration
}

// NewOAuthStateManager creates a new OAuth state manager with in-memory storage (for backward compatibility)
func NewOAuthStateManager(secret string, ttl time.Duration) (*OAuthStateManager, error) {
	storage := NewInMemoryOAuthStateStorage(5 * time.Minute) // Default cleanup interval
	return NewOAuthStateManagerWithStorage(secret, ttl, storage)
}

// NewOAuthStateManagerWithStorage creates a new OAuth state manager with custom storage
func NewOAuthStateManagerWithStorage(secret string, ttl time.Duration, storage OAuthStateStorage) (*OAuthStateManager, error) {
	if secret == "" {
		return nil, fmt.Errorf("secret cannot be empty")
	}

	if ttl <= 0 {
		ttl = 10 * time.Minute // Default TTL
	}

	if storage == nil {
		return nil, fmt.Errorf("storage cannot be nil")
	}

	// Create versioned cipher manager for encryption, signing, and secret rotation
	cipher, err := crypto.NewVersionedCipherManager(secret, 5) // Keep last 5 secret versions
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher manager: %w", err)
	}

	return &OAuthStateManager{
		cipher:  cipher,
		storage: storage,
		ttl:     ttl,
	}, nil
}

// GenerateState generates a new signed OAuth state parameter
func (m *OAuthStateManager) GenerateState(providerID string, redirectTo string, userID string) (string, error) {
	if providerID == "" {
		return "", fmt.Errorf("provider_id cannot be empty")
	}

	// Generate random state token
	randomState, err := crypto.GenerateToken(24)
	if err != nil {
		return "", fmt.Errorf("failed to generate random state: %w", err)
	}

	now := time.Now()
	state := &OAuthState{
		State:      randomState,
		ProviderID: providerID,
		RedirectTo: redirectTo,
		UserID:     userID,
		CreatedAt:  now,
		ExpiresAt:  now.Add(m.ttl),
	}

	// Marshal to JSON
	data, err := json.Marshal(state)
	if err != nil {
		return "", fmt.Errorf("failed to marshal state: %w", err)
	}

	// Encrypt and sign the data using versioned cipher manager
	encrypted, err := m.cipher.Encrypt(string(data))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt state: %w", err)
	}

	// Store using pluggable storage backend
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = m.storage.Store(ctx, state.State, state, m.ttl)
	if err != nil {
		return "", fmt.Errorf("failed to store state: %w", err)
	}

	// Return the encrypted state
	return encrypted, nil
}

// ValidateState validates an encrypted OAuth state parameter
func (m *OAuthStateManager) ValidateState(encryptedState string) (*OAuthState, error) {
	if encryptedState == "" {
		return nil, fmt.Errorf("state cannot be empty")
	}

	// Decrypt and verify the state (supports multiple secret versions)
	decrypted, err := m.cipher.Decrypt(encryptedState)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt state: %w", err)
	}

	// Unmarshal the state
	var state OAuthState
	err = json.Unmarshal([]byte(decrypted), &state)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal state: %w", err)
	}

	// Retrieve state from storage backend
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	storedState, err := m.storage.Retrieve(ctx, state.State)
	if err != nil {
		return nil, fmt.Errorf("state not found or expired: %w", err)
	}

	// Validate state matches
	if storedState.ProviderID != state.ProviderID {
		return nil, fmt.Errorf("provider mismatch: possible tampering")
	}

	// Additional validation: compare encrypted state data
	if storedState.State != state.State {
		return nil, fmt.Errorf("state token mismatch: possible replay attack")
	}

	// Clean up used state (one-time use)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel2()

	err = m.storage.Delete(ctx2, state.State)
	if err != nil {
		// Log error but don't fail validation - state was valid
		_ = err // TODO: Add structured logging here
	}

	return storedState, nil
}

// CleanupExpiredStates removes expired state parameters
func (m *OAuthStateManager) CleanupExpiredStates() int {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	count, err := m.storage.CleanupExpired(ctx)
	if err != nil {
		// Log error but return 0
		_ = err // TODO: Add structured logging here
		return 0
	}

	return count
}

// Count returns the number of active states
func (m *OAuthStateManager) Count() int {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	count, err := m.storage.Count(ctx)
	if err != nil {
		// Log error but return 0
		_ = err // TODO: Add structured logging here
		return 0
	}

	return count
}

// RotateSecret adds a new secret version for encryption while maintaining
// backward compatibility for decryption. This enables seamless secret rotation
// in production environments.
func (m *OAuthStateManager) RotateSecret(newSecret string) error {
	if newSecret == "" {
		return fmt.Errorf("new secret cannot be empty")
	}

	return m.cipher.AddSecret(newSecret)
}

// GetCurrentSecretVersion returns the current secret version being used for encryption
func (m *OAuthStateManager) GetCurrentSecretVersion() int {
	return m.cipher.GetCurrentVersion()
}

// GetAvailableSecretVersions returns all available secret versions for decryption
func (m *OAuthStateManager) GetAvailableSecretVersions() []int {
	return m.cipher.GetAvailableVersions()
}

// Close releases any resources used by the storage backend
func (m *OAuthStateManager) Close() error {
	return m.storage.Close()
}
