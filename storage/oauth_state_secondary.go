package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// SecondaryOAuthStateStorage implements OAuthStateStorage using SecondaryStorage backend.
// This allows OAuth states to be stored in Redis, database, or any other SecondaryStorage implementation,
// making it suitable for multi-instance deployments.
type SecondaryOAuthStateStorage struct {
	storage   SecondaryStorage
	keyPrefix string
}

// NewSecondaryOAuthStateStorage creates a new OAuth state storage using SecondaryStorage backend
func NewSecondaryOAuthStateStorage(storage SecondaryStorage, keyPrefix string) *SecondaryOAuthStateStorage {
	if keyPrefix == "" {
		keyPrefix = "oauth_state:"
	}

	return &SecondaryOAuthStateStorage{
		storage:   storage,
		keyPrefix: keyPrefix,
	}
}

// Store saves an OAuth state with the given TTL
func (s *SecondaryOAuthStateStorage) Store(ctx context.Context, stateID string, state *OAuthState, ttl time.Duration) error {
	if stateID == "" {
		return fmt.Errorf("stateID cannot be empty")
	}
	if state == nil {
		return fmt.Errorf("state cannot be nil")
	}

	// Update expiration time based on TTL
	state.ExpiresAt = time.Now().Add(ttl)

	// Marshal state to JSON
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal OAuth state: %w", err)
	}

	key := s.keyPrefix + stateID
	ttlSeconds := int(ttl.Seconds())

	err = s.storage.Set(ctx, key, string(data), ttlSeconds)
	if err != nil {
		return fmt.Errorf("failed to store OAuth state: %w", err)
	}

	return nil
}

// Retrieve gets an OAuth state by its ID
func (s *SecondaryOAuthStateStorage) Retrieve(ctx context.Context, stateID string) (*OAuthState, error) {
	if stateID == "" {
		return nil, fmt.Errorf("stateID cannot be empty")
	}

	key := s.keyPrefix + stateID

	value, err := s.storage.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve OAuth state: %w", err)
	}

	if value == nil {
		return nil, fmt.Errorf("state not found")
	}

	// Convert value to string
	dataStr, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("invalid state data format")
	}

	// Unmarshal state from JSON
	var state OAuthState
	err = json.Unmarshal([]byte(dataStr), &state)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal OAuth state: %w", err)
	}

	// Check if expired (double-check since TTL might not be exact)
	if time.Now().After(state.ExpiresAt) {
		// Clean up expired state
		_ = s.storage.Delete(ctx, key)
		return nil, fmt.Errorf("state expired")
	}

	return &state, nil
}

// Delete removes an OAuth state by its ID
func (s *SecondaryOAuthStateStorage) Delete(ctx context.Context, stateID string) error {
	if stateID == "" {
		return fmt.Errorf("stateID cannot be empty")
	}

	key := s.keyPrefix + stateID
	err := s.storage.Delete(ctx, key)
	if err != nil {
		return fmt.Errorf("failed to delete OAuth state: %w", err)
	}

	return nil
}

// CleanupExpired removes all expired OAuth states and returns the count of cleaned up states
// Note: This implementation assumes the SecondaryStorage handles TTL-based expiration automatically.
// For storage backends that don't support TTL, this method will return 0 as expired states
// should be cleaned up during retrieve operations.
func (s *SecondaryOAuthStateStorage) CleanupExpired(ctx context.Context) (int, error) {
	// Most SecondaryStorage implementations (Redis, etc.) handle TTL automatically
	// If the storage backend doesn't support TTL, expired states are cleaned up during retrieval
	return 0, nil
}

// Count returns the number of active states
// Note: This is an approximate count and may not be fully accurate for all SecondaryStorage implementations
func (s *SecondaryOAuthStateStorage) Count(ctx context.Context) (int, error) {
	// This is a best-effort implementation
	// Some storage backends might not support efficient counting
	// In such cases, this could be extended with a separate counter key

	// For now, return 0 as most secondary storage implementations
	// don't provide efficient pattern-based counting without scanning all keys
	return 0, nil
}

// Close releases any resources used by the storage
func (s *SecondaryOAuthStateStorage) Close() error {
	// SecondaryStorage interface doesn't define Close method
	// The underlying storage should be managed by the caller
	return nil
}

// GetKeyPrefix returns the key prefix used for OAuth states
func (s *SecondaryOAuthStateStorage) GetKeyPrefix() string {
	return s.keyPrefix
}
