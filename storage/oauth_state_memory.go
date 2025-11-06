package storage

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// InMemoryOAuthStateStorage implements OAuthStateStorage using in-memory storage.
// This implementation includes automatic cleanup via a background goroutine.
type InMemoryOAuthStateStorage struct {
	mu        sync.RWMutex
	states    map[string]*OAuthState
	stopCh    chan struct{}
	closeOnce sync.Once
}

// NewInMemoryOAuthStateStorage creates a new in-memory OAuth state storage
// with automatic cleanup running in the background.
func NewInMemoryOAuthStateStorage(cleanupInterval time.Duration) *InMemoryOAuthStateStorage {
	if cleanupInterval <= 0 {
		cleanupInterval = 5 * time.Minute // Default cleanup interval
	}

	storage := &InMemoryOAuthStateStorage{
		states: make(map[string]*OAuthState),
		stopCh: make(chan struct{}),
	}

	// Start background cleanup goroutine
	go storage.backgroundCleanup(cleanupInterval)

	return storage
}

// Store saves an OAuth state with the given TTL
func (s *InMemoryOAuthStateStorage) Store(ctx context.Context, stateID string, state *OAuthState, ttl time.Duration) error {
	if stateID == "" {
		return fmt.Errorf("stateID cannot be empty")
	}
	if state == nil {
		return fmt.Errorf("state cannot be nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Update expiration time based on TTL
	state.ExpiresAt = time.Now().Add(ttl)
	s.states[stateID] = state

	return nil
}

// Retrieve gets an OAuth state by its ID
func (s *InMemoryOAuthStateStorage) Retrieve(ctx context.Context, stateID string) (*OAuthState, error) {
	if stateID == "" {
		return nil, fmt.Errorf("stateID cannot be empty")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	state, exists := s.states[stateID]
	if !exists {
		return nil, fmt.Errorf("state not found")
	}

	// Check if expired
	if time.Now().After(state.ExpiresAt) {
		return nil, fmt.Errorf("state expired")
	}

	// Return a copy to avoid external modification
	stateCopy := *state
	return &stateCopy, nil
}

// Delete removes an OAuth state by its ID
func (s *InMemoryOAuthStateStorage) Delete(ctx context.Context, stateID string) error {
	if stateID == "" {
		return fmt.Errorf("stateID cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.states, stateID)
	return nil
}

// CleanupExpired removes all expired OAuth states and returns the count of cleaned up states
func (s *InMemoryOAuthStateStorage) CleanupExpired(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	count := 0

	for stateID, state := range s.states {
		if now.After(state.ExpiresAt) {
			delete(s.states, stateID)
			count++
		}
	}

	return count, nil
}

// Count returns the number of active states
func (s *InMemoryOAuthStateStorage) Count(ctx context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.states), nil
}

// Close releases any resources used by the storage
func (s *InMemoryOAuthStateStorage) Close() error {
	s.closeOnce.Do(func() {
		close(s.stopCh)
	})
	return nil
}

// backgroundCleanup runs periodic cleanup of expired states
func (s *InMemoryOAuthStateStorage) backgroundCleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			count, err := s.CleanupExpired(ctx)
			if err != nil {
				// Log error but continue cleanup cycle
				_ = err // TODO: Add structured logging here
			} else if count > 0 {
				// Log successful cleanup
				_ = count // TODO: Add structured logging here
			}
			cancel()

		case <-s.stopCh:
			return
		}
	}
}
