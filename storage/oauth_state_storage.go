package storage

import (
	"context"
	"time"
)

// OAuthStateStorage defines the interface for storing OAuth state parameters.
// This interface allows for different storage backends (in-memory, Redis, database)
// to support multi-instance deployments and configurable persistence strategies.
type OAuthStateStorage interface {
	// Store saves an OAuth state with the given TTL
	Store(ctx context.Context, stateID string, state *OAuthState, ttl time.Duration) error

	// Retrieve gets an OAuth state by its ID
	Retrieve(ctx context.Context, stateID string) (*OAuthState, error)

	// Delete removes an OAuth state by its ID (for one-time use enforcement)
	Delete(ctx context.Context, stateID string) error

	// CleanupExpired removes all expired OAuth states and returns the count of cleaned up states
	CleanupExpired(ctx context.Context) (int, error)

	// Count returns the number of active states (useful for monitoring)
	Count(ctx context.Context) (int, error)

	// Close releases any resources used by the storage
	Close() error
}
