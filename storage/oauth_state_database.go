package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// OAuthStateRecord represents an OAuth state record in the database
type OAuthStateRecord struct {
	ID        string    `gorm:"primaryKey;column:id"`
	StateData string    `gorm:"column:state_data;type:text"`
	ExpiresAt time.Time `gorm:"column:expires_at;index"`
	CreatedAt time.Time `gorm:"column:created_at"`
}

// TableName returns the table name for OAuth state records
func (OAuthStateRecord) TableName() string {
	return "oauth_states"
}

// DatabaseOAuthStateStorage implements OAuthStateStorage using a database backend.
// This implementation provides persistent storage suitable for multi-instance deployments
// and includes automatic cleanup via background processes.
type DatabaseOAuthStateStorage struct {
	db        *gorm.DB
	stopCh    chan struct{}
	tableName string
}

// NewDatabaseOAuthStateStorage creates a new database-based OAuth state storage
func NewDatabaseOAuthStateStorage(db *gorm.DB, cleanupInterval time.Duration) (*DatabaseOAuthStateStorage, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection cannot be nil")
	}

	if cleanupInterval <= 0 {
		cleanupInterval = 10 * time.Minute // Default cleanup interval
	}

	storage := &DatabaseOAuthStateStorage{
		db:        db,
		stopCh:    make(chan struct{}),
		tableName: "oauth_states",
	}

	// Start background cleanup goroutine
	go storage.backgroundCleanup(cleanupInterval)

	return storage, nil
}

// Store saves an OAuth state with the given TTL
func (s *DatabaseOAuthStateStorage) Store(ctx context.Context, stateID string, state *OAuthState, ttl time.Duration) error {
	if stateID == "" {
		return fmt.Errorf("stateID cannot be empty")
	}
	if state == nil {
		return fmt.Errorf("state cannot be nil")
	}

	// Update expiration time based on TTL
	state.ExpiresAt = time.Now().Add(ttl)

	// Marshal state to JSON
	stateData, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal OAuth state: %w", err)
	}

	record := &OAuthStateRecord{
		ID:        stateID,
		StateData: string(stateData),
		ExpiresAt: state.ExpiresAt,
		CreatedAt: time.Now(),
	}

	// Use GORM's Create which handles upserts
	err = s.db.WithContext(ctx).Create(record).Error
	if err != nil {
		return fmt.Errorf("failed to store OAuth state: %w", err)
	}

	return nil
}

// Retrieve gets an OAuth state by its ID
func (s *DatabaseOAuthStateStorage) Retrieve(ctx context.Context, stateID string) (*OAuthState, error) {
	if stateID == "" {
		return nil, fmt.Errorf("stateID cannot be empty")
	}

	var record OAuthStateRecord
	err := s.db.WithContext(ctx).Where("id = ? AND expires_at > ?", stateID, time.Now()).First(&record).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("state not found")
		}
		return nil, fmt.Errorf("failed to retrieve OAuth state: %w", err)
	}

	// Unmarshal state from JSON
	var state OAuthState
	err = json.Unmarshal([]byte(record.StateData), &state)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal OAuth state: %w", err)
	}

	return &state, nil
}

// Delete removes an OAuth state by its ID
func (s *DatabaseOAuthStateStorage) Delete(ctx context.Context, stateID string) error {
	if stateID == "" {
		return fmt.Errorf("stateID cannot be empty")
	}

	err := s.db.WithContext(ctx).Where("id = ?", stateID).Delete(&OAuthStateRecord{}).Error
	if err != nil {
		return fmt.Errorf("failed to delete OAuth state: %w", err)
	}

	return nil
}

// CleanupExpired removes all expired OAuth states and returns the count of cleaned up states
func (s *DatabaseOAuthStateStorage) CleanupExpired(ctx context.Context) (int, error) {
	result := s.db.WithContext(ctx).Where("expires_at <= ?", time.Now()).Delete(&OAuthStateRecord{})
	if result.Error != nil {
		return 0, fmt.Errorf("failed to cleanup expired OAuth states: %w", result.Error)
	}

	return int(result.RowsAffected), nil
}

// Count returns the number of active states
func (s *DatabaseOAuthStateStorage) Count(ctx context.Context) (int, error) {
	var count int64
	err := s.db.WithContext(ctx).Model(&OAuthStateRecord{}).Where("expires_at > ?", time.Now()).Count(&count).Error
	if err != nil {
		return 0, fmt.Errorf("failed to count OAuth states: %w", err)
	}

	return int(count), nil
}

// Close releases any resources used by the storage
func (s *DatabaseOAuthStateStorage) Close() error {
	close(s.stopCh)
	return nil
}

// backgroundCleanup runs periodic cleanup of expired states
func (s *DatabaseOAuthStateStorage) backgroundCleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
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
