package storage

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"gorm.io/gorm"
)

// secondaryStorageModel represents a GORM model for the secondary storage table
type secondaryStorageModel struct {
	Key       string     `gorm:"primaryKey"`
	Value     string     `gorm:"not null"`
	ExpiresAt *time.Time `gorm:"index"`
	CreatedAt time.Time  `gorm:"autoCreateTime"`
	UpdatedAt time.Time  `gorm:"autoUpdateTime"`
}

// TableName returns the table name for GORM
func (secondaryStorageModel) TableName() string {
	return "secondary_storage"
}

// DBSecondaryStorage implements SecondaryStorage interface using GORM.
// It provides key-value storage with optional TTL for session data and rate limiting.
// This is useful as a fallback when Redis is not available.
type DBSecondaryStorage struct {
	db     *gorm.DB
	logger *slog.Logger
}

// NewDBSecondaryStorage creates a new database-backed secondary storage instance.
// It uses GORM for key-value storage operations.
func NewDBSecondaryStorage(db *gorm.DB) (*DBSecondaryStorage, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection cannot be nil")
	}

	logger := slog.Default()

	// Test connection
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := sqlDB.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	logger.Info("successfully initialized database secondary storage")

	return &DBSecondaryStorage{
		db:     db,
		logger: logger,
	}, nil
}

// Get retrieves the value for the given key from the database.
func (s *DBSecondaryStorage) Get(ctx context.Context, key string) (any, error) {
	s.logger.Debug("getting value from database", "key", key)

	var model secondaryStorageModel
	err := s.db.WithContext(ctx).Where("key = ?", key).First(&model).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("key not found: %s", key)
		}
		return nil, fmt.Errorf("failed to get value from database: %w", err)
	}

	// Check if value has expired
	if model.ExpiresAt != nil && model.ExpiresAt.Before(time.Now()) {
		// Delete expired entry
		_ = s.Delete(ctx, key)
		return nil, fmt.Errorf("key has expired: %s", key)
	}

	return model.Value, nil
}

// Set stores the value for the given key in the database with optional TTL.
// ttlSeconds is the time to live in seconds. If 0 or negative, the key won't expire.
func (s *DBSecondaryStorage) Set(ctx context.Context, key string, value string, ttlSeconds int) error {
	s.logger.Debug("setting value in database", "key", key, "ttl_seconds", ttlSeconds)

	var expiresAt *time.Time
	if ttlSeconds > 0 {
		expTime := time.Now().Add(time.Duration(ttlSeconds) * time.Second)
		expiresAt = &expTime
	}

	model := secondaryStorageModel{
		Key:       key,
		Value:     value,
		ExpiresAt: expiresAt,
	}

	// Use GORM's Save method which performs UPSERT
	err := s.db.WithContext(ctx).Save(&model).Error
	if err != nil {
		return fmt.Errorf("failed to set value in database: %w", err)
	}

	return nil
}

// Delete removes the value for the given key from the database.
func (s *DBSecondaryStorage) Delete(ctx context.Context, key string) error {
	s.logger.Debug("deleting value from database", "key", key)

	err := s.db.WithContext(ctx).Where("key = ?", key).Delete(&secondaryStorageModel{}).Error
	if err != nil {
		return fmt.Errorf("failed to delete value from database: %w", err)
	}

	return nil
}
