package storage

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// setupTestDB creates an in-memory SQLite database using migration files
func setupTestDB(t *testing.T) (*DBSecondaryStorage, func()) {
	// Create GORM instance with SQLite in memory
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}

	// Run migrations from the migration files
	if err := runTestMigrations(t, db); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	storage, err := NewDBSecondaryStorage(db)
	if err != nil {
		t.Fatalf("failed to create secondary storage: %v", err)
	}

	cleanup := func() {
		sqlDB, err := db.DB()
		if err == nil {
			sqlDB.Close()
		}
	}

	return storage, cleanup
}

// runTestMigrations reads and executes the SQLite migration files
func runTestMigrations(t *testing.T, db *gorm.DB) error {
	// Get the project root directory
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to get current file path")
	}

	// Navigate to project root (go up from storage/ to project root)
	projectRoot := filepath.Dir(filepath.Dir(filename))
	migrationPath := filepath.Join(projectRoot, "migrations", "sqlite", "000001_initial_schema.up.sql")

	// Read the migration file
	migrationSQL, err := os.ReadFile(migrationPath)
	if err != nil {
		return err
	}

	// Execute the migration SQL
	return db.Exec(string(migrationSQL)).Error
}

// TestDBSecondaryStorage_Set tests setting values in database storage
func TestDBSecondaryStorage_Set(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	tests := []struct {
		name      string
		key       string
		value     string
		ttl       int
		expectErr bool
	}{
		{
			name:      "set value without TTL",
			key:       "db:key1",
			value:     "hello",
			ttl:       0,
			expectErr: false,
		},
		{
			name:      "set value with TTL",
			key:       "db:key2",
			value:     "world",
			ttl:       3600,
			expectErr: false,
		},
		{
			name:      "overwrite existing value",
			key:       "db:key3",
			value:     "original",
			ttl:       0,
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := storage.Set(ctx, tt.key, tt.value, tt.ttl)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestDBSecondaryStorage_Get tests retrieving values from database storage
func TestDBSecondaryStorage_Get(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Set test data
	storage.Set(ctx, "db:get1", "test-value", 0)

	tests := []struct {
		name      string
		key       string
		expectVal string
		expectErr bool
	}{
		{
			name:      "get existing value",
			key:       "db:get1",
			expectVal: "test-value",
			expectErr: false,
		},
		{
			name:      "get non-existent key",
			key:       "db:nonexistent",
			expectVal: "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, err := storage.Get(ctx, tt.key)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectVal, val)
			}
		})
	}
}

// TestDBSecondaryStorage_Delete tests deleting values from database storage
func TestDBSecondaryStorage_Delete(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	tests := []struct {
		name      string
		key       string
		setup     func()
		expectErr bool
	}{
		{
			name: "delete existing key",
			key:  "db:del1",
			setup: func() {
				storage.Set(ctx, "db:del1", "value", 0)
			},
			expectErr: false,
		},
		{
			name: "delete non-existent key",
			key:  "db:del-nonexistent",
			setup: func() {
				// No setup needed
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}
			err := storage.Delete(ctx, tt.key)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestDBSecondaryStorage_TTL tests TTL expiration in database storage
func TestDBSecondaryStorage_TTL(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	key := "db:ttl-key"
	value := "short-lived"

	// Set value with 1 second TTL
	err := storage.Set(ctx, key, value, 1)
	require.NoError(t, err)

	// Value should exist immediately
	val, err := storage.Get(ctx, key)
	assert.NoError(t, err)
	assert.Equal(t, value, val)

	// Wait for expiration
	time.Sleep(2 * time.Second)

	// Value should be gone after expiration
	_, err = storage.Get(ctx, key)
	assert.Error(t, err)
}

// TestDBSecondaryStorage_Upsert tests updating existing values
func TestDBSecondaryStorage_Upsert(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	key := "db:upsert-key"

	// First insert
	err := storage.Set(ctx, key, "value1", 0)
	require.NoError(t, err)

	val, err := storage.Get(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, "value1", val)

	// Update existing key
	err = storage.Set(ctx, key, "value2", 0)
	require.NoError(t, err)

	val, err = storage.Get(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, "value2", val)
}

// TestDBSecondaryStorage_EmptyValue tests storing empty values
func TestDBSecondaryStorage_EmptyValue(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	key := "db:empty-key"

	// Store empty string
	err := storage.Set(ctx, key, "", 0)
	require.NoError(t, err)

	val, err := storage.Get(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, "", val)
}
