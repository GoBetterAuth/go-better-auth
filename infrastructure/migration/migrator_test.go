package migration

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gormRepo "github.com/GoBetterAuth/go-better-auth/repository/gorm"
)

func TestMigrator_SQLite(t *testing.T) {
	// Setup test database with in-memory SQLite
	cfg := &gormRepo.Config{
		Provider:         "sqlite",
		ConnectionString: ":memory:",
		LogQueries:       false,
	}

	repos, err := gormRepo.NewRepositories(cfg)
	require.NoError(t, err)
	defer repos.Close()

	// Create migrator with embedded migrations
	migratorCfg := &MigratorConfig{
		DB:       repos.DB,
		Provider: "sqlite",
	}

	migrator, err := NewMigrator(migratorCfg)
	require.NoError(t, err)
	defer migrator.Close()

	// Run migrations
	ctx := context.Background()
	err = migrator.Up(ctx)
	require.NoError(t, err)

	// Get SQL DB to verify tables
	sqlDB, err := repos.DB.DB()
	require.NoError(t, err)

	// Check if users table exists
	var count int
	err = sqlDB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='users'").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "users table should exist")

	// Check if sessions table exists
	err = sqlDB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='sessions'").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "sessions table should exist")

	// Check if accounts table exists
	err = sqlDB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='accounts'").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "accounts table should exist")

	// Check if verifications table exists
	err = sqlDB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='verifications'").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "verifications table should exist")
}

func TestMigrator_NewMigrator(t *testing.T) {
	// Setup test database with in-memory SQLite
	cfg := &gormRepo.Config{
		Provider:         "sqlite",
		ConnectionString: ":memory:",
		LogQueries:       false,
	}

	repos, err := gormRepo.NewRepositories(cfg)
	require.NoError(t, err)
	defer repos.Close()

	// Get relative path to migrations
	// Test creating a new migrator with embedded migrations
	migratorCfg := &MigratorConfig{
		DB:       repos.DB,
		Provider: "sqlite",
	}

	migrator, err := NewMigrator(migratorCfg)
	require.NoError(t, err)
	defer migrator.Close()

	// Test migration up
	ctx := context.Background()
	err = migrator.Up(ctx)
	assert.NoError(t, err)

	// Test getting version
	version, dirty, err := migrator.Version(ctx)
	require.NoError(t, err)
	assert.False(t, dirty, "migration should not be dirty")
	assert.Greater(t, version, uint(0), "version should be greater than 0")

	// Test getting migration info
	info, err := migrator.GetMigrationInfo(ctx)
	require.NoError(t, err)
	assert.Equal(t, version, info.CurrentVersion)
	assert.Equal(t, dirty, info.Dirty)
}

func TestMigrator_InvalidProvider(t *testing.T) {
	cfg := &gormRepo.Config{
		Provider:         "sqlite",
		ConnectionString: ":memory:",
		LogQueries:       false,
	}

	repos, err := gormRepo.NewRepositories(cfg)
	require.NoError(t, err)
	defer repos.Close()

	// Get relative path to migrations
	// Test creating a migrator with invalid provider
	migratorCfg := &MigratorConfig{
		DB:       repos.DB,
		Provider: "invalid",
	}

	_, err = NewMigrator(migratorCfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported database provider")
}

func TestMigrator_NilDB(t *testing.T) {
	// Test creating a migrator with nil DB
	migratorCfg := &MigratorConfig{
		DB:       nil,
		Provider: "sqlite",
	}

	_, err := NewMigrator(migratorCfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database connection is required")
}
