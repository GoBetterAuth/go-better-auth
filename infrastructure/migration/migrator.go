package migration

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/database/sqlite3"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"gorm.io/gorm"

	"github.com/GoBetterAuth/go-better-auth/domain"
)

// Migrator handles database migrations using golang-migrate
type Migrator struct {
	migrate *migrate.Migrate
	db      *sql.DB
	logger  *slog.Logger
}

// Ensure Migrator implements domain.MigrationService
var _ domain.MigrationService = (*Migrator)(nil)

// findProjectRoot attempts to find the project root by looking for go.mod file
func findProjectRoot() (string, error) {
	// Start from current working directory
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	// Walk up the directory tree looking for go.mod
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// We've reached the root directory
			break
		}
		dir = parent
	}

	// Fallback: use the directory where this source file is located
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("could not determine project root")
	}

	// Go up from this file's directory to find project root
	dir = filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return "", fmt.Errorf("could not find project root (go.mod not found)")
}

// MigratorConfig contains configuration for the migrator
type MigratorConfig struct {
	DB            *gorm.DB
	Provider      string // "sqlite" or "postgres"
	Logger        *slog.Logger
	MigrationPath string // Path to migration files directory (e.g., "migrations/postgres")
}

// NewMigrator creates a new migrator instance
func NewMigrator(config *MigratorConfig) (*Migrator, error) {
	if config.DB == nil {
		return nil, fmt.Errorf("database connection is required")
	}

	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	// Get the underlying sql.DB from GORM
	sqlDB, err := config.DB.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get sql.DB from GORM: %w", err)
	}

	// Create database driver based on provider
	var driver database.Driver
	switch config.Provider {
	case "sqlite":
		driver, err = sqlite3.WithInstance(sqlDB, &sqlite3.Config{})
		if err != nil {
			return nil, fmt.Errorf("failed to create sqlite driver: %w", err)
		}
	case "postgres":
		driver, err = postgres.WithInstance(sqlDB, &postgres.Config{})
		if err != nil {
			return nil, fmt.Errorf("failed to create postgres driver: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported database provider: %s", config.Provider)
	}

	// Set default migration path if not provided
	migrationPath := config.MigrationPath
	if migrationPath == "" {
		// Find project root and construct absolute path
		projectRoot, err := findProjectRoot()
		if err != nil {
			return nil, fmt.Errorf("failed to find project root: %w", err)
		}
		migrationPath = filepath.Join(projectRoot, "migrations", config.Provider)
	}

	// Ensure migration path is absolute
	if !filepath.IsAbs(migrationPath) {
		abs, err := filepath.Abs(migrationPath)
		if err != nil {
			return nil, fmt.Errorf("failed to get absolute path for migrations: %w", err)
		}
		migrationPath = abs
	}

	// Verify migration directory exists
	if _, err := os.Stat(migrationPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("migration directory does not exist: %s", migrationPath)
	}

	// Create file source URL
	sourceURL := fmt.Sprintf("file://%s", migrationPath)

	// Create migrate instance with file source
	m, err := migrate.NewWithDatabaseInstance(sourceURL, config.Provider, driver)
	if err != nil {
		return nil, fmt.Errorf("failed to create migrate instance: %w", err)
	}

	return &Migrator{
		migrate: m,
		db:      sqlDB,
		logger:  config.Logger,
	}, nil
}

// Up runs all pending migrations
func (m *Migrator) Up(ctx context.Context) error {
	m.logger.InfoContext(ctx, "Running migrations up")

	err := m.migrate.Up()
	if err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			m.logger.InfoContext(ctx, "No migrations to run")
			return nil
		}
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	m.logger.InfoContext(ctx, "Migrations completed successfully")
	return nil
}

// Down runs one migration down
func (m *Migrator) Down(ctx context.Context) error {
	m.logger.InfoContext(ctx, "Running one migration down")

	err := m.migrate.Steps(-1)
	if err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			m.logger.InfoContext(ctx, "No migrations to rollback")
			return nil
		}
		return fmt.Errorf("failed to rollback migration: %w", err)
	}

	m.logger.InfoContext(ctx, "Migration rollback completed")
	return nil
}

// Steps runs n migrations up (positive) or down (negative)
func (m *Migrator) Steps(ctx context.Context, n int) error {
	direction := "up"
	if n < 0 {
		direction = "down"
	}

	m.logger.InfoContext(ctx, "Running migrations", "steps", n, "direction", direction)

	err := m.migrate.Steps(n)
	if err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			m.logger.InfoContext(ctx, "No migrations to run")
			return nil
		}
		return fmt.Errorf("failed to run %d migrations: %w", n, err)
	}

	m.logger.InfoContext(ctx, "Migration steps completed", "steps", n)
	return nil
}

// Version returns the current migration version
func (m *Migrator) Version(ctx context.Context) (uint, bool, error) {
	version, dirty, err := m.migrate.Version()
	if err != nil {
		if errors.Is(err, migrate.ErrNilVersion) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("failed to get migration version: %w", err)
	}

	return version, dirty, nil
}

// Force sets the migration version without running migrations
func (m *Migrator) Force(ctx context.Context, version int) error {
	m.logger.WarnContext(ctx, "Forcing migration version", "version", version)

	err := m.migrate.Force(version)
	if err != nil {
		return fmt.Errorf("failed to force migration version %d: %w", version, err)
	}

	m.logger.InfoContext(ctx, "Migration version forced", "version", version)
	return nil
}

// Drop drops all tables and schema
func (m *Migrator) Drop(ctx context.Context) error {
	m.logger.WarnContext(ctx, "Dropping all database tables and schema")

	err := m.migrate.Drop()
	if err != nil {
		return fmt.Errorf("failed to drop database: %w", err)
	}

	m.logger.InfoContext(ctx, "Database dropped successfully")
	return nil
}

// Close closes the migration instance
func (m *Migrator) Close() error {
	// Only close the source, not the database connection
	// This allows the database to remain open for further use
	sourceErr, _ := m.migrate.Close()
	if sourceErr != nil {
		m.logger.Error("Failed to close migration source", "error", sourceErr)
		return fmt.Errorf("failed to close migrator source: %v", sourceErr)
	}

	return nil
}

// GetMigrationInfo returns information about migration status
func (m *Migrator) GetMigrationInfo(ctx context.Context) (*domain.MigrationInfo, error) {
	version, dirty, err := m.Version(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get version info: %w", err)
	}

	info := &domain.MigrationInfo{
		CurrentVersion: version,
		Dirty:          dirty,
	}

	return info, nil
}
