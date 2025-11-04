package domain

import "context"

// MigrationInfo represents migration status information
type MigrationInfo struct {
	CurrentVersion uint `json:"current_version"`
	Dirty          bool `json:"dirty"`
}

// MigrationService defines the interface for database migration operations
type MigrationService interface {
	// Up runs all pending migrations
	Up(ctx context.Context) error

	// Down runs one migration down
	Down(ctx context.Context) error

	// Steps runs n migrations up (positive) or down (negative)
	Steps(ctx context.Context, n int) error

	// Version returns the current migration version and dirty state
	Version(ctx context.Context) (uint, bool, error)

	// Force sets the migration version without running migrations
	Force(ctx context.Context, version int) error

	// Drop drops all tables and schema
	Drop(ctx context.Context) error

	// GetMigrationInfo returns information about migration status
	GetMigrationInfo(ctx context.Context) (*MigrationInfo, error)

	// Close closes the migration instance
	Close() error
}
