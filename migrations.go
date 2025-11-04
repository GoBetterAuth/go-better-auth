package gobetterauth

import (
	"context"
	"fmt"

	"github.com/GoBetterAuth/go-better-auth/domain"
	migrationService "github.com/GoBetterAuth/go-better-auth/usecase/migration"
)

// RunMigrations applies all pending migrations to the database
// This is a convenience function for users to run migrations programmatically
func RunMigrations(ctx context.Context, config *domain.Config) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}

	service := migrationService.NewService(config, nil)
	return service.Up(ctx)
}

// RunMigrationsDown rolls back database migrations
// This is a convenience function for users to rollback migrations programmatically
func RunMigrationsDown(ctx context.Context, config *domain.Config) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}

	service := migrationService.NewService(config, nil)
	return service.Down(ctx)
}

// RunMigrationsSteps rolls back a specific number of migration steps
// This is a convenience function for users to rollback a specific number of migrations programmatically
func RunMigrationsSteps(ctx context.Context, config *domain.Config, steps int) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}

	if steps <= 0 {
		return fmt.Errorf("steps must be a positive number")
	}

	service := migrationService.NewService(config, nil)
	// Negative steps for rollback
	return service.Steps(ctx, -steps)
}

// DropDatabase drops all database tables (DESTRUCTIVE OPERATION)
// This is a convenience function for users to drop all tables programmatically
// WARNING: This operation is irreversible and will delete all data
func DropDatabase(ctx context.Context, config *domain.Config) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}

	service := migrationService.NewService(config, nil)
	return service.Drop(ctx)
}

// ForceVersion forces the migration version to a specific number
// This should only be used to fix a dirty database state
// This is a convenience function for users to force migration version programmatically
func ForceVersion(ctx context.Context, config *domain.Config, version int) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}

	service := migrationService.NewService(config, nil)
	return service.Force(ctx, version)
}

// GetMigrationInfo returns information about migration status
// This is a convenience function for users to check migration status programmatically
func GetMigrationInfo(ctx context.Context, config *domain.Config) (*domain.MigrationInfo, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	service := migrationService.NewService(config, nil)
	return service.GetMigrationInfo(ctx)
}

// GetMigrationVersion returns only the current migration version
// This is a convenience function for users who only need the version number
func GetMigrationVersion(ctx context.Context, config *domain.Config) (uint, bool, error) {
	if config == nil {
		return 0, false, fmt.Errorf("config cannot be nil")
	}

	service := migrationService.NewService(config, nil)
	return service.Version(ctx)
}

// IsMigrationDirty checks if the database is in a dirty state
// This is useful for checking if migrations failed and need manual intervention
func IsMigrationDirty(ctx context.Context, config *domain.Config) (bool, error) {
	if config == nil {
		return false, fmt.Errorf("config cannot be nil")
	}

	service := migrationService.NewService(config, nil)
	return service.IsDirty(ctx)
}

// ResetDatabase drops all tables and re-runs all migrations
// This is equivalent to running DropDatabase followed by RunMigrations
// WARNING: This operation is destructive and will delete all data
func ResetDatabase(ctx context.Context, config *domain.Config) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}

	service := migrationService.NewService(config, nil)
	return service.Reset(ctx)
}
