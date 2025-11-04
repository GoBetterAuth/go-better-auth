package migration

import (
	"context"
	"fmt"
	"log/slog"

	"gorm.io/gorm"

	"github.com/GoBetterAuth/go-better-auth/domain"
)

// RunUp applies all pending migrations to the database
func RunUp(ctx context.Context, db *gorm.DB, provider string) error {
	migrator, err := NewMigrator(&MigratorConfig{
		DB:       db,
		Provider: provider,
		Logger:   slog.Default(),
	})
	if err != nil {
		return fmt.Errorf("failed to create migrator: %w", err)
	}
	defer migrator.Close()

	return migrator.Up(ctx)
}

// RunDown rolls back one migration
func RunDown(ctx context.Context, db *gorm.DB, provider string) error {
	migrator, err := NewMigrator(&MigratorConfig{
		DB:       db,
		Provider: provider,
		Logger:   slog.Default(),
	})
	if err != nil {
		return fmt.Errorf("failed to create migrator: %w", err)
	}
	defer migrator.Close()

	return migrator.Down(ctx)
}

// RunSteps runs n migrations up (positive) or down (negative)
func RunSteps(ctx context.Context, db *gorm.DB, provider string, steps int) error {
	migrator, err := NewMigrator(&MigratorConfig{
		DB:       db,
		Provider: provider,
		Logger:   slog.Default(),
	})
	if err != nil {
		return fmt.Errorf("failed to create migrator: %w", err)
	}
	defer migrator.Close()

	return migrator.Steps(ctx, steps)
}

// GetMigrationInfo returns information about migration status
func GetMigrationInfo(ctx context.Context, db *gorm.DB, provider string) (*domain.MigrationInfo, error) {
	migrator, err := NewMigrator(&MigratorConfig{
		DB:       db,
		Provider: provider,
		Logger:   slog.Default(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create migrator: %w", err)
	}
	defer migrator.Close()

	return migrator.GetMigrationInfo(ctx)
}

// DropDatabase drops all tables and schema
func DropDatabase(ctx context.Context, db *gorm.DB, provider string) error {
	migrator, err := NewMigrator(&MigratorConfig{
		DB:       db,
		Provider: provider,
		Logger:   slog.Default(),
	})
	if err != nil {
		return fmt.Errorf("failed to create migrator: %w", err)
	}
	defer migrator.Close()

	return migrator.Drop(ctx)
}

// ForceVersion sets the migration version without running migrations
func ForceVersion(ctx context.Context, db *gorm.DB, provider string, version int) error {
	migrator, err := NewMigrator(&MigratorConfig{
		DB:       db,
		Provider: provider,
		Logger:   slog.Default(),
	})
	if err != nil {
		return fmt.Errorf("failed to create migrator: %w", err)
	}
	defer migrator.Close()

	return migrator.Force(ctx, version)
}
