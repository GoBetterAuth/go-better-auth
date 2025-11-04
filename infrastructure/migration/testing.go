package migration

import (
	"context"
	"fmt"
	"log/slog"

	"gorm.io/gorm"
)

// RunTestMigrations runs migrations for testing using golang-migrate with embedded files
func RunTestMigrations(db *gorm.DB, provider string) error {
	config := &MigratorConfig{
		DB:       db,
		Provider: provider,
		Logger:   slog.Default(),
	}

	migrator, err := NewMigrator(config)
	if err != nil {
		return fmt.Errorf("failed to create migrator: %w", err)
	}

	// Run all migrations up
	if err := migrator.Up(context.Background()); err != nil {
		migrator.Close() // Only close on error
		return fmt.Errorf("failed to run test migrations: %w", err)
	}

	// Don't close the migrator to keep the connection alive for tests
	return nil
}

// DropTestTables drops all tables for testing cleanup
func DropTestTables(db *gorm.DB, provider string) error {
	config := &MigratorConfig{
		DB:       db,
		Provider: provider,
		Logger:   slog.Default(),
	}

	migrator, err := NewMigrator(config)
	if err != nil {
		return fmt.Errorf("failed to create migrator: %w", err)
	}
	defer migrator.Close()

	// Drop all tables
	if err := migrator.Drop(context.Background()); err != nil {
		return fmt.Errorf("failed to drop test tables: %w", err)
	}

	return nil
}
