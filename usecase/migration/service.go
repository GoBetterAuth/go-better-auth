package migration

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/GoBetterAuth/go-better-auth/domain"
	"github.com/GoBetterAuth/go-better-auth/infrastructure/migration"
	gormrepo "github.com/GoBetterAuth/go-better-auth/repository/gorm"
)

// Service provides database migration operations
type Service struct {
	config *domain.Config
	logger *slog.Logger
}

// NewService creates a new migration service
func NewService(config *domain.Config, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}

	return &Service{
		config: config,
		logger: logger,
	}
}

// createConnection creates a database connection and repositories
func (s *Service) createConnection() (*gormrepo.Repositories, error) {
	if s.config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	// Apply defaults to ensure database configuration is set
	s.config.ApplyDefaults()

	// Validate that database configuration is present
	if s.config.Database.Provider == "" {
		return nil, fmt.Errorf("database provider is required for migrations")
	}

	// Create GORM repositories to get database connection
	gormCfg := &gormrepo.Config{
		Provider:         strings.ToLower(s.config.Database.Provider),
		ConnectionString: s.config.Database.ConnectionString,
		LogQueries:       s.config.Database.LogQueries,
		MaxOpenConns:     s.config.Database.MaxOpenConns,
		MaxIdleConns:     s.config.Database.MaxIdleConns,
		ConnMaxLifetime:  s.config.Database.ConnMaxLifetime,
	}

	repos, err := gormrepo.NewRepositories(gormCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create database connection: %w", err)
	}

	return repos, nil
}

// createMigrator creates a migrator instance with the given repositories
func (s *Service) createMigrator(repos *gormrepo.Repositories) (*migration.Migrator, error) {
	migrator, err := migration.NewMigrator(&migration.MigratorConfig{
		DB:       repos.DB,
		Provider: strings.ToLower(s.config.Database.Provider),
		Logger:   s.logger,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create migrator: %w", err)
	}

	return migrator, nil
}

// withMigrator executes a function with a migrator instance, handling connection management
func (s *Service) withMigrator(ctx context.Context, fn func(*migration.Migrator) error) error {
	repos, err := s.createConnection()
	if err != nil {
		return err
	}
	defer repos.Close()

	migrator, err := s.createMigrator(repos)
	if err != nil {
		return err
	}
	defer migrator.Close()

	return fn(migrator)
}

// Up runs all pending migrations
func (s *Service) Up(ctx context.Context) error {
	s.logger.InfoContext(ctx, "Running database migrations up")
	return s.withMigrator(ctx, func(migrator *migration.Migrator) error {
		return migrator.Up(ctx)
	})
}

// Down runs one migration down
func (s *Service) Down(ctx context.Context) error {
	s.logger.InfoContext(ctx, "Running database migration down")
	return s.withMigrator(ctx, func(migrator *migration.Migrator) error {
		return migrator.Down(ctx)
	})
}

// Steps runs n migrations up (positive) or down (negative)
func (s *Service) Steps(ctx context.Context, n int) error {
	s.logger.InfoContext(ctx, "Running migration steps", "steps", n)
	return s.withMigrator(ctx, func(migrator *migration.Migrator) error {
		return migrator.Steps(ctx, n)
	})
}

// Version returns the current migration version and dirty state
func (s *Service) Version(ctx context.Context) (uint, bool, error) {
	var version uint
	var dirty bool
	err := s.withMigrator(ctx, func(migrator *migration.Migrator) error {
		var err error
		version, dirty, err = migrator.Version(ctx)
		return err
	})
	return version, dirty, err
}

// Force sets the migration version without running migrations
func (s *Service) Force(ctx context.Context, version int) error {
	s.logger.InfoContext(ctx, "Forcing migration version", "version", version)
	if version < 0 {
		return fmt.Errorf("version cannot be negative")
	}

	return s.withMigrator(ctx, func(migrator *migration.Migrator) error {
		return migrator.Force(ctx, version)
	})
}

// Drop drops all tables and schema
func (s *Service) Drop(ctx context.Context) error {
	s.logger.WarnContext(ctx, "Dropping all database tables - DESTRUCTIVE OPERATION")
	return s.withMigrator(ctx, func(migrator *migration.Migrator) error {
		return migrator.Drop(ctx)
	})
}

// GetMigrationInfo returns information about migration status
func (s *Service) GetMigrationInfo(ctx context.Context) (*domain.MigrationInfo, error) {
	var info *domain.MigrationInfo
	err := s.withMigrator(ctx, func(migrator *migration.Migrator) error {
		var err error
		info, err = migrator.GetMigrationInfo(ctx)
		return err
	})
	return info, err
}

// Close implements the MigrationService interface but is a no-op for this service
// since connections are managed per-operation
func (s *Service) Close() error {
	return nil
}

// IsDirty checks if the database is in a dirty state
func (s *Service) IsDirty(ctx context.Context) (bool, error) {
	_, dirty, err := s.Version(ctx)
	return dirty, err
}

// Reset drops all tables and re-runs all migrations
// WARNING: This operation is destructive and will delete all data
func (s *Service) Reset(ctx context.Context) error {
	s.logger.WarnContext(ctx, "Resetting database - DESTRUCTIVE OPERATION")

	// First drop all tables
	if err := s.Drop(ctx); err != nil {
		return fmt.Errorf("failed to drop database: %w", err)
	}

	// Then run all migrations
	if err := s.Up(ctx); err != nil {
		return fmt.Errorf("failed to run migrations after drop: %w", err)
	}

	return nil
}
