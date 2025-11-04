package commands

import (
	"fmt"
	"log/slog"
	"slices"

	"github.com/GoBetterAuth/go-better-auth/domain"
	migrationService "github.com/GoBetterAuth/go-better-auth/usecase/migration"
)

// MigratorConfig holds configuration for creating migration services
type MigratorConfig struct {
	CreateService func() *migrationService.Service
	Provider      *string
	ConnStr       *string
	LogQueries    *bool
	Version       *string
	Steps         *int
}

// CreateMigrationService creates a migration service using current configuration
func (c *MigratorConfig) CreateMigrationService(logger *slog.Logger) (*migrationService.Service, error) {
	// Validate configuration
	if err := c.validateConfig(); err != nil {
		return nil, err
	}

	config := &domain.Config{
		Database: domain.DatabaseConfig{
			Provider:         *c.Provider,
			ConnectionString: *c.ConnStr,
			LogQueries:       *c.LogQueries,
		},
	}

	return migrationService.NewService(config, logger), nil
}

// validateConfig validates the CLI configuration
func (c *MigratorConfig) validateConfig() error {
	// Validate provider
	validProviders := []string{"sqlite", "postgres"}
	provider := *c.Provider
	isValid := slices.Contains(validProviders, provider)
	if !isValid {
		return fmt.Errorf("invalid database provider '%s', valid options: %v", provider, validProviders)
	}

	// Validate connection string
	if *c.ConnStr == "" {
		return fmt.Errorf("database connection string cannot be empty")
	}

	return nil
}
