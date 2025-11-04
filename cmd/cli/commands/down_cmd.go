package commands

import (
	"log/slog"

	"github.com/spf13/cobra"
)

func InitDownCmd(config *MigratorConfig) *cobra.Command {
	return &cobra.Command{
		Use:   "down",
		Short: "Rollback migrations",
		Long:  "Rollback one or more database migrations.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			steps := *config.Steps
			logger := slog.Default()
			logger.InfoContext(ctx, "Rolling back migration", "steps", steps)

			migrationService, err := config.CreateMigrationService(logger)
			if err != nil {
				logger.ErrorContext(ctx, "Failed to create migration service", "error", err)
				return err
			}
			defer migrationService.Close()

			currentVersion, _, err := migrationService.Version(ctx)
			if err != nil {
				logger.ErrorContext(ctx, "Failed to get current version", "error", err)
				return err
			}

			if currentVersion == 0 {
				logger.WarnContext(ctx, "No migrations to rollback - database is already at version 0")
				return nil
			}

			// Rollback specified number of steps using the Steps method with negative value
			if err := migrationService.Steps(ctx, -steps); err != nil {
				logger.ErrorContext(ctx, "Failed to rollback migrations", "steps", steps, "error", err)
				return err
			}

			logger.InfoContext(ctx, "Migration rollback completed successfully", "steps_rolled_back", steps)
			return nil
		},
	}
}
