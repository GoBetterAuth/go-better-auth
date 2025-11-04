package commands

import (
	"log/slog"

	"github.com/spf13/cobra"
)

func InitUpCmd(config *MigratorConfig) *cobra.Command {
	return &cobra.Command{
		Use:   "up",
		Short: "Run all pending migrations",
		Long:  "Run all pending database migrations to bring the schema up to date.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			logger := slog.Default()
			logger.InfoContext(ctx, "Running database migrations")

			migrationService, err := config.CreateMigrationService(logger)
			if err != nil {
				logger.ErrorContext(ctx, "Failed to create migration service", "error", err)
				return err
			}
			defer migrationService.Close()

			currentVersion, dirty, err := migrationService.Version(ctx)
			if err == nil {
				logger.InfoContext(ctx, "Current migration state", "version", currentVersion, "dirty", dirty)
				if dirty {
					logger.WarnContext(ctx, "Database is in a dirty state. You may need to use 'force' command to fix it.")
				}
			}

			if err := migrationService.Up(ctx); err != nil {
				logger.ErrorContext(ctx, "Failed to run migrations", "error", err)
				logger.ErrorContext(ctx, "If the database is in a dirty state, try using the 'force' command")
				return err
			}

			logger.InfoContext(ctx, "Migrations completed successfully")
			return nil
		},
	}
}
