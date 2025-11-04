package commands

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"
)

func InitDropCmd(config *MigratorConfig) *cobra.Command {
	return &cobra.Command{
		Use:   "drop",
		Short: "Drop all tables (DESTRUCTIVE)",
		Long:  "Drop all database tables. This action is irreversible and will delete all data.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			logger := slog.Default()

			fmt.Println("⚠️  WARNING: This will DROP ALL TABLES in the database!")
			fmt.Println("This action is IRREVERSIBLE and will delete all your data.")
			fmt.Print("Type 'yes' to confirm: ")

			var confirmation string
			fmt.Scanln(&confirmation)

			if confirmation != "yes" {
				logger.InfoContext(ctx, "Operation cancelled")
				return nil
			}

			migrationService, err := config.CreateMigrationService(logger)
			if err != nil {
				logger.ErrorContext(ctx, "Failed to create migration service", "error", err)
				return err
			}
			defer migrationService.Close()

			logger.WarnContext(ctx, "Dropping all tables - THIS WILL DELETE ALL DATA")
			if err := migrationService.Drop(ctx); err != nil {
				logger.ErrorContext(ctx, "Failed to drop tables", "error", err)
				return err
			}

			logger.InfoContext(ctx, "All tables dropped successfully - DATABASE IS NOW EMPTY")
			return nil
		},
	}
}
