package commands

import (
	"fmt"
	"log/slog"
	"strconv"

	"github.com/spf13/cobra"
)

func InitForceCmd(config *MigratorConfig) *cobra.Command {
	return &cobra.Command{
		Use:   "force",
		Short: "Force migration to specific version",
		Long:  "Force the migration version to a specific number. This should only be used to fix a dirty database state.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			logger := slog.Default()
			version := *config.Version
			if version == "" {
				return fmt.Errorf("version is required for force command. Use --version flag")
			}

			v, err := strconv.Atoi(version)
			if err != nil {
				return fmt.Errorf("invalid version number '%s': must be a valid integer", version)
			}

			if v < 0 {
				return fmt.Errorf("version cannot be negative")
			}

			migrationService, err := config.CreateMigrationService(logger)
			if err != nil {
				logger.ErrorContext(ctx, "Failed to create migration service", "error", err)
				return err
			}
			defer migrationService.Close()

			currentVersion, dirty, err := migrationService.Version(ctx)
			if err == nil {
				logger.InfoContext(ctx, "Current migration state", "version", currentVersion, "dirty", dirty)
			}

			fmt.Printf("⚠️  WARNING: This will force the migration version to %d\n", v)
			fmt.Println("This should only be used to fix a dirty database state.")
			fmt.Print("Type 'yes' to confirm: ")

			var confirmation string
			fmt.Scanln(&confirmation)

			if confirmation != "yes" {
				logger.InfoContext(ctx, "Operation cancelled")
				return nil
			}

			logger.InfoContext(ctx, "Forcing migration version", "version", v)
			if err := migrationService.Force(ctx, v); err != nil {
				logger.ErrorContext(ctx, "Failed to force migration version", "error", err)
				return err
			}

			logger.InfoContext(ctx, "Migration version forced successfully", "version", v)
			return nil
		},
	}
}
