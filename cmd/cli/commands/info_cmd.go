package commands

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/spf13/cobra"
)

// maskConnectionString masks sensitive parts of connection strings
func maskConnectionString(connStr string) string {
	if strings.Contains(connStr, "password=") {
		parts := strings.Split(connStr, " ")
		for i, part := range parts {
			if strings.HasPrefix(part, "password=") {
				parts[i] = "password=***"
			}
		}
		return strings.Join(parts, " ")
	}
	// For SQLite, just show the filename
	if !strings.Contains(connStr, "://") && !strings.Contains(connStr, "=") {
		return connStr
	}
	return "***"
}

func InitInfoCmd(config *MigratorConfig) *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Show migration status",
		Long:  "Display current migration version and database status information.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			logger := slog.Default()
			logger.InfoContext(ctx, "Getting migration information")

			migrationService, err := config.CreateMigrationService(logger)
			if err != nil {
				logger.ErrorContext(ctx, "Failed to create migration service", "error", err)
				return err
			}
			defer migrationService.Close()

			currentVersion, dirty, err := migrationService.Version(ctx)
			if err != nil {
				logger.ErrorContext(ctx, "Failed to get migration info", "error", err)
				return err
			}

			fmt.Println("Database Migration Information:")
			fmt.Println("===============================")
			fmt.Printf("Provider:        %s\n", *config.Provider)
			fmt.Printf("Connection:      %s\n", maskConnectionString(*config.ConnStr))
			fmt.Printf("Current Version: %d\n", currentVersion)
			fmt.Printf("Dirty:          %t\n", dirty)

			if dirty {
				fmt.Println("⚠️  WARNING: Database is in a dirty state!")
				fmt.Println("   This usually means a migration failed partway through.")
				fmt.Println("   You may need to manually fix the database or use the 'force' command.")
			} else {
				fmt.Println("✅ Database is in a clean state.")
			}

			if info, err := migrationService.GetMigrationInfo(ctx); err == nil && info != nil {
				fmt.Printf("Additional Info: %+v\n", info)
			}

			return nil
		},
	}
}
