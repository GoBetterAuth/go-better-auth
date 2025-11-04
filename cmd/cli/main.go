package main

import (
	"log/slog"
	"os"

	"github.com/GoBetterAuth/go-better-auth/cmd/cli/commands"
)

var (
	// Global flags
	provider   string
	connStr    string
	logQueries bool

	// Command-specific flags
	version string
	steps   int
)

// setupLogger configures structured logging
func setupLogger() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)
}

func main() {
	setupLogger()

	// Create configuration struct to pass to commands
	config := &commands.MigratorConfig{
		Provider:   &provider,
		ConnStr:    &connStr,
		LogQueries: &logQueries,
		Version:    &version,
		Steps:      &steps,
	}

	rootCmd := commands.InitRootCmd()
	migrateCmd := commands.InitMigrateCmd()
	upCmd := commands.InitUpCmd(config)
	downCmd := commands.InitDownCmd(config)
	dropCmd := commands.InitDropCmd(config)
	infoCmd := commands.InitInfoCmd(config)
	forceCmd := commands.InitForceCmd(config)

	// Global flags for migration
	migrateCmd.PersistentFlags().StringVarP(&provider, "provider", "p", "sqlite", "Database provider (sqlite, postgres)")
	migrateCmd.PersistentFlags().StringVarP(&connStr, "conn", "c", "app.db", "Database connection string")
	migrateCmd.PersistentFlags().BoolVarP(&logQueries, "log", "l", false, "Enable database query logging")

	// Command-specific flags
	downCmd.Flags().IntVarP(&steps, "steps", "s", 1, "Number of migration steps to rollback")
	forceCmd.Flags().StringVarP(&version, "version", "v", "", "Version number to force (required)")

	// Mark required flags
	forceCmd.MarkFlagRequired("version")

	// Add commands to migrate command
	migrateCmd.AddCommand(upCmd)
	migrateCmd.AddCommand(downCmd)
	migrateCmd.AddCommand(dropCmd)
	migrateCmd.AddCommand(infoCmd)
	migrateCmd.AddCommand(forceCmd)

	// Add migrate command to root
	rootCmd.AddCommand(migrateCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
