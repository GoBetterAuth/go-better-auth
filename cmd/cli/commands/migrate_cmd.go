package commands

import "github.com/spf13/cobra"

func InitMigrateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "migrate",
		Short: "Database migration commands",
		Long:  `A collection of commands for managing database migrations.`,
	}
}
