package commands

import "github.com/spf13/cobra"

func InitRootCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "go-better-auth-cli",
		Short: "Go Better Auth CLI Tool",
		Long:  `A CLI tool for Go Better Auth.`,
	}
}
