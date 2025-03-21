package main

import (
	"fmt"
	"os"

	"github.com/maelvls/tppcred/undent"
	"github.com/spf13/cobra"
)

const (
	userAgent       = "tppcred/v0.0.1"
	requiredScope   = "configuration:manage;security:manage,delete;admin"
	expirationYears = 20 // 20 years.
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "tppcred",
		Short: "tppcred helps you handle Generic Credentials.",
		Long: undent.Undent(`
			tppcred helps you handle Generic Credentials in Venafi Trust Protection Platform (TPP).
			To get started, run:

			    tppcred auth
		`),
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.AddCommand(authCmd(), lsCmd(), editCmd(), pushCmd(), showCmd(), rmCmd(), jwtMappingsSubCmd(), usersSubSubCmd())

	err := rootCmd.Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
