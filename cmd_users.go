package main

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/spf13/cobra"
)

func usersSubSubCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "users",
		Short: "Manage users",
		Long:  `Manage users in TPP`,
	}
	cmd.AddCommand(findUserCmd())
	return cmd
}

func findUserCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "find",
		Short: "Find a user in TPP",
		Long: `
			Find a user in TPP by username. The username must be an exact match.
		`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("expected argument: username")
			}
			username := args[0]

			token, tppURL, err := GetTokenUsingFileConf()
			if err != nil {
				return fmt.Errorf("while authenticating: %v\n", err)
			}

			users, err := findUsers(tppURL, token, username)
			if err != nil {
				return fmt.Errorf("while finding user using filter '%s': %v\n", username, err)
			}

			if len(users) == 0 {
				fmt.Printf("No user found with username '%s'\n", username)
				return nil
			}

			var rows [][]string
			for _, user := range users {
				rows = append(rows, []string{user.PrefixedUniversal, user.PrefixedName})
			}

			t := table.New().
				Border(lipgloss.NormalBorder()).
				Headers("Prefixed Universal", "Prefixed Name").
				Rows(rows...)

			fmt.Println(t.Render())
			return nil
		},
	}
}
