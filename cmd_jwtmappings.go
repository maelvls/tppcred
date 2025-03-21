package main

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/maelvls/tppcred/undent"
	"github.com/spf13/cobra"
)

func jwtMappingsSubCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jwtmappings",
		Short: "Manage JWT mappings",
		Long:  `Manage JWT mappings in TPP`,
	}
	cmd.AddCommand(jwtMappingsSetCmd(), jwtMappingsRmCmd(), jwtMappingsLsCmd())
	return cmd
}

func jwtMappingsSetCmd() *cobra.Command {
	var jwtSub, jwtAud, jwtIss, userFilter string
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Create or update a JWT mapping",
		Long: undent.Undent(`
			Create or update a JWT mapping in TPP. If the user is a local user,
			the 'local:' prefix can be omitted. Examples of users:

			  my-user
			  local:my-user
			  local:{77a4cdda-12f2-4d83-aaff-8a3682d014cc}
			  AD+prod:my-user

			Remember that the user calling 'tppcred' must be in the same domain
			as the user you are trying to associate with the JWT mapping;
			for example, if 'tppcred' is authenticated with a local user, you won't
			be able to associate an AD user with the JWT mapping. You will need
			to authenticate with an AD user.

			Example:
			  tppcred jwtmappings set --name foo --sub sub --aud tpp --iss iss --user local:my-user
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			token, tppURL, err := GetTokenUsingFileConf()
			if err != nil {
				return fmt.Errorf("while authenticating: %v\n", err)
			}

			// Get the positional argument.
			if len(args) != 1 {
				return fmt.Errorf("expected argument: JWT mapping name")
			}
			jwtMappingName := args[0]

			// Find the user.
			users, err := findUsers(tppURL, token, userFilter)
			if err != nil {
				return fmt.Errorf("while finding user using filter '%s': %v\n", userFilter, err)
			}
			if len(users) == 0 {
				return fmt.Errorf("no user found with filter '%s'", userFilter)
			}
			user := users[0]

			mapping := JWTMapping{
				Name:                     jwtMappingName,
				IDField:                  "sub",
				IDMatch:                  jwtSub,
				IssuerURI:                jwtIss,
				PurposeField:             "aud",
				PurposeMatch:             jwtAud,
				GranteePrefixedUniversal: user.PrefixedUniversal,
			}

			// List existing mappings to check if the mapping exists.
			mappings, err := listJWTMappings(tppURL, token)
			if err != nil {
				return err
			}

			exists := false
			for _, m := range mappings {
				if m.Name == jwtMappingName {
					exists = true
					mapping.GranteePrefixedUniversal = m.GranteePrefixedUniversal // Preserve the GranteePrefixedUniversal
					break
				}
			}

			if exists {
				err := updateJWTMapping(tppURL, token, mapping)
				if err != nil {
					return fmt.Errorf("error updating JWT mapping: %w", err)
				}
				fmt.Println("JWT mapping updated successfully")
			} else {
				err := createJwtMapping(tppURL, token, JWTMapping{
					Name:                     jwtMappingName,
					IDField:                  "sub",
					IDMatch:                  jwtSub,
					IssuerURI:                jwtIss,
					PurposeField:             "aud",
					PurposeMatch:             jwtAud,
					GranteePrefixedUniversal: user.PrefixedUniversal,
				})
				if err != nil {
					return fmt.Errorf("error creating JWT mapping: %w", err)
				}
				fmt.Println("JWT mapping created successfully")
			}

			return nil
		},
	}
	cmd.Flags().StringVar(&jwtSub, "sub", "", "JWT Subject (sub)")
	cmd.Flags().StringVar(&jwtAud, "aud", "", "JWT Audience (aud)")
	cmd.Flags().StringVar(&jwtIss, "iss", "", "JWT Issuer (iss)")
	cmd.Flags().StringVar(&userFilter, "user", "", "User to associate with the JWT mapping")
	cmd.MarkFlagRequired("name")
	cmd.MarkFlagRequired("sub")
	cmd.MarkFlagRequired("aud")
	cmd.MarkFlagRequired("iss")

	return cmd
}

func jwtMappingsRmCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rm",
		Short: "Delete a JWT mapping",
		Long: undent.Undent(`
			Delete a JWT mapping in TPP.

			Example:
			  tppcred jwtmappings rm <name>
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			token, tppURL, err := GetTokenUsingFileConf()
			if err != nil {
				return fmt.Errorf("while authenticating: %v\n", err)
			}

			if len(args) != 1 {
				return fmt.Errorf("expected argument: JWT mapping name")
			}
			jwtMappingName := args[0]

			err = deleteJwtMapping(tppURL, token, jwtMappingName)
			if err != nil {
				return err
			}

			fmt.Println("JWT mapping deleted successfully")
			return nil
		},
	}

	return cmd
}

func jwtMappingsLsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List JWT mappings",
		Long:  `List JWT mappings in TPP`,
		RunE: func(cmd *cobra.Command, args []string) error {
			token, tppURL, err := GetTokenUsingFileConf()
			if err != nil {
				return fmt.Errorf("while authenticating: %v\n", err)
			}

			mappings, err := listJWTMappings(tppURL, token)
			if err != nil {
				return fmt.Errorf("while listing JWT mappings: %v\n", err)
			}

			users, err := listUsers(tppURL, token)
			if err != nil {
				return fmt.Errorf("while listing users: %v\n", err)
			}

			for i, m := range mappings {
				for _, u := range users {
					if m.GranteePrefixedUniversal == u.PrefixedUniversal {
						mappings[i].GranteePrefixedUniversal = u.PrefixedName
						break
					}
				}
			}

			var rows [][]string
			for _, m := range mappings {
				rows = append(rows, []string{m.Name, m.IDField + "=" + m.IDMatch, m.PurposeField + "=" + m.PurposeMatch, m.GranteePrefixedUniversal})
			}

			t := table.New().
				Border(lipgloss.NormalBorder()).
				Headers("Name", "Identity", "Audience", "TPP user").
				Rows(rows...)
			fmt.Println(t.String())
			return nil
		},
	}

	return cmd
}
