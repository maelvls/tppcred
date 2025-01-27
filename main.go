package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/maelvls/tppctl/undent"
	"github.com/spf13/cobra"
)

const (
	userAgent       = "tppctl/v0.0.1"
	usage           = `Usage: tppctl (auth|ls|edit|push|show|rm) [args]`
	requiredScope   = "configuration:manage;security:manage,delete"
	expirationYears = 20 // 20 years.
)

func authCmd() *cobra.Command {
	cmdFlags := AuthCmdCLIFlags{}
	cmd := &cobra.Command{
		Use:   "auth [--url <url>] [--username <username>] [--password <password>] --client-id <client-id>",
		Short: "Authenticate to TPP and save credentials.",
		Long: undent.Undent(`
			Authenticate to TPP and save credentials. The credentials are saved in
			~/.config/tppctl.yaml.

			When run without arguments, the command will prompt you for the URL,
			username, password, and client ID.

			The client ID must be associated with an API Integration that accepts
			the scope 'configuration:manage;security:manage,delete'.

			The URL must not include the suffix '/vedsdk'.

			The TPP user must be a super admin if you want to run 'tppctl ls'.

			Example:
			  tppctl auth
			  tppctl auth --url https://tpp.example.com --username admin --password admin --client-id my-client-id

			Alternatively, you can provide the configuration using environment
			variables. For example:
			  export TPP_URL=https://tpp.example.com USERNAME=admin PASSWORD=admin CLIENT_ID=my-client-id
			  tppctl auth
		`),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          runAuthCmd(&cmdFlags),
	}
	authCmdSetupFlags(cmd.Flags(), &cmdFlags)
	return cmd
}

func runAuthCmd(cmdFlags *AuthCmdCLIFlags) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		conf, err := AuthCmdLoad(cmdFlags)
		if err != nil {
			return fmt.Errorf("while loading configuration: %v\n", err)
		}

		if conf.ClientID == "" {
			conf.ClientID = "vcert-sdk"
		}

		var fields []huh.Field

		// Let's let the user know if the username and password already work,
		// and offer to abort.
		_, err = getToken(conf.URL, conf.Username, conf.Password, conf.ClientID)
		if err == nil {
			fields = append(fields, huh.NewNote().
				Title("🎉 Your credentials are already working. You can still update them if you want."),
			)
		}
		fields = append(fields,
			huh.NewInput().
				Prompt("URL: ").
				Description("Do not add the suffix '/vedsdk'.").
				Value(&conf.URL),
			huh.NewInput().
				Prompt("Username: ").
				Description("The TPP user must be a super admin if you want to run 'tppctl ls'.").
				Value(&conf.Username),
			huh.NewInput().
				Prompt("Password: ").
				EchoMode(huh.EchoModePassword).
				Description("The password will be stored in plain text in ~/"+configPath).
				Value(&conf.Password),
			huh.NewInput().
				Prompt("Client ID: ").
				Description("The API Integration associated to your client ID must accept the scope "+requiredScope+".").
				Value(&conf.ClientID),
		)
		f := huh.NewForm(huh.NewGroup(fields...))
		err = f.Run()
		if err != nil {
			return err
		}

		err = SaveFileConf(conf.ToFileConf())
		if err != nil {
			return fmt.Errorf("while saving configuration: %v\n", err)
		}

		token, err := getToken(conf.URL, conf.Username, conf.Password, conf.ClientID)
		if err != nil {
			return fmt.Errorf("while while authenticating: %v\n", err)
		}
		conf.Token = token

		err = SaveFileConf(conf.ToFileConf())
		if err != nil {
			return fmt.Errorf("while saving configuration: %v\n", err)
		}
		return nil
	}
}

func lsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List the Generic Credentials objects across all folders in TPP",
		Long: undent.Undent(`
			List the Generic Credentials objects across all folders in TPP.

			Do not forget to add the prefix '\VED\Policy' to the path if you are using
			TPP's built-in credential store.

			You need to authenticate using a super admin user to run this command.
		`),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			token, tppURL, err := GetTokenUsingFileConf()
			if err != nil {
				return err
			}

			objs, err := listObjects(tppURL, token)
			if err != nil {
				return err
			}
			for _, obj := range objs {
				fmt.Println(obj)
			}

			return nil
		},
	}
}

func editCmd() *cobra.Command {
	return &cobra.Command{
		Use:           "edit <credPath>",
		Short:         "Edit a Generic Credential",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf(`expected argument: credential path, e.g., \VED\Policy\Firefly\config.yaml`)
			}

			token, tppURL, err := GetTokenUsingFileConf()
			if err != nil {
				return fmt.Errorf("while authenticating: %v\n", err)
			}

			err = editConfigInCred(tppURL, token, args[0])
			if err != nil {
				return err
			}

			return nil
		},
	}
}

func pushCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "push <credPath>",
		Short: "Push YAML configuration to a Generic Credential",
		Long: undent.Undent(fmt.Sprintf(`
			Pushes the contents of a YAML file to a Generic Credential. If the Generic
			Credential does not exist, it will be created with an expiration date of
			%d years from now and a password set to foo. If the Generic Credential
			already exists, it will be updated.

			Do not forget to add the prefix '\VED\Policy' to the path if you are using
			TPP's built-in credential store.

			Example:
			  cat config.yaml | tppctl push '\VED\Policy\firefly\configs\config-prod'
		`, expirationYears)),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf(`expected argument: credential path, e.g., \VED\Policy\Firefly\config.yaml`)
			}
			credPath := args[0]

			token, tppURL, err := GetTokenUsingFileConf()
			if err != nil {
				return fmt.Errorf("while authenticating: %v\n", err)
			}

			// Get the contents from stdin.
			yamlBlob, err := io.ReadAll(os.Stdin)
			if err != nil {
				return err
			}

			// When the value's type is 'byte[]', TPP will not accept an empty
			// value. So, let's check that the YAML blob is not empty.
			if len(yamlBlob) == 0 {
				return fmt.Errorf("the YAML blob is empty, TPP cannot store an empty value in a Generic Credential\n")
			}

			credResp, err := getCred(tppURL, token, credPath)
			switch {
			case isNotFoundCred(err):
				// Credential does not exist: let's create the credential.
				err := createCred(tppURL, token, credPath, Credential{
					FriendlyName: "Generic",
					Values: []Value{
						{
							Name:  "Generic",
							Type:  "byte[]",
							Value: base64.StdEncoding.EncodeToString(yamlBlob),
						},
						{
							Name:  "Password",
							Type:  "string",
							Value: "foo",
						},
					},
					Expiration: DotNetUnixTime(time.Now().AddDate(expirationYears, 0, 0)),
				})
				if err != nil {
					return err
				}
			case err != nil:
				return err
			default:
				// Credential already exists: let's update the credential.
				err = updateCred(tppURL, token, credPath, *credResp)
				if err != nil {
					return err
				}
			}

			return nil
		},
	}
}

func showCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <credPath>",
		Short: "Shows the contents of a Generic Credential",
		Long: undent.Undent(`
			Shows the contents of a Generic Credential. Do not forget to
			add the prefix '\VED\Policy' to the path if you are using TPP's
			built-in credential store.

			Example:
			  tppctl show '\VED\Policy\firefly\configs\config-prod'
		`),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf(`expected argument: credential path, e.g., \VED\Policy\Firefly\config.yaml`)
			}
			credPath := args[0]

			token, tppURL, err := GetTokenUsingFileConf()
			if err != nil {
				return fmt.Errorf("while authenticating: %v\n", err)
			}

			credResp, err := getCred(tppURL, token, credPath)
			if err != nil {
				return err
			}

			// Get the Values[0].Value, and base64-decode it.
			if len(credResp.Values) == 0 {
				return fmt.Errorf("no values found in %q\n", credPath)
			}

			yamlBlob, err := base64.StdEncoding.DecodeString(credResp.Values[0].Value)
			if err != nil {
				return fmt.Errorf("while decoding the value 'Values[0].Value' within the Generic Credential '%s': %v\n", credPath, err)
			}

			fmt.Printf("%s", yamlBlob)
			return nil
		},
	}
}

func rmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <credPath>",
		Short: "Remove the specified Generic Credential",
		Long: undent.Undent(`
			Removes the specified Generic Credential. Do not forget to
			add the prefix '\VED\Policy' to the path if you are using TPP's
			built-in credential store.

			Example:
			  tppctl rm '\VED\Policy\firefly\configs\config-prod'
		`),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf(`expected argument: credential path, e.g., \VED\Policy\Firefly\config.yaml`)
			}
			credPath := args[0]

			token, tppURL, err := GetTokenUsingFileConf()
			if err != nil {
				return fmt.Errorf("while authenticating: %w\n", err)
			}

			fmt.Printf("Deleting '%s'\n", credPath)

			err = RmCred(tppURL, token, credPath)
			if err != nil {
				return err
			}

			return nil
		},
	}
}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "tppctl",
		Short: "tppctl helps you handle Generic Credentials.",
		Long: undent.Undent(`
			tppctl helps you handle Generic Credentials in Venafi Trust Protection Platform (TPP).
			To get started, run:

			    tppctl auth
		`),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	rootCmd.AddCommand(authCmd(), lsCmd(), editCmd(), pushCmd(), showCmd(), rmCmd())

	err := rootCmd.Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func editConfigInCred(tppURL, token, credPath string) error {
	credResp, err := getCred(tppURL, token, credPath)
	if err != nil {
		return fmt.Errorf("while fetching %s: %w", credPath, err)
	}

	// Get the Values[0].Value, and base64-decode it. This is the YAML blob that
	// we want to edit.
	if len(credResp.Values) == 0 {
		return fmt.Errorf("no values found in '%s'", credPath)
	}
	yamlBlob, err := base64.StdEncoding.DecodeString(credResp.Values[0].Value)
	if err != nil {
		return fmt.Errorf("while base64-decoding the field 'Values[0].Value': %w", err)
	}

	tmpfile, err := os.CreateTemp("", "vcp-*.yaml")
	if err != nil {
		return err
	}
	defer os.Remove(tmpfile.Name())
	if _, err := tmpfile.Write(yamlBlob); err != nil {
		return err
	}
	tmpfile.Close()

	// Open editor to let you edit YAML.
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vim"
	}
	cmd := exec.Command("sh", "-c", editor+" "+tmpfile.Name())
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	// Read and parse the modified YAML.
	yamlBlob, err = os.ReadFile(tmpfile.Name())
	if err != nil {
		return err
	}

	credResp.Values[0].Value = base64.StdEncoding.EncodeToString(yamlBlob)

	err = updateCred(tppURL, token, credPath, *credResp)
	if err != nil {
		return fmt.Errorf("while patching Firefly configuration: %w", err)
	}

	return nil
}
