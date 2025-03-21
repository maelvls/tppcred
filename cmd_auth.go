package main

import (
	"fmt"
	"os"

	"github.com/charmbracelet/huh"
	"github.com/maelvls/tppcred/undent"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func authCmd() *cobra.Command {
	cmdFlags := AuthCmdCLIFlags{}
	cmd := &cobra.Command{
		Use:   "auth [--url <url>] [--username <username>] [--password <password>] --client-id <client-id>",
		Short: "Authenticate to TPP and save credentials.",
		Long: undent.Undent(`
			Authenticate to TPP and save credentials. The credentials are saved in
			~/.config/tppcred.yaml.

			When run without arguments, the command will prompt you for the URL,
			username, password, and client ID.

			The client ID must be associated with an API Integration that accepts
			the scope 'configuration:manage;security:manage,delete'.

			The URL must not include the suffix '/vedsdk'.

			The TPP user must be a super admin if you want to run 'tppcred ls'.

			Example:
			  tppcred auth
			  tppcred auth --url https://tpp.example.com --username admin --password admin --client-id my-client-id

			Alternatively, you can provide the configuration using environment
			variables. For example:
			  export TPP_URL=https://tpp.example.com USERNAME=admin PASSWORD=admin CLIENT_ID=my-client-id
			  tppcred auth
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
				Description("The TPP user must be a super admin if you want to run 'tppcred ls'.").
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

type AuthCmdCLIFlags struct {
	URL      string
	Token    string
	Username string // Used by the `auth` command to renew the token.
	Password string // Used by the `auth` command to renew the token.
	ClientID string // Used by the `auth` command to renew the token.
}

type AuthCmdResultConf struct {
	URL      string
	Token    string
	Username string
	Password string
	ClientID string
}

func authCmdSetupFlags(f *pflag.FlagSet, fl *AuthCmdCLIFlags) {
	f.StringVar(&fl.URL, "url", "", "The TPP URL")
	f.StringVar(&fl.Username, "username", "", "The TPP username")
	f.StringVar(&fl.Password, "password", "", "The TPP password")
	f.StringVar(&fl.ClientID, "client-id", "", "The TPP client ID (also called the API Integration)")
}

// Env vars take precedence over the configuration file ~/.config/tppctl.yaml.
// This func is just used by the `auth` command. The other commands use
// LoadNormalConf. Does the flag.Parse() for you.
func AuthCmdLoad(cliFlags *AuthCmdCLIFlags) (AuthCmdResultConf, error) {
	var result AuthCmdResultConf
	// First, load the file.
	conf, err := LoadFileConf()
	if err != nil {
		fmt.Println("Error loading configuration file:", err)
	}
	result.URL = conf.URL
	result.Username = conf.Username
	result.Password = conf.Password
	result.ClientID = conf.ClientID

	// Then, load the environment. The env vars take precedence.
	envURL := os.Getenv("TPP_URL")
	if envURL != "" {
		result.URL = conf.URL
	}
	envUsername := os.Getenv("USERNAME")
	if envUsername != "" {
		result.Username = envUsername
	}
	envPassword := os.Getenv("PASSWORD")
	if envPassword != "" {
		result.Password = envPassword
	}
	envClientID := os.Getenv("CLIENT_ID")
	if envClientID != "" {
		result.ClientID = envClientID
	}

	// Finally, look at the CLI flags. These take precedence over the env vars.
	if cliFlags.URL != "" {
		result.URL = cliFlags.URL
	}
	if cliFlags.Username != "" {
		result.Username = cliFlags.Username
	}
	if cliFlags.Password != "" {
		result.Password = cliFlags.Password
	}
	if cliFlags.ClientID != "" {
		result.ClientID = cliFlags.ClientID
	}

	return result, nil
}

func (c AuthCmdResultConf) ToFileConf() FileConf {
	return FileConf{
		URL:      c.URL,
		Username: c.Username,
		Password: c.Password,
		ClientID: c.ClientID,
		Token:    c.Token,
	}
}

// Also requests a new token if the token is empty.
func GetTokenUsingFileConf() (url, token string, _ error) {
	conf, err := LoadFileConf()
	if err != nil {
		return "", "", fmt.Errorf("loading configuration: %w", err)
	}

	if conf.URL == "" || conf.Username == "" || conf.Password == "" || conf.ClientID == "" {
		return "", "", fmt.Errorf("not authenticated. Please run `tppcred auth`.")
	}

	// Let's check if the token is valid.
	err = checkToken(conf.URL, conf.Token)
	if err == nil {
		return conf.Token, conf.URL, nil
	}

	// If the token is invalid, let's request a new one and save it.
	token, err = getToken(conf.URL, conf.Username, conf.Password, conf.ClientID)
	if err != nil {
		return "", "", fmt.Errorf("getting token: %w", err)
	}
	conf.Token = token

	err = SaveFileConf(conf)
	if err != nil {
		return "", "", fmt.Errorf("saving token: %w", err)
	}

	return conf.Token, conf.URL, nil
}
