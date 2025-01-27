package main

import (
	"fmt"
	"os"

	"github.com/spf13/pflag"
)

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
		return "", "", fmt.Errorf("not authenticated. Please run `tppctl auth`.")
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
