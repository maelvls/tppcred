package main

import (
	"flag"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type AuthCmdCLIFlags struct {
	URL      string
	Token    string
	Username string // Used by the `auth` command to renew the token.
	Password string // Used by the `auth` command to renew the token.
}

type AuthCmdResultConf struct {
	URL      string
	Token    string
	Username string
	Password string
}

func AuthCmdSetup(f *flag.FlagSet) *AuthCmdCLIFlags {
	var c AuthCmdCLIFlags
	f.StringVar(&c.URL, "url", "", "The TPP URL")
	f.StringVar(&c.Username, "username", "", "The TPP username")
	f.StringVar(&c.Password, "password", "", "The TPP password")
	return &c
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

	return result, nil
}

// This CLI stores its authentication information in ~/.config/tppctl.yaml.
const configPath = ".config/tppctl.yaml"

type FileConf struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
	Token    string `json:"token"`
}

func LoadFileConf() (FileConf, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return FileConf{}, fmt.Errorf("while getting user's home directory: %w", err)
	}

	configPath := home + "/.config/tppctl.yaml"
	f, err := os.Open(configPath)
	if err != nil {
		return FileConf{}, fmt.Errorf("while opening ~/%s: %w", configPath, err)
	}

	var conf FileConf
	if err := yaml.NewDecoder(f).Decode(&conf); err != nil {
		return FileConf{}, fmt.Errorf("while decoding ~/%s: %w", configPath, err)
	}

	return conf, nil
}

func SaveFileConf(conf FileConf) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("while getting user's home directory: %w", err)
	}

	configPath := home + "/.config/tppctl.yaml"
	f, err := os.Create(configPath)
	if err != nil {
		return fmt.Errorf("while creating ~/%s: %w", configPath, err)
	}
	defer f.Close()

	if err := yaml.NewEncoder(f).Encode(conf); err != nil {
		return fmt.Errorf("while encoding ~/%s: %w", configPath, err)
	}

	return nil
}
