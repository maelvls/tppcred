package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// This CLI stores its authentication information in ~/.config/tppctl.yaml.
const configPath = ".config/tppctl.yaml"

type FileConf struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
	ClientID string `json:"client_id"`
	Token    string `json:"token"`
}

func LoadFileConf() (FileConf, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return FileConf{}, fmt.Errorf("while getting user's home directory: %w", err)
	}

	configPath := home + "/.config/tppctl.yaml"
	f, err := os.Open(configPath)
	if os.IsNotExist(err) {
		return FileConf{}, nil
	}
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
