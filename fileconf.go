package main

import (
	"fmt"
	"os"
	"path"

	"gopkg.in/yaml.v3"
)

// This CLI stores its authentication information in ~/.config/tppcred.yaml.
const configPath = ".config/tppcred.yaml"

// For backwards compatibility, if an ~/.config/tppctl.yaml is found, it will be
// renamed to ~/.config/tppcred.yaml.
const configPathOld = ".config/tppctl.yaml"

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

	// Backwards compatibility: if ~/.config/tppctl.yaml exists, rename it to
	// ~/.config/tppcred.yaml.
	_, err = os.Stat(path.Join(home, configPathOld))
	switch {
	case os.IsNotExist(err):
		// Do nothing.
	case err != nil:
		return FileConf{}, fmt.Errorf("while checking for the presence of ~/%s: %w", configPathOld, err)
	default:
		fmt.Fprintf(os.Stderr, "found a config file at ~/%s, renaming it to ~/%s as 'tppctl' was renamed to 'tppcred'\n", configPathOld, configPath)
		err = os.Rename(path.Join(home, configPathOld), path.Join(home, configPath))
		if err != nil {
			return FileConf{}, fmt.Errorf("while renaming ~/%s to ~/%s: %w", configPathOld, configPath, err)
		}
	}

	f, err := os.Open(path.Join(home, configPath))
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

	f, err := os.Create(path.Join(home, configPath))
	if err != nil {
		return fmt.Errorf("while creating ~/%s: %w", configPath, err)
	}
	defer f.Close()

	if err := yaml.NewEncoder(f).Encode(conf); err != nil {
		return fmt.Errorf("while encoding ~/%s: %w", configPath, err)
	}

	return nil
}
