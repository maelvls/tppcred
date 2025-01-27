package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/charmbracelet/huh"
)

const (
	userAgent     = "tppctl/v0.0.1"
	usage         = `Usage: tppctl (auth|ls|edit|push|show|rm) [args]`
	requiredScope = "configuration:manage;security:manage,delete"
)

func main() {
	flag.CommandLine.Usage = func() {
		fmt.Println(usage)
	}
	authCmd := flag.NewFlagSet("auth", flag.ExitOnError)
	authCmd.Usage = func() {
		fmt.Println("Usage: tppctl auth [--url <url>] [--username <username>] [--password <password>]")
	}
	lsCmd := flag.NewFlagSet("ls", flag.ExitOnError)
	lsCmd.Usage = func() {
		fmt.Println("Usage: tppctl ls")
	}
	editCmd := flag.NewFlagSet("edit", flag.ExitOnError)
	editCmd.Usage = func() {
		fmt.Println(`Usage: tppctl edit '\VED\Policy\firefly\config.yaml'`)
	}
	pushCmd := flag.NewFlagSet("push", flag.ExitOnError)
	pushCmd.Usage = func() {
		fmt.Println(`Usage: tppctl push '\VED\Policy\firefly\config.yaml' <config.yaml`)
	}
	show := flag.NewFlagSet("show", flag.ExitOnError)
	show.Usage = func() {
		fmt.Println(`Usage: tppctl show '\VED\Policy\firefly\config.yaml'`)
	}
	rmCmd := flag.NewFlagSet("rm", flag.ExitOnError)
	rmCmd.Usage = func() {
		fmt.Println(`Usage: tppctl rm '\VED\Policy\firefly\config.yaml'`)
	}

	if len(os.Args) < 2 {
		fmt.Println("Please give a subcommand: ls, edit, push, rm, show")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "-h", "--help":
		flag.CommandLine.Usage()
	case "auth":
		flags := AuthCmdSetup(authCmd)

		authCmd.Parse(os.Args[2:])

		conf, err := AuthCmdLoad(flags)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
			os.Exit(1)
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
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		err = SaveFileConf(conf.ToFileConf())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error saving configuration: %v\n", err)
			os.Exit(1)
		}

		token, err := getToken(conf.URL, conf.Username, conf.Password, conf.ClientID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while authenticating: %v\n", err)
			os.Exit(1)
		}
		conf.Token = token

		err = SaveFileConf(conf.ToFileConf())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error saving configuration: %v\n", err)
			os.Exit(1)
		}

		authCmd.Parse(os.Args[2:])

	// Usage: tppctl ls
	case "ls":
		lsCmd.Parse(os.Args[2:])

		token, tppURL, err := GetTokenUsingFileConf()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		objs, err := listObjects(tppURL, token)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		for _, obj := range objs {
			fmt.Println(obj)
		}

	// Usage: tppctl edit '\VED\Policy\firefly\config.yaml'
	case "edit":
		editCmd.Parse(os.Args[2:])
		if editCmd.NArg() < 1 {
			fmt.Println(`Expected credential path, e.g., \VED\Policy\Firefly\config.yaml`)
			os.Exit(1)
		}

		token, tppURL, err := GetTokenUsingFileConf()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: while authenticating: %v\n", err)
			os.Exit(1)
		}

		if err := editConfigInCred(tppURL, token, editCmd.Arg(0)); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	// Usage: tppctl push '\VED\Policy\firefly\config.yaml' <config.yaml
	case "push":
		pushCmd.Parse(os.Args[2:])
		if pushCmd.NArg() < 1 {
			fmt.Println(`Expected credential path, e.g., \VED\Policy\Firefly\config.yaml`)
			os.Exit(1)
		}
		credPath := pushCmd.Arg(0)

		token, tppURL, err := GetTokenUsingFileConf()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: while authenticating: %v\n", err)
			os.Exit(1)
		}

		// Get the contents from stdin.
		yamlBlob, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		// When the value's type is 'byte[]', TPP will not accept an empty
		// value. So, let's check that the YAML blob is not empty.
		if len(yamlBlob) == 0 {
			fmt.Fprintf(os.Stderr, "Error: the YAML blob is empty, TPP cannot store an empty value in a Generic Credential\n")
			os.Exit(1)
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
				// 20 years from now.
				Expiration: DotNetUnixTime(time.Now().AddDate(20, 0, 0)),
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		case err != nil:
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		default:
			// Credential already exists: let's update the credential.
			err = updateCred(tppURL, token, credPath, *credResp)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		}

	case "show":
		show.Parse(os.Args[2:])
		if show.NArg() < 1 {
			fmt.Println(`Expected credential path, e.g., \VED\Policy\Firefly\config.yaml`)
			os.Exit(1)
		}
		credPath := show.Arg(0)

		token, tppURL, err := GetTokenUsingFileConf()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: while authenticating: %v\n", err)
			os.Exit(1)
		}

		credResp, err := getCred(tppURL, token, credPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		// Get the Values[0].Value, and base64-decode it.
		if len(credResp.Values) == 0 {
			fmt.Fprintf(os.Stderr, "Error: no values found in %q\n", credPath)
			os.Exit(1)
		}

		yamlBlob, err := base64.StdEncoding.DecodeString(credResp.Values[0].Value)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: while decoding the value 'Values[0].Value' within the Generic Credential '%s': %v\n", credPath, err)
			os.Exit(1)
		}

		fmt.Printf("%s", yamlBlob)

	case "rm":
		rmCmd.Parse(os.Args[2:])
		if rmCmd.NArg() < 1 {
			fmt.Println(`Expected credential path, e.g., \VED\Policy\Firefly\config.yaml`)
			os.Exit(1)
		}
		credPath := rmCmd.Arg(0)

		token, tppURL, err := GetTokenUsingFileConf()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: while authenticating: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Deleting %q\n", credPath)

		err = RmCred(tppURL, token, credPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
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
		return fmt.Errorf("error base64-decoding the field 'Values[0].Value': %w", err)
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
