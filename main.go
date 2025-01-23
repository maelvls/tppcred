package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

const (
	userAgent = "tppctl/v0.0.1"
)

func main() {
	tppURL := os.Getenv("TPP_URL")
	if tppURL == "" {
		fmt.Println("TPP_URL needs to be set in the environment")
		os.Exit(1)
	}

	token := os.Getenv("TOKEN")
	if token == "" {
		fmt.Println("TOKEN needs to be set in the environment")
		os.Exit(1)
	}

	lsCmd := flag.NewFlagSet("ls", flag.ExitOnError)
	editCmd := flag.NewFlagSet("edit", flag.ExitOnError)
	pushCmd := flag.NewFlagSet("push", flag.ExitOnError)
	rmCmd := flag.NewFlagSet("rm", flag.ExitOnError)
	read := flag.NewFlagSet("read", flag.ExitOnError)

	if len(os.Args) < 2 {
		fmt.Println("Please give a subcommand: ls, edit, push, rm, read")
		os.Exit(1)
	}

	switch os.Args[1] {
	// Usage: tppctl ls
	case "ls":
		lsCmd.Parse(os.Args[2:])
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
	case "rm":
		rmCmd.Parse(os.Args[2:])
		if rmCmd.NArg() < 1 {
			fmt.Println(`Expected credential path, e.g., \VED\Policy\Firefly\config.yaml`)
			os.Exit(1)
		}
		credPath := rmCmd.Arg(0)
		fmt.Printf("Deleting %q\n", credPath)

		err := RmCred(tppURL, token, credPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "read":
		read.Parse(os.Args[2:])
		if read.NArg() < 1 {
			fmt.Println(`Expected credential path, e.g., \VED\Policy\Firefly\config.yaml`)
			os.Exit(1)
		}
		credPath := read.Arg(0)

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
	cmd := exec.Command(editor, tmpfile.Name())
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

type Credential struct {
	Contact      []Contact `json:"Contact"`
	FriendlyName string    `json:"FriendlyName"`
	Values       []Value   `json:"Values"`
}
type Contact struct {
	Prefix            string `json:"Prefix"`
	PrefixedName      string `json:"PrefixedName"`
	PrefixedUniversal string `json:"PrefixedUniversal"`
	State             int    `json:"State"`
	Universal         string `json:"Universal"`
}

// Note: The Value field cannot be empty regardless of the Type. Otherwise, the
// creation or update of the cred will fail with:
//
//	400 Bad Request, body: {"error":"invalid_request","error_description":"The request is missing a required parameter or is otherwise malformed"}
type Value struct {
	Name  string `json:"Name"`
	Type  string `json:"Type"`
	Value string `json:"Value"` // Cannot be empty regardless of the Type.
}

// Works with getCred and updateCred.
func isNotFoundCred(err error) bool {
	if err == nil {
		return false
	}
	c := CredError{}
	if !errors.As(err, &c) {
		return false
	}
	return c.Res() == ResultObjectDoesNotExist
}

// POST /vedsdk/Credentials/retrieve
func getCred(apiURL, token, credPath string) (*Credential, error) {
	body, err := json.Marshal(struct {
		CredentialPath string `json:"CredentialPath"`
	}{CredentialPath: credPath})
	if err != nil {
		return nil, fmt.Errorf("while marshalling request: %w", err)
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/vedsdk/Credentials/retrieve", apiURL), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("while creating request for /vedsdk/Credentials/retrieve: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("while making request to /vedsdk/Credentials/retrieve: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Dump body.
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("retrieve failed: %s, body: %v", resp.Status, string(body))
	}

	var cred struct {
		Credential `json:",inline"`
		Result     Result `json:"Result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cred); err != nil {
		return nil, fmt.Errorf("while decoding response from /vedsdk/Credentials/retrieve: %w", err)
	}

	switch cred.Result {
	case ResultSuccess:
		// continue
	default:
		return nil, CredError{Result: cred.Result, CredPath: credPath}
	}
	return &cred.Credential, nil
}

type CredError struct {
	Result   Result
	CredPath string
}

func (e CredError) Error() string {
	return ResultString(e.Result)
}

func (e CredError) Res() Result {
	return e.Result
}

// E.g., '\VED\Policy\firefly\config.yaml'
func (e CredError) Path() string {
	return e.CredPath
}

// POST /vedsdk/Credentials/create
func createCred(tppURL, token, credPath string, c Credential) error {
	body, err := json.Marshal(struct {
		Credential     `json:",inline"`
		CredentialPath string `json:"CredentialPath"`
	}{
		Credential:     c,
		CredentialPath: credPath,
	})
	if err != nil {
		return fmt.Errorf("while marshalling request for POST /vedsdk/credentials/create: %w", err)
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/vedsdk/credentials/create", tppURL), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("while creating request for POST /vedsdk/credentials/create: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("while making request to POST /vedsdk/credentials/create: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Dump body.
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("create failed: %s, body: %v", resp.Status, string(body))
	}

	var res struct {
		Result Result `json:"Result"`
	}

	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return fmt.Errorf("while decoding response from POST /vedsdk/credentials/create: %w", err)
	}

	switch res.Result {
	case ResultSuccess:
		// continue
	default:
		return fmt.Errorf("error creating '%s': %v", credPath, ResultString(res.Result))
	}
	return nil
}

// POST /vedsdk/Credentials/update
func updateCred(tppURL, token, credPath string, c Credential) error {
	body, err := json.Marshal(struct {
		Credential     `json:",inline"`
		CredentialPath string `json:"CredentialPath"`
	}{
		Credential:     c,
		CredentialPath: credPath,
	})
	if err != nil {
		return fmt.Errorf("while marshalling request for POST /vedsdk/credentials/update: %w", err)
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/vedsdk/credentials/update", tppURL), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("while creating request for POST /vedsdk/credentials/update: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("while making request to POST /vedsdk/credentials/update: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Dump body.
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update failed: %s, body: %v", resp.Status, string(body))
	}

	var res struct {
		Result Result `json:"Result"`
	}
	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return err
	}

	switch res.Result {
	case ResultSuccess:
		// continue
	case ResultAttributeNotFound:
		return fmt.Errorf("attribute not found: %q", credPath)
	default:
		return fmt.Errorf("error updating %q: %v", credPath, ResultString(res.Result))
	}
	return nil
}

func RmCred(tppURL, token, credPath string) error {
	body, err := json.Marshal(struct {
		CredentialPath string `json:"CredentialPath"`
	}{CredentialPath: credPath})
	if err != nil {
		return fmt.Errorf("while marshalling request for /vedsdk/Credentials/delete: %w", err)
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/vedsdk/Credentials/delete", tppURL), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("while creating request for /vedsdk/Credentials/delete: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("while making request to /vedsdk/Credentials/delete: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Dump body.
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete failed: %s, body: %v", resp.Status, string(body))
	}

	var res struct {
		Result Result `json:"Result"`
	}
	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return fmt.Errorf("while decoding response from /vedsdk/Credentials/delete: %w", err)
	}

	if res.Result != ResultSuccess {
		return CredError{Result: res.Result, CredPath: credPath}
	}

	return nil
}

func listObjects(tppURL, token string) ([]string, error) {
	body, err := json.Marshal(struct {
		ObjectDN  string `json:"ObjectDN"`
		Pattern   string `json:"Pattern"`
		Recursive bool   `json:"Recursive"`
	}{
		ObjectDN:  `\VED\Policy`,
		Recursive: true,
	})
	if err != nil {
		return nil, fmt.Errorf("while marshalling request for /vedsdk/Config/Enumerate: %w", err)
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/vedsdk/Config/Enumerate", tppURL), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("while creating request for /vedsdk/Config/Enumerate: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("while making request to /vedsdk/Config/Enumerate: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Dump body.
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list failed: %s: %s", resp.Status, string(body))
	}

	var creds ObjectsResp
	err = json.NewDecoder(resp.Body).Decode(&creds)
	if err != nil {
		return nil, fmt.Errorf("while decoding response from /vedsdk/Config/Enumerate: %w", err)
	}

	var credPaths []string
	for _, cred := range creds.Objects {
		if !strings.Contains(cred.TypeName, "Generic Credential") {
			continue
		}
		credPaths = append(credPaths, fmt.Sprintf("%s", cred.Dn))
	}
	return credPaths, nil
}

type ObjectsResp struct {
	Objects []Objects `json:"Objects"`
	Result  int       `json:"Result"`
}
type Objects struct {
	AbsoluteGUID string `json:"AbsoluteGUID"`
	Dn           string `json:"DN"`
	GUID         string `json:"GUID"`
	ID           int    `json:"Id"`
	Name         string `json:"Name"`
	Parent       string `json:"Parent"`
	Revision     int    `json:"Revision"`
	TypeName     string `json:"TypeName"`
}

type TypeName string

const (
	TypeNameX509ServerCert       TypeName = "X509 Server Certificate"
	TypeNamePolicy               TypeName = "Policy"
	TypeNameGoogleCred           TypeName = "Google Credential"
	TypeNameGenericCred          TypeName = "Generic Credential"
	TypeNameUsernamePasswordCred TypeName = "Username Password Credential"
)
