package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Credential struct {
	Contact      []Contact      `json:"Contact"` // Optional.
	FriendlyName string         `json:"FriendlyName"`
	Values       []Value        `json:"Values"`
	Expiration   DotNetUnixTime `json:"Expiration"` // Optional.
}

// The `Expiration` field used by the TPP Credentials endpoints [1] use
// Microsoft's .NET JavaScriptSerializer hacky format [2] [3]. It looks like
// this:
//
//	/Date(1335205592410)/
//	/Date(1335205592410-0500)/
//	/Date(1335205592410+0100)/
//	/Date(-1335205592410+0100)/
//	/Date(-1335205592410-0100)/
//	       <----------->
//	       Unix time in milliseconds.
//
// The part "-0500" is the timezone offset. It can be a "+" too, e.g, "+0100".
//
//	[1]: https://docs.venafi.com/Docs/24.1/TopNav/Content/SDK/WebSDK/r-SDK-POST-Credentials-create.php
//	[2]: https://learn.microsoft.com/en-us/dotnet/api/system.web.script.serialization.javascriptserializer?view=netframework-4.8.1
//	[3]: https://learn.microsoft.com/en-us/dotnet/standard/datetime/system-text-json-support#use-unix-epoch-date-format
type DotNetUnixTime time.Time

// Always uses the Unix time in milliseconds with timezone offset, e.g.,
// `/Date(1335205592410-0500)/`.
func (e DotNetUnixTime) MarshalJSON() ([]byte, error) {
	t := time.Time(e)

	var offset string
	if t.Location() != time.UTC {
		offset = t.Format("-0700")
	}

	// No need to use json.Marshal on the string since we know we are using
	// JSON-compatible characters.
	return []byte(fmt.Sprintf(`"/Date(%d%s)/"`, t.UnixNano()/int64(time.Millisecond), offset)), nil
}

// Parses "/Date(1335205592410)/" or "/Date(1335205592410-0500)/".
func (e *DotNetUnixTime) UnmarshalJSON(raw []byte) error {
	// Parse JSON string.
	var wholeStr string
	err := json.Unmarshal(raw, &wholeStr)
	if err != nil {
		return fmt.Errorf("while marshalling the JSON string %v: %w", string(raw), err)
	}

	regxp := regexp.MustCompile(`^/Date\((-?\d+)([+-]\d{4})?\)/$`)
	if !regxp.MatchString(wholeStr) {
		return fmt.Errorf("while parsing date: expected format '/Date([-]1335205592410[(+|-)0100])/' but got '%v'", wholeStr)
	}

	millisStr := regxp.FindStringSubmatch(wholeStr)[1]
	offsetStr := regxp.FindStringSubmatch(wholeStr)[2]

	millis, err := strconv.ParseInt(millisStr, 10, 64)
	if err != nil {
		return fmt.Errorf("while parsing date '%s': expected a number such as '1335205592410' but got '%v': %w", wholeStr, millisStr, err)
	}

	// Parse the timezone offset. Examples: "-0500" or "+0100".
	loc := time.UTC
	if offsetStr != "" {
		tmp, err := time.Parse("-0700", offsetStr)
		if err != nil {
			return fmt.Errorf("while parsing date '%s': expected timezone offset to look like '+0100' or '-0500', but got '%v': %w", wholeStr, offsetStr, err)
		}
		loc = tmp.Location()
	}

	*e = DotNetUnixTime(time.UnixMilli(millis).In(loc))
	return nil
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
//
// https://docs.venafi.com/Docs/24.1/TopNav/Content/SDK/WebSDK/r-SDK-POST-Credentials-create.php
// https://docs.venafi.com/Docs/24.1API/#?route=post-/vedsdk/Credentials/create
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

// POST /vedsdk/Credentials/delete
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

// POST /vedsdk/Config/Enumerate
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

func getToken(tppURL, username, password, clientID string) (string, error) {
	body, err := json.Marshal(struct {
		ClientID string `json:"client_id"`
		Username string `json:"username"`
		Password string `json:"password"`
		Scope    string `json:"scope"`
	}{
		ClientID: clientID,
		Username: username,
		Password: password,
		Scope:    requiredScope,
	})
	if err != nil {
		return "", fmt.Errorf("while marshalling request for POST /vedauth/authorize/oauth: %w", err)
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/vedauth/authorize/oauth", tppURL), bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("while creating request for POST /vedauth/authorize/oauth: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("while making request to POST /vedauth/authorize/oauth: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Dump body.
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("auth failed: %s, body: %v", resp.Status, string(body))
	}

	var authResp struct {
		AccessToken string `json:"access_token"`
	}
	err = json.NewDecoder(resp.Body).Decode(&authResp)
	if err != nil {
		return "", fmt.Errorf("while decoding response from POST /vedauth/authorize/oauth: %w", err)
	}

	return authResp.AccessToken, nil
}

func checkToken(tppURL, token string) error {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/vedsdk/Identity/Self", tppURL), nil)
	if err != nil {
		return fmt.Errorf("while creating request for GET /vedsdk/Identity/Self: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("while making request to GET /vedsdk/Identity/Self: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Dump body.
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("check token failed: %s, body: %v", resp.Status, string(body))
	}

	return nil
}
