# tppctl

A utility to edit the Generic Credentials in TPP.

## Installation

```bash
go install github.com/maelvls/tppctl@latest
```

## Usage

First, authenticate with the TPP server using the command:

```bash
tppctl auth
```

This will prompt you for the TPP URL, your username, password, and client ID:

```console
$ tppctl auth
┃ Do not add the suffix '/vedsdk'.
┃ URL: https://tpp-ext.tpp-tests.jetstack.net

  The TPP user must be a super admin if you want to run 'tppctl ls'.
  Username: jetstack-platform

  The password will be stored in plain text in ~/.config/tppctl.yaml
  Password: *******************

  The API Integration associated to your client ID must accept the scope configuration:manage;security:manage,delete.
  Client ID: vcert-sdk
```

Now, you can list the Generic Credentials with:

```console
$ tppctl ls
\VED\Policy\firefly\config.yaml
\VED\Policy\firefly\us-west-1\service-mesh\firefly
\VED\Policy\firefly-e2e\config.yaml
```

You can edit a Generic Credential straight from your terminal with:

```bash
tppctl edit '\VED\Policy\firefly\config.yaml'
```

This will open your `$EDITOR` (e.g., Vim). Close the editor to save the changes.

You can create or update a Generic Credential with:

```bash
tppctl push '\VED\Policy\firefly\config.yaml' <<EOF
the contents
EOF
```

You can output the Generic Credential's contents with:

```bash
tppctl read '\VED\Policy\firefly\config.yaml'
```

You can delete a Generic Credential with:

```bash
tppctl rm '\VED\Policy\firefly\config.yaml'
```
