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
┃ Enter the TPP URL: https://tpp-ext.tpp-tests.jetstack.net
  Enter your username: jetstack-platform
  Enter your password: *******************
  Enter the client ID: vcert-sdk
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
