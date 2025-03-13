# tppcred

A utility to edit the Generic Credentials in TPP.

## Installation

```bash
go install github.com/maelvls/tppcred@latest
```

## Usage

First, authenticate with the TPP server using the command:

```bash
tppcred auth
```

This will prompt you for the TPP URL, your username, password, and client ID:

```console
$ tppcred auth
┃ Do not add the suffix '/vedsdk'.
┃ URL: https://tpp-ext.tpp-tests.jetstack.net

  The TPP user must be a super admin if you want to run 'tppcred ls'.
  Username: jetstack-platform

  The password will be stored in plain text in ~/.config/tppcred.yaml
  Password: *******************

  The API Integration associated to your client ID must accept the scope configuration:manage;security:manage,delete.
  Client ID: vcert-sdk
```

You can list the Generic Credentials with:

```bash
tppcred ls
```

You can edit a Generic Credential straight from your terminal with:

```bash
tppcred edit '\VED\Policy\firefly\config.yaml'
```

This will open your `$EDITOR` (e.g., Vim). Close the editor to save the changes.

You can create or update a Generic Credential with:

```bash
tppcred push '\VED\Policy\firefly\config.yaml' < config.yaml
```

You can output the Generic Credential's contents with:

```bash
tppcred show '\VED\Policy\firefly\config.yaml'
```

You can delete a Generic Credential with:

```bash
tppcred rm '\VED\Policy\firefly\config.yaml'
```
