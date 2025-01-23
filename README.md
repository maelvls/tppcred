# tppctl

A utility to edit the Generic Credentials in TPP.

## Installation

```bash
go install github.com/maelvls/tppctl@latest
```

## Usage

Before using `tppctl`, you need to set the `TPP_URL` and `TOKEN` environment
variables. To get a token, you can use the `vcert` utility:

```bash
export TPP_URL=https://tpp-ext.tpp-tests.jetstack.net
export TOKEN=$(vcert getcred \
  -u $TPP_URL \
  --username=$TPP_USER \
  --password=$TPP_PWD \
  --client-id=vcert-sdk \
  --scope='credential:manage,delete' \
  --format json | tee /dev/stderr | jq -r .access_token)
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
