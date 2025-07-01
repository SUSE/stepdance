# Stepdance

A client certificate self-service portal built on [step-ca](https://smallstep.com/docs/step-ca/).

Users are authenticated through OIDC, certificates are mapped through the `sub`ject contained in the JWT.

## Features

- overview of certificates
- revocation of certificates
- issuance of certificates

All features are tied to the logged in user and the certificates belonging to them.

## Non-Features

Administrative management of certificates - currently the application only provides a self-service interface for end-users to manage their own client certificates.

## Caveats

The application ties to integrate with step-ca as tightly as possible, however unfortunately not all necessary features are exposed in the self-hostable community version of step-ca:

- no querying of existing certificates
- no mapping of certificates to uesrs and no revocation of certificates without admin privileges if the subject does not match the certificate serial

Hence `stepdance` implements three kinds of interaction with `step-ca`:

- REST API using `smallstep/certificates` for issuance of new certificates, authenticated to a [OIDC provisioner](https://smallstep.com/docs/step-ca/provisioners/#oauthoidc-single-sign-on) using OIDC JWTs
- REST API using `smallstep/certificates` for revocation of existing certificates, authenticated to a [JWK provisioner](https://smallstep.com/docs/step-ca/provisioners/#jwk) using an admin token (a separate provisioner and token with only revocation privileges is recommended)
- PostgreSQL using `database/sql` for listing existing certificates, authenticated using database credentials (a separate user with read-only privileges is recommended)

## Running

1. Copy and adjust `config.example.json`
2. Run `stepdance`

By default the application will search for a config file at `config.json` in the same directory. Use `-config` and pass a different path if needed.

For debugging, the log level can be raised using `-loglevel debug`. This will be very noisy in busy deployments.

## Hacking

Some of the Makefile targets require a GNU variant of `make`, but the respective commands can easily be copied from the `GNUmakefile` and executed manually.

### Build

```
make build
```

### Test

Requirements are [`podman`](https://podman.io/).

1. `make dev` - will bring up one container with Step CA, and one with PostgreSQL
2. `make test` - will run the test suite
