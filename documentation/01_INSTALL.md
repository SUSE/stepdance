# Installation

## Preparation of IDP

Tested with Authentik, but as this uses generic OAuth2 functionality, any other suitable IDP (Keycloak, Kanidm, ...) should work equally and the instructions below are hence kept generic.

### Configure an OAuth2 client

- client should be of "confidential" type (i.e. one which has a client secret)
- allow the `email` and `openid` claims
- map a unique user attribute to use as the Common Name (CN) in the client certificates as the subject
- allow the base URL Stepdance will be hosted under suffixed with `/login/callback` as a callback URL (for example `https://stepdance.example.com/login/callback`)

## Preparation of step-ca

The below `step` commands will ask for admin authentication. For non-interactive use, add something like `--admin-provisioner='Admin JWK' --admin-name=step --admin-password-file=admin_provisioner_password` to them.

### Configure the OIDC provisioner

Basic command:

```shell
step ca provisioner add OIDC --type=oidc \
    --configuration-endpoint=<url to IDP OIDC discovery endpoint>/.well-known/openid-configuration \
    --client-id=<client ID from IDP> \
    --client-secret=<client secret from IDP> \
    --domain=<domain of allowed email addresses> \
    --ssh=false --disable-smallstep-extensions
```

Here, the provisioner name is `OIDC`, but any name can be chosen.

The discovery endpoint (and the endpoints reported by it) must be reachable from the step-ca server.

The email `--domain`s are needed, as step-ca will only sign certificates for tokens from users with authorized email domains.

To customize the contents of the issued certificates, add `--template` pass a file containing a [X.509 template](https://smallstep.com/docs/step-ca/templates/#x509-templates). Here is an example for certificates without SANs, only client authentication, and a CRL endpoint:

```json
{
        "subject": {"commonName":"{{ .Subject.CommonName }}"},
        "keyUsage": ["digitalSignature"],
        "extKeyUsage": ["clientAuth"],
        "basicConstraints": {
                "CA": false
        },
        "crlDistributionPoints": ["https://ca.example.com/1.0/crl"]
}
```

### Configure the admin provisioner (WIP)

This is optional, as the default `Admin JWK` provisioner can be used, but recommended, as to avoid giving Stepdance unnecessary privileges as well as to not copy the super admin token to other places.

Basic commands:

```shell
step ca provisioner add StepdanceJWK --create
step ca admin add StepdanceAdmin StepdanceJWK
```

## Preparation of PostgreSQL

```sql
CREATE ROLE stepdance WITH LOGIN PASSWORD 'changeme';
# connect to step-ca database
\c stepca
GRANT SELECT ON x509_certs, revoked_x509_certs TO stepdance;
```

Adjust `pg_hba.conf` if needed.

## Preparation of Stepdance

Reference `config.example.json` to build a configuration file - the needed values are expected to be obvious after having followed the previous steps from this document.
