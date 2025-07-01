# Usage

The following expects you having pointed a web browser to the URL Stepdance is hosted under.

## Login

1. Click the _Login_ button in the middle of the page (only shown if **not** logged in)
2. Follow the authentication flow defined by the IDP.

## Certificate overview

After logging in,  greeting will be displayed, and underneath either:
 * an overview of certificates, if any were issued already, and the button _Request certificate_ underneath or
 * only the button _Request certificate_, if no certificates were issued yet.

## Certificate issuance

Click the aforementioned _Request certificate_ button. Note currently only one certificate may be active at a time - the operation will fail if the overview shows any existing certificates with "No" in the "Revoked?" column of the overview.

## Certificate revocation

Find a certificate with "No" in the "Revoked?" column in the overview. Click the _revoke now_ link next to it.
