% sasl-xoauth2.conf(5) | File Formats Manual

# NAME

/etc/sasl-xoauth2.conf - configuration file for sasl-xoauth2

# DESCRIPTION

This file contains static, administrator-defined information needed for XOAUTH2 SASL authentication.

It uses a JSON format to define variables needed to complete XOAUTH2 configuration. 

It may contain credentials, so it should not be readable for other users (it is installed with mode 0640; make it `root:postfix` for Postfix).
The mail agent reads it when the plugin is loaded (for Postfix, before it drops privileges and enters its chroot).

A minimal configuration file looks like:

```json
{
  "client_id": "CLIENT_ID_GOES_HERE",
  "client_secret": "CLIENT_SECRET_GOES_HERE"
}
```

See the full README for guidance on initial configuration:
https://github.com/LMS235/sasl-xoauth2

# OPTIONS

The top-level JSON object can contain the following keys:

`client_id`

: identifies this client for OAuth 2 token requests (required)

`client_secret`

: authenticates this client for OAuth 2 token requests; optional: leave it empty or out for public clients (e.g. Microsoft device flow), in which case no secret is sent, or when a client certificate is used (see below); it is only sent to the configured `token_endpoint`, not to an endpoint set in a token file

`always_log_to_syslog`

: always write plugin log messages to syslog, even for successful runs; tokens and secrets are redacted, but user names and file paths are logged (defaults to "no")

`log_to_syslog_on_failure`

: log to syslog if XOAUTH2 flow fails (defaults to "yes")

`log_full_trace_on_failure`

: log a full trace to syslog if XOAUTH2 flow fails; tokens and secrets are redacted (defaults to "no")

`token_endpoint`

: URL to use when requesting tokens; must be an `https://` URL (redirects are not followed); defaults to Google, must be overridden for use with Microsoft/Outlook.
  For national clouds, use the appropriate endpoint:
  US Government: `https://login.microsoftonline.us/{tenant}/oauth2/v2.0/token`;
  China (21Vianet): `https://login.partner.microsoftonline.cn/{tenant}/oauth2/v2.0/token`

`proxy`

: if set, HTTP requests will be proxied through this server

`ca_bundle_file`

: if set, overrides CURL's default certificate-authority bundle file

`ca_certs_dir`

: if set, overrides CURL's default certificate-authority directory (CURL's default bundle file still applies; to trust only specific certificate authorities, use `ca_bundle_file`)

`refresh_window`

: request a new access token this many seconds before the current one expires (integer from 0 to 1800, defaults to 300); Microsoft's HVE endpoint needs at least 600.
  In a token file, a value of 0 is ignored (versions before 0.29 wrote it there by mistake).

`grant_type`

: how access tokens are obtained: `refresh_token` (default; the token file must contain a refresh token) or `client_credentials` (app-only access with client ID and secret, e.g. Microsoft 365 with the `SMTP.SendAsApp` permission; requires `scope`)

`scope`

: the `scope` of `client_credentials` token requests, and required for them (for Microsoft 365: `https://outlook.office365.com/.default`); not sent for `refresh_token` requests, which keep the originally granted scopes

`client_certificate_file`

: authenticate to the token endpoint with a certificate instead of `client_secret` (recommended for `client_credentials`): path of a PEM file with the X.509 certificate registered for the application; for each token request, a client assertion (a JWT signed with PS256, with the certificate's SHA-256 thumbprint, valid for 5 minutes) is sent instead of a secret; takes precedence over `client_secret`

`client_private_key_file`

: path of a PEM file with the unencrypted RSA private key of `client_certificate_file`; defaults to `client_certificate_file`; must be readable by the mail agent (inside its chroot, if any) and by no one else

# TOKEN FILE

In addition to this file, `sasl-xoauth2` relies on a "token file" which it updates independently.
The token file is also JSON-formatted.
The contents of this token file MAY contain values for the keys described above (except for the logging-related keys).
If they do, the value in the token file overrides the value in the main configuration file.

It may additionally contain `user`, which overrides the user name sent to the server (with `client_credentials`, the mailbox address; for a shared mailbox, its address).
A token file that sets a different `token_endpoint`, `proxy`, `ca_bundle_file` or `ca_certs_dir` than this file must also set its own `client_secret` (or use a certificate); the `client_secret` from this file is not sent there.

This makes it possible to use the same installation of `sasl-xoauth2` to connect to two different providers simultaneously.
This also has the benefit of providing storage for client secrets that is not world-readable.

Token files are updated atomically (a new file is written and renamed into place).
The new file belongs to the user that writes it (normally the mail agent's user), keeps the owner and group permission bits of the previous file, and never grants access to other users.
Refreshes are serialized between processes with a lock file named after the token file plus `.lock`, so the directory containing the token file must be writable by the mail agent.
If the new token cannot be stored, it is used anyway and an error is logged; if a refresh fails while the current token is still valid for at least a minute, the current token is used.

# BUGS

Please report improvements in this documentation at https://github.com/LMS235/sasl-xoauth2/issues

# SEE ALSO

sasl-xoauth2-tool(1)
