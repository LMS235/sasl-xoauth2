% sasl-xoauth2.conf(5) | File Formats Manual

# NAME

/etc/sasl-xoauth2.conf - configuration file for sasl-xoauth2

# DESCRIPTION

This file contains static, administrator-defined information needed for XOAUTH2 SASL authentication.

It uses a JSON format to define variables needed to complete XOAUTH2 configuration. 

A minimal configuration file looks like:

```json
{
  "client_id": "CLIENT_ID_GOES_HERE",
  "client_secret": "CLIENT_SECRET_GOES_HERE"
}
```

See the full README for guidance on initial configuration:
https://github.com/tarickb/sasl-xoauth2

# OPTIONS

The top-level JSON object can contain the following keys:

`client_id`

: identifies this client for OAuth 2 token requests

`client_secret`

: authenticates this client for OAuth 2 token requests; leave empty for public clients (e.g. Microsoft device flow), in which case no secret is sent; world-readable by default (but see below to place this in token files instead)

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

: if set, overrides CURL's default certificate-authority directory

`refresh_window`

: request a new access token this many seconds before the current one expires (integer, defaults to 300); Microsoft's HVE endpoint needs at least 600.
  In a token file, a value of 0 is ignored (versions before 0.29 wrote it there by mistake).

`grant_type`

: how access tokens are obtained: `refresh_token` (default; the token file must contain a refresh token) or `client_credentials` (app-only access with client ID and secret, e.g. Microsoft 365 with the `SMTP.SendAsApp` permission; requires `scope`)

`scope`

: if set, sent as the `scope` of token requests; required for `client_credentials` (for Microsoft 365: `https://outlook.office365.com/.default`)

# TOKEN FILE

In addition to this file, `sasl-xoauth2` relies on a "token file" which it updates independently.
The token file is also JSON-formatted.
The contents of this token file MAY contain values for the keys described above (except for the logging-related keys).
If they do, the value in the token file overrides the value in the main configuration file.

It may additionally contain `user`, which overrides the user name sent to the server (with `client_credentials`, the mailbox address).

This makes it possible to use the same installation of `sasl-xoauth2` to connect to two different providers simultaneously.
This also has the benefit of providing storage for client secrets that is not world-readable.

Token files are updated atomically (a new file is written and renamed into place), keeping the owner and group permission bits of the previous file but never permissions for other users.
Refreshes are serialized between processes with a lock file named after the token file plus `.lock`, so the directory containing the token file must be writable by the mail agent.

# BUGS

Please report improvements in this documentation upstream at https://github.com/tarickb/sasl-xoauth2/issues

# SEE ALSO

sasl-xoauth2-tool(1)
