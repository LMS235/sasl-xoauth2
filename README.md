# sasl-xoauth2

## Disclaimer

This is not an officially supported Google or Microsoft product, nor a product
of any other mail or identity provider, and it is not affiliated with or
endorsed by any of them. It is provided "as is", without any warranty and
without any claim to completeness (see the Apache License 2.0 in
[COPYING](COPYING)).

## Background

sasl-xoauth2 is a SASL plugin that enables client-side use of OAuth 2.0. Among
other things it enables the use of Gmail or Outlook/Office 365 SMTP relays from
Postfix.

## Building from Source

### Requirements

| Purpose | Requirement | Ubuntu/Debian package |
|---|---|---|
| Compiler and build tools | C++17 compiler, `make`, CMake, pkg-config | `build-essential`, `cmake`, `pkgconf` |
| HTTPS requests | libcurl (OpenSSL or GnuTLS flavor) | `libcurl4-openssl-dev` |
| JSON | jsoncpp | `libjsoncpp-dev` |
| SASL plugin API | Cyrus SASL headers | `libsasl2-dev` |
| Man page `sasl-xoauth2.conf(5)` | pandoc (**required**; configuration fails without it) | `pandoc` |
| Man page `sasl-xoauth2-tool(1)` | argparse-manpage (optional; skipped with a warning) | `python3-argparse-manpage` |
| `sasl-xoauth2-tool` (runtime) | Python 3 | `python3` |
| Microsoft device flow (runtime) | MSAL for Python | `python3-msal` |
| Shell completion for the tool (optional) | argcomplete | `python3-argcomplete` |
| Checking the installed plugin (optional) | `saslpluginviewer` | `sasl2-bin` |

### Ubuntu 26.04 LTS

This was tested on Ubuntu 26.04.1 LTS (GCC 15.2, CMake 4.2, libcurl 8.18,
jsoncpp 1.9.6, Cyrus SASL 2.1.28, Python 3.14). Install the build
dependencies:

```
$ sudo apt install build-essential cmake pkgconf git \
    libcurl4-openssl-dev libjsoncpp-dev libsasl2-dev \
    pandoc python3-argparse-manpage
```

and the runtime dependencies of `sasl-xoauth2-tool`:

```
$ sudo apt install python3 python3-msal python3-argcomplete sasl2-bin
```

Install MSAL from the Ubuntu archive as shown: Ubuntu does not allow
`sudo pip3 install` into the system Python (PEP 668, "externally-managed-environment").

Then build, test and install:

```
$ git clone https://github.com/LMS235/sasl-xoauth2.git
$ cd sasl-xoauth2
$ cmake -S . -B build -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_SYSCONFDIR=/etc
$ cmake --build build -j"$(nproc)"
$ ctest --test-dir build
$ sudo cmake --install build
```

The two `-D` options matter: with CMake's default prefix (`/usr/local`) the
plugin would be installed to `/usr/local/lib/sasl2`, where the system's Cyrus
SASL library (and thus Postfix) does not look, and the configuration file to
`/usr/local/etc`. With the options above, the following files are installed:

| File | Purpose |
|---|---|
| `/usr/lib/x86_64-linux-gnu/sasl2/libsasl-xoauth2.so` | The SASL plugin |
| `/etc/sasl-xoauth2.conf` | Configuration file (a template; see [Configuration](#configuration)) |
| `/usr/bin/sasl-xoauth2-tool` | Tool to obtain tokens and test the configuration |
| `/usr/lib/x86_64-linux-gnu/sasl-xoauth2/test-config` | Helper used by `sasl-xoauth2-tool test-config` and `test-token-refresh` |
| `/usr/share/man/man5/sasl-xoauth2.conf.5`, `/usr/share/man/man1/sasl-xoauth2-tool.1` | Man pages |

(On other architectures, `x86_64-linux-gnu` is replaced by the respective
multiarch directory.) Check that SASL finds the plugin:

```
$ saslpluginviewer -c -m XOAUTH2
...
Plugin "sasl-xoauth2" [loaded],         API version: 4
        SASL mechanism: XOAUTH2, best SSF: 60
```

On Ubuntu 26.04, Postfix's `smtp` service does not run chrooted by default
(see [A Note on chroot](#a-note-on-chroot)), but its systemd sandbox needs one
adjustment so that token files can be updated: see [A Note on Ubuntu
26.04](#a-note-on-ubuntu-2604).

Only if you enable the chroot: copy the CA certificates into it, and install
the script that keeps them up to date as an `update-ca-certificates` hook (see
[SSL/TLS Certificates](#ssltls-certificates)):

```
$ sudo install -m 755 scripts/postfix-sasl-xoauth2-update-ca-certs /etc/ca-certificates/update.d/
$ sudo /etc/ca-certificates/update.d/postfix-sasl-xoauth2-update-ca-certs
```

Continue with [Configuration](#configuration).

To build without the test program, add `-DEnableTests=OFF` to the first
`cmake` command (and skip `ctest`). To uninstall, remove the files listed
above.

### Other Distributions

The same steps work on other distributions with the equivalent packages (on
Debian and older Ubuntu releases the package names above are the same).

## System-Specific Notes

### A Note on SELinux

If SELinux is enabled (e.g. on RHEL or Fedora), you may find that authentication is failing. This is
likely because the sasl-xoauth2 plugin, running within the Postfix `smtp`
process, is unable to read, write, or create a new token file. If in doubt,
check your SELinux audit logs.

### A Note on Ubuntu 26.04

Postfix's systemd unit on Ubuntu 26.04 sets `ProtectSystem=full`, which makes
`/etc` read-only for Postfix. With token files in `/etc/tokens` -- the normal
case, since the `smtp` service does not run chrooted by default -- sasl-xoauth2
then cannot update them, and fails with errors about a read-only file system.
Rather than relaxing the sandbox as a whole, allow writes to just the token
directory (thank you @bernd-it for pointing out the problem):

```
$ sudo systemctl edit postfix.service
```

And then add:

```
[Service]
ReadWritePaths=/etc/tokens
```

Then `sudo systemctl restart postfix`. (For instances started via
`postfix@.service`, edit that unit instead.) Token files inside the chroot
(`/var/spool/postfix/etc/tokens`) are not affected.

## Configuration

### Configure Mail Agent

This plugin has only been tested with Postfix. First, configure Postfix to use
SASL, and specifically the XOAUTH2 method. In `/etc/postfix/main.cf`:

```
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options =
smtp_sasl_mechanism_filter = xoauth2
```

Alternatively, you could specify multiple mechanisms, i.e.

```
smtp_sasl_mechanism_filter = xoauth2,login
```

The above used to cause problems, because both "xoauth2" and the "login"
plug-in (as is used for many older, not-yet-OAuth2 providers) had the
same "SSF" setting of "0". This made SASL's automatic detection of which
plug-in to use non-deterministic. Now, with the higher SSF of "60" for
"xoauth2", providers offering OAUTH2 will be handled via the xoauth2 plug-in.

You can check the effective value by calling `pluginviewer -c` (on Debian/Ubuntu it’s installed as `/usr/sbin/saslpluginviewer` in the `sasl2-bin` package); look for
the "SSF" value:

```
Plugin "sasl-xoauth2" [loaded],         API version: 4
        SASL mechanism: XOAUTH2, best SSF: 60
        security flags: NO_ANONYMOUS|PASS_CREDENTIALS
        features: WANT_CLIENT_FIRST|PROXY_AUTHENTICATION
Plugin "login" [loaded],        API version: 4
        SASL mechanism: LOGIN, best SSF: 0
        security flags: NO_ANONYMOUS|PASS_CREDENTIALS
        features: SERVER_FIRST
```

See https://www.cyrusimap.org/sasl/sasl/authentication_mechanisms.html#authentication-mechanisms for details on the fields.

While you're at it, enable TLS:

```
smtp_tls_security_level = encrypt
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache
```

And then set the outbound relay to Gmail's SMTP server:

```
relayhost = [smtp.gmail.com]:587
```

(For Outlook/Microsoft 365, use `[smtp.office365.com]:587` instead; see
[Outlook/Microsoft 365 Configuration](#outlookmicrosoft-365-configuration).)

Next, add client account details to the SASL password database in
`/etc/postfix/sasl_passwd`:

```
[smtp.gmail.com]:587 username@domain.com:/etc/tokens/username@domain.com
```

(For Outlook, replace `[smtp.gmail.com]:587` with `[smtp.office365.com]:587`.)

The path specified above tells sasl-xoauth2 where to find tokens for the account
"username@domain.com" (but see [A Note on chroot](#a-note-on-chroot) below).

Finally, regenerate the SASL password database:

```
$ sudo postmap /etc/postfix/sasl_passwd
```

#### A Note on chroot

Check if chroot is enabled:

```
$ grep -E '^(smtp|.*chroot)' /etc/postfix/master.cf
# service type  private unpriv  chroot  wakeup  maxproc command + args
smtp      inet  n       -       y       -       -       smtpd
smtp      unix  -       -       y       -       -       smtp
```

In this example `master.cf`, chroot is in fact enabled for the Postfix smtp
process. As a result, the token path specified above will be interpreted at
runtime relative to the Postfix root (`/var/spool/postfix`, usually).

This means that **even though the path in `/etc/postfix/sasl_passwd` is
(and should be) `/etc/tokens/username@domain.com`**, at runtime Postfix will
attempt to read from `/var/spool/postfix/etc/tokens/username@domain.com`.

Whether chroot is enabled by default depends on the distribution and its
version; on Ubuntu 26.04, for example, the `smtp` service is *not* chrooted
(`n` in the chroot column), so the token path is used as is.

#### A Note on Token File Permissions

Token files contain secrets (refresh tokens, and possibly client secrets), so
they should only be readable by the user Postfix runs as. sasl-xoauth2 updates
a token file by writing a new file next to it and renaming it into place, and
it serializes token refreshes between Postfix processes with a lock file
(`<token file>.lock`). The token *directory* must therefore be writable by the
Postfix user:

```
$ sudo chown -R postfix:postfix /etc/tokens
$ sudo chmod 700 /etc/tokens
$ sudo chmod 600 /etc/tokens/*
```

or, with chroot:

```
$ sudo chown -R postfix:postfix /var/spool/postfix/etc/tokens
$ sudo chmod 700 /var/spool/postfix/etc/tokens
$ sudo chmod 600 /var/spool/postfix/etc/tokens/*
```

Updated token files keep the owner and group permission bits of the file they
replace; permissions for other users are never carried over. (Versions before
0.29 created updated token files according to the process umask, which usually
made them world-readable. Re-run the `chmod` above after upgrading.)
`sasl-xoauth2-tool` creates new token files readable by their owner only; when
it updates an existing file (`--overwrite-existing-token`), it keeps the file's
owner and group, so running it as root does not lock Postfix out. A new file
created as root still needs the `chown` above.

#### SSL/TLS Certificates

If you see an error message similar to the following, you may need to copy over
root CA certificates for the TLS handshake to work within sasl-xoauth2:

```
TokenStore::Refresh: http error: error setting certificate verify locations: ...
```

To copy certificates manually, assuming the Postfix root is
`/var/spool/postfix`:

```
$ sudo mkdir -p /var/spool/postfix/etc/ssl/certs
$ sudo cp /etc/ssl/certs/ca-certificates.crt /var/spool/postfix/etc/ssl/certs/ca-certificates.crt
```

sasl-xoauth2 includes a script,
`scripts/postfix-sasl-xoauth2-update-ca-certs`, that copies the certificates
into the chroot. Installed as a hook in `/etc/ca-certificates/update.d/` (see
[Ubuntu 26.04 LTS](#ubuntu-2604-lts) under Building from Source), it is run by
`update-ca-certificates` whenever the system certificates change. The script
replaces the chroot copy as a whole, so certificates removed from the system
are removed from the chroot too.

Token endpoints must use `https://`; sasl-xoauth2 does not send credentials over
plain HTTP and does not follow redirects. Requests time out after 10 seconds
(connect) and 30 seconds (total), so an unreachable endpoint cannot stall mail
delivery indefinitely.

sasl-xoauth2 also provides two configuration variables, `ca_bundle_file` and
`ca_certs_dir`, that may be used to manually configure where the SSL/TLS
libraries will look for a CA certificate bundle (for `ca_bundle_file`) or a set
of CA certificates (for `ca_certs_dir`). Specify one or the other, but not both.

#### A Note on postmulti

[@jamenlang](https://github.com/jamenlang) has provided a [very helpful
tutorial](https://github.com/jamenlang/sasl-xoauth2-1/wiki/Setting-up-postmulti-with-multiple-xoauth2-relays)
on setting up `postmulti` with sasl-xoauth2.

### Gmail Configuration

From a new account, Google requires several steps to enable access.
Once you are logged into your Gmail account in the browser, all these steps happen at the [Google Cloud Platform console](https://console.cloud.google.com/).

#### Basic Account Setup

- Select an existing project, or add a Project if you don't have one yet (it can be any name)

- Set up "OAuth Consent Screen" for the project

  - If this is an "External" app, make sure the "Publishing status" of the app is set to "In production" (as opposed to "Testing"), otherwise the token [will be revoked after 7 days](https://github.com/tarickb/sasl-xoauth2/issues/29) (upstream issue).
    - You can ignore any requests to "verify" your app. The warnings shown in the console are misleading. You don't actually need to go through verification.

#### Client Credentials

From the [Google Cloud Platform console](https://console.cloud.google.com/),

- Credentials: Create Credentials: OAuth client ID

  - Application type: Desktop app

  - Choose a memorable name

Store the client ID and secret in `/etc/sasl-xoauth2.conf`:

```json
{
  "client_id": "client ID goes here",
  "client_secret": "client secret goes here"
}
```

We'll also need these credentials in the next step.

#### Initial Access Token

`sasl-xoauth2-tool`, which is installed along with the plugin, can assist in
the generation of Gmail OAuth tokens. Run the script as follows:

```shell
$ sasl-xoauth2-tool get-token gmail \
    PATH_TO_TOKENS_FILE \
    --client-id=CLIENT_ID_FROM_SASL_XOAUTH2_CONF \
    --client-secret=CLIENT_SECRET_FROM_SASL_XOAUTH2_CONF \
    --scope="https://mail.google.com/"

Please open this URL in a browser ON THIS HOST (or that has port 54332 forwarded to this host):

http://127.0.0.1:54332/auth
```

The tool listens on `127.0.0.1` only (use `--local-listen-address` to change
this, e.g. inside a container), and protects the exchange with a random `state`
and PKCE.

(This script must run on the same host that is opening the URL -- it's not
possible to copy the URL and paste it into a browser on another computer. This
is because [recent
changes](https://developers.googleblog.com/2022/02/making-oauth-flows-safer.html)
to the OAuth2 authorization flow require that the browser pass the resulting
authorization code directly to the requesting application. If the Postfix
installation is running on a headless host, simply run the script on a host with
a usable browser then copy the resulting token file over to the headless host.)

Opening the URL and authorizing the application should result in a new token in
`PATH_TO_TOKENS_FILE`, which should be the file specified in
`/etc/postfix/sasl_passwd`.  In our example that file will be either
`/etc/tokens/username@domain.com` or
`/var/spool/postfix/etc/tokens/username@domain.com` (see [A Note on
chroot](#a-note-on-chroot)):

```json
{
  "access_token" : "access token goes here",
  "expiry" : "0",
  "refresh_token" : "refresh token goes here"
}
```

In my configuration, chroot is enabled and so even though
`/etc/postfix/sasl_passwd` specifies `/etc/tokens/username@domain.com`,
my token file is `/var/spool/postfix/etc/tokens/username@domain.com`.

It may be necessary to adjust permissions on the token file so that Postfix (or,
more accurately, sasl-xoauth2 running as the Postfix user) can update it. See
[A Note on Token File Permissions](#a-note-on-token-file-permissions).

Skip to [restart Postfix](#restart-postfix) below.

### Outlook/Microsoft 365 Configuration

sasl-xoauth2 supports two ways of obtaining tokens for Outlook and Microsoft
365. Both use the same Postfix configuration; they differ in who authorizes
access and in what the token file contains.

|  | [Way A: delegated access (interactive sign-in)](#way-a-delegated-access-with-sasl-xoauth2-tool-get-token) | [Way B: app-only access (client credentials)](#way-b-app-only-access-with-client-credentials) |
|---|---|---|
| Who authorizes | The mailbox user signs in once with `sasl-xoauth2-tool get-token` | An administrator grants an application access to the mailbox; nobody signs in |
| Token file holds | A refresh token | Client ID and client secret |
| Access ends when | The refresh token expires or is revoked (e.g. 90 days without use, password change, Conditional Access); the user must sign in again | The client secret expires (at most 24 months) or is deleted, or the mailbox permission is removed |
| Entra ID application | Public client, delegated permission `SMTP.Send` | Confidential client with a secret, application permission `SMTP.SendAsApp` with admin consent, service principal registered in Exchange Online |
| Accounts | Personal (outlook.com) and work/school accounts | Work/school (Microsoft 365) accounts only |
| Selected by | Default (`grant_type` `refresh_token`) | `"grant_type": "client_credentials"` in the token file |

Way A is the default. Its interactive sign-in is a deliberate control: when the
refresh token stops working, a person has to confirm access again. Way B suits
unattended relays where that is not wanted; access is then bounded by the
lifetime of the client secret and by the mailbox permissions in Exchange
Online. Both can coexist on one host, each with its own token file.

#### Common Prerequisites

Configure Postfix as described in [Configure Mail Agent](#configure-mail-agent),
with the Microsoft 365 relay:

```
relayhost = [smtp.office365.com]:587
```

and, in `/etc/postfix/sasl_passwd`, the mailbox that sends the mail and the
path of its token file:

```
[smtp.office365.com]:587 relay@contoso.com:/etc/tokens/relay@contoso.com
```

The examples below use `/etc/tokens`, which is where the token files are when
Postfix's `smtp` service is not chrooted (the default on Ubuntu 26.04). If it is chrooted, the token files must be in
`/var/spool/postfix/etc/tokens` instead (see [A Note on
chroot](#a-note-on-chroot)). On Ubuntu 26.04, Postfix must also be allowed to
write to `/etc/tokens` (see [A Note on Ubuntu 26.04](#a-note-on-ubuntu-2604)).

SMTP AUTH must be enabled for the mailbox. It is often disabled for the whole
organization (`Get-TransportConfig | Format-List SmtpClientAuthenticationDisabled`);
rather than enabling it organization-wide, enable it for just this mailbox in
Exchange Online PowerShell:

```
Set-CASMailbox -Identity relay@contoso.com -SmtpClientAuthenticationDisabled $false
```

You will need the *tenant ID* (Microsoft Entra admin center, "Overview") for
work/school accounts. Token requests go to
`https://login.microsoftonline.com/TENANT/oauth2/v2.0/token`, where `TENANT` is
the tenant ID (or the tenant's domain, e.g. `contoso.onmicrosoft.com`) for
work/school accounts, or `consumers` for personal accounts. `common` and
`organizations` also work for Way A, but a specific tenant is preferable. See
[Microsoft's endpoint
documentation](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols#endpoints).

Token files contain secrets; see [A Note on Token File
Permissions](#a-note-on-token-file-permissions).

> [!WARNING] When using Microsoft's HVE endpoint (smtp-hve.office365.com), set
> `refresh_window` in the configuration file to at least 600 seconds (10
> minutes) to prevent the "501 5.5.127 Invalid XOAUTH2 auth data - Token will
> expire soon" error. (Before version 0.29, a `refresh_window` set in the
> configuration file had no effect.)

##### National Clouds (US Government, 21Vianet)

Microsoft operates separate cloud environments for government and sovereign
regions, with different login endpoints and scopes. `sasl-xoauth2-tool` selects
them with `--cloud`:

| Cloud | `--cloud` value | Login endpoint | Delegated scope (Way A) | App-only scope (Way B) |
|---|---|---|---|---|
| Public (default) | `public` | `login.microsoftonline.com` | `https://outlook.office.com/SMTP.Send` | `https://outlook.office365.com/.default` |
| US Government GCC High | `usgov` | `login.microsoftonline.us` | `https://outlook.office365.us/SMTP.Send` | `https://outlook.office365.us/.default` |
| US Government DoD | `usgov-dod` | `login.microsoftonline.us` | `https://outlook.office365.us/SMTP.Send` | `https://outlook.office365.us/.default` |
| China (21Vianet) | `china` | `login.partner.microsoftonline.cn` | `https://partner.outlook.cn/SMTP.Send` | `https://partner.outlook.cn/.default` |

Use the matching token endpoint, e.g.
`https://login.microsoftonline.us/TENANT_ID/oauth2/v2.0/token` or
`https://login.partner.microsoftonline.cn/TENANT_ID/oauth2/v2.0/token`. For an
environment that is not listed, override the login endpoint and scope with
`--login-base` and `--scope`:

```shell
$ sasl-xoauth2-tool get-token outlook \
    PATH_TO_TOKENS_FILE \
    --client-id=CLIENT_ID \
    --tenant=TENANT_ID \
    --login-base=https://login.microsoftonline.us \
    --scope="offline_access https://outlook.office365.us/SMTP.Send" \
    --use-device-flow
```

#### Way A: Delegated Access with `sasl-xoauth2-tool get-token`

The mailbox user signs in once; sasl-xoauth2 then keeps the token alive on its
own. The device flow described here is the preferred variant; an
[authorization code variant](#variant-authorization-code-flow) is described
below.

##### A1. Register the Application

[Register an
application](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app)
in the Microsoft Entra admin center:

* Use any name you like (it doesn't have to be "sasl-xoauth2").
* Select the appropriate type of account: "Accounts in this organizational
  directory only" for a Microsoft 365 tenant, or personal Microsoft accounts
  for outlook.com (see upstream issue [#89](https://github.com/tarickb/sasl-xoauth2/issues/89)
  for why this matters).
* Do **not** add any redirect URIs or set up any platform configurations.
* Under "Authentication", you **must** set "Allow public client flows" to
  "yes".

Then add the delegated permission `SMTP.Send`:

1. On the app registration's "API permissions" page, click "Add a permission".
1. Click "Microsoft Graph", then "Delegated permissions".
1. Enter "SMTP.Send" in the search box, expand `SMTP`, and check `SMTP.Send`.
1. Optionally, "Grant admin consent" so that users are not asked to consent.

##### A2. Configure sasl-xoauth2

Store the "Application (client) ID" (from the app's "Overview" page) and the
token endpoint in `/etc/sasl-xoauth2.conf`. Leave `client_secret` empty: the
device flow uses a public client, and sasl-xoauth2 then sends no secret.

```json
{
  "client_id": "APPLICATION_ID",
  "client_secret": "",
  "token_endpoint": "https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/token"
}
```

(For personal outlook.com accounts, use `consumers` instead of `TENANT_ID`.)

##### A3. Obtain the Initial Token

Run the tool and sign in **as the mailbox user that sends the mail** (the user
in `/etc/postfix/sasl_passwd`). The token is bound to that user. The token file
is the path from `sasl_passwd` -- with chroot, below `/var/spool/postfix` (see
[A Note on chroot](#a-note-on-chroot)):

```shell
$ sasl-xoauth2-tool get-token outlook \
    /etc/tokens/relay@contoso.com \
    --client-id=APPLICATION_ID \
    --tenant=TENANT_ID \
    --use-device-flow
To sign in, use a web browser to open the page https://www.microsoft.com/link and enter the code REDACTED to authenticate.
Acquired token.
Wrote token to /etc/tokens/relay@contoso.com.
```

Open the page in any browser (it does not have to be on this host), enter the
code, sign in as the mailbox user and accept the prompts. Omit `--tenant` for
personal accounts (it defaults to `consumers`), and add `--cloud` for national
clouds. The device flow needs the Python `msal` module.

Then give the token file to the Postfix user (see [A Note on Token File
Permissions](#a-note-on-token-file-permissions)):

```
$ sudo chown -R postfix:postfix /etc/tokens
$ sudo chmod 700 /etc/tokens
$ sudo chmod 600 /etc/tokens/*
```

##### A4. Test

```
$ sasl-xoauth2-tool test-token-refresh /etc/tokens/relay@contoso.com
Config check passed.
Token refresh succeeded.
```

See [Testing Your Configuration](#testing-your-configuration), then [restart
Postfix](#restart-postfix).

##### A5. Renewing the Token

From then on, sasl-xoauth2 requests new access tokens itself and stores the new
refresh token that Microsoft returns with each of them. When the refresh token
stops working (`invalid_grant` in the log, see
[Troubleshooting](#troubleshooting-microsoft-365)), sign in again with the same
command, adding `--overwrite-existing-token` to keep any other fields of the
token file (such as `user` or `token_endpoint`):

```shell
$ sasl-xoauth2-tool get-token outlook \
    /etc/tokens/relay@contoso.com \
    --client-id=APPLICATION_ID \
    --tenant=TENANT_ID \
    --use-device-flow \
    --overwrite-existing-token
```

The file is replaced atomically, keeping its permissions. Postfix needs no
restart: the token file is read for every authentication.

##### A6. Monitoring

Run `sasl-xoauth2-tool test-token-refresh TOKEN_FILE` regularly (for example
from cron or your monitoring system). It exits with a non-zero status, and
prints the reason, when the refresh token no longer works. It does not modify
the token file.

Note that only Postfix's own token refreshes (which happen when mail is sent)
extend the life of the stored refresh token; the monitoring check does not. A
relay that sends no mail for 90 days therefore loses its refresh token -- the
check reports this, but cannot prevent it.

##### Variant: Authorization Code Flow

If the device flow cannot be used, the tool can instead print a sign-in URL and
read back the URL the browser ends up on. This was the original method and is
deprecated in favor of the device flow, but still works. Register the
application as in [A1](#a1-register-the-application), and additionally add a
"Mobile and desktop applications" platform with the redirect URI
`https://login.microsoftonline.com/common/oauth2/nativeclient` ("Allow public
client flows" is not needed for this variant).
Then run the tool without `--use-device-flow`:

```shell
$ sasl-xoauth2-tool get-token outlook \
    /etc/tokens/relay@contoso.com \
    --client-id=APPLICATION_ID \
    --tenant=TENANT_ID
Please enter OAuth2 client secret (leave empty for public clients):
Please visit the following link in a web browser, then paste the resulting URL:

https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/authorize?client_id=REDACTED&response_type=code&redirect_uri=https%3A%2F%2Flogin.microsoftonline.com%2Fcommon%2Foauth2%2Fnativeclient&response_mode=query&scope=offline_access+https%3A%2F%2Foutlook.office.com%2FSMTP.Send&state=REDACTED&code_challenge=REDACTED&code_challenge_method=S256

Resulting URL: https://login.microsoftonline.com/common/oauth2/nativeclient?code=REDACTED&state=REDACTED
Wrote token to /etc/tokens/relay@contoso.com.
```

After signing in you are redirected to a blank page; copy its URL into the
terminal. The tool protects the exchange with a random `state` and PKCE.

Some users have [reported](https://github.com/tarickb/sasl-xoauth2/issues/61) (upstream issue)
needing a client secret with this variant, for applications registered for
"accounts in any organizational directory". In that case, enter the secret when
prompted and also set it as `client_secret` in `/etc/sasl-xoauth2.conf` (or in
the token file, which is not world-readable).

#### Way B: App-Only Access with Client Credentials

An application gets permission to send as an existing mailbox, using the
[client credentials grant
flow](https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth#use-client-credentials-grant-flow-to-authenticate-smtp-imap-and-pop-connections).
Nobody signs in and there is no refresh token: whenever the current access
token is about to expire, sasl-xoauth2 requests a new one with the client ID and
secret. The mailbox itself is unchanged. All steps are done by administrators.

##### B1. Register the Application

Use a separate application from Way A (that one is a public client without a
secret). In the Microsoft Entra admin center:

1. [Register an
   application](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app)
   for "Accounts in this organizational directory only". No redirect URI or
   platform configuration is needed, and "Allow public client flows" stays
   "no".
1. Under "Certificates & secrets", create a new client secret. Copy its
   *value* (it is shown only once) and note its expiry date.
1. Under "API permissions", choose "Add a permission", then "APIs my
   organization uses", search for "Office 365 Exchange Online", choose
   "Application permissions", and select `SMTP.SendAsApp`.
1. Click "Grant admin consent".

Note the "Application (client) ID" from the app registration's "Overview", and
the "Object ID" from the app's page under **Enterprise applications** -- *not*
the Object ID shown under App registrations.

##### B2. Grant the Application Access to the Mailbox

In Exchange Online PowerShell, register the application's service principal
and give it access to the mailbox:

```
Install-Module -Name ExchangeOnlineManagement
Connect-ExchangeOnline -Organization TENANT_ID
New-ServicePrincipal -AppId APPLICATION_ID -ObjectId ENTERPRISE_APP_OBJECT_ID -DisplayName "sasl-xoauth2"
$sp = Get-ServicePrincipal -Identity "sasl-xoauth2"
Add-MailboxPermission -Identity relay@contoso.com -User $sp.Identity -AccessRights FullAccess
```

The application can only use mailboxes granted this way. If Postfix relays mail
with sender addresses other than the mailbox's own (for example, other users or
a shared address), also grant `SendAs` for each of them:

```
Add-RecipientPermission -Identity sender@contoso.com -Trustee $sp.Identity -AccessRights SendAs
```

`SMTP.SendAsApp` only allows sending; the mailbox cannot be read with it.
Permission changes in Exchange Online can take a while to take effect.

##### B3. Create the Token File

`sasl-xoauth2-tool` creates the token file and, in doing so, checks that a
token can actually be obtained:

```shell
$ sasl-xoauth2-tool get-token outlook \
    /etc/tokens/relay@contoso.com \
    --client-credentials \
    --tenant=TENANT_ID \
    --client-id=APPLICATION_ID \
    --mailbox=relay@contoso.com
Please enter OAuth2 client secret:
Acquired app-only token.
Wrote token to /etc/tokens/relay@contoso.com.
```

(Add `--cloud` for national clouds. The secret can also be passed with
`--client-secret`, but then it ends up in the shell history.) The file contains
everything needed to request new tokens, and is created readable by its owner
only:

```json
{
    "grant_type": "client_credentials",
    "scope": "https://outlook.office365.com/.default",
    "token_endpoint": "https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/token",
    "client_id": "APPLICATION_ID",
    "client_secret": "client secret value",
    "user": "relay@contoso.com",
    "access_token": "...",
    "expiry": 1792505479
}
```

The file may also be written by hand: `access_token` and `expiry` can be left
out, and a token is then requested on first use. `user` is the mailbox to send
as; it may be left out if the user name in `sasl_passwd` already is the mailbox
address.

`/etc/sasl-xoauth2.conf` must still exist with `client_id` and `client_secret`
keys (they may be empty, or hold Way A's values); the values in the token file
take precedence. Alternatively, `grant_type` and `scope` may be set in
`/etc/sasl-xoauth2.conf` to apply to all token files.

To switch a token file back to Way A, run the Way A `get-token` command with
`--overwrite-existing-token`; the tool then removes the client credentials
settings (`grant_type`, `scope`, `client_id`, `client_secret`) from the file.

Give the token file to the Postfix user as in [A3](#a3-obtain-the-initial-token).

##### B4. Test and Switch Over

```
$ sasl-xoauth2-tool test-token-refresh /etc/tokens/relay@contoso.com
Config check passed.
Token refresh succeeded.
```

If the mailbox previously used Way A, write the new token file under a
different name first, test it, then point `/etc/postfix/sasl_passwd` at it and
run `postmap /etc/postfix/sasl_passwd` and `postfix reload`. Keep the old token
file until you are sure; switching back is just a matter of changing the path
again.

##### B5. Rotating the Client Secret

Before the secret expires, create a new one under "Certificates & secrets",
replace `client_secret` in the token file (keeping owner and permissions), run
`sasl-xoauth2-tool test-token-refresh`, and then delete the old secret. An
expired secret makes token requests fail with `invalid_client`.

##### B6. Monitoring

`sasl-xoauth2-tool test-token-refresh TOKEN_FILE` works exactly as for Way A
and reports an expired or deleted secret. Also keep track of the secret's
expiry date. Unlike Way A, access does not lapse when no mail is sent.

#### Troubleshooting Microsoft 365

Exchange Online rejects a bad token with `535 5.7.3 Authentication
unsuccessful` and no further details. Run `sasl-xoauth2-tool test-token-refresh
TOKEN_FILE` to see the reason from Microsoft Entra ID; sasl-xoauth2 also logs
it, with a hint, when a token request fails (see [Debugging](#debugging)).

| Symptom | Likely cause |
|---|---|
| `invalid_grant` (e.g. AADSTS700082, AADSTS50173) | Way A: the refresh token expired or was revoked. [Sign in again](#a5-renewing-the-token). |
| `invalid_grant`, AADSTS7000012 | The token was obtained for a different tenant than the one in `token_endpoint`. |
| `invalid_client` (e.g. AADSTS7000215, AADSTS7000222) | Wrong or expired client secret. For the device flow (public client), `client_secret` must be empty. |
| `unauthorized_client`, AADSTS700016 | The application ID is unknown in this tenant: check `client_id` and the tenant in `token_endpoint`. |
| AADSTS65001 | Consent is missing: grant (admin) consent for the permission. |
| `535 5.7.139 ... SmtpClientAuthentication is disabled` | SMTP AUTH is disabled for the mailbox or tenant; see [Common Prerequisites](#common-prerequisites). |
| `535 5.7.3` although the token refresh succeeds | Way B: the service principal is missing or has no mailbox permission (check the Object ID in B2); or the `user` is not the mailbox the permission was granted for. |
| `554 5.2.252 SendAsDenied` | The sender address is not the mailbox's own and `SendAs` has not been granted. |
| `501 5.5.127 ... Token will expire soon` | Increase `refresh_window` (HVE needs at least 600). |

#### Further Reading

- [Authenticate an IMAP, POP or SMTP connection using OAuth](https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth)
- [Microsoft identity platform and the OAuth 2.0 device authorization grant flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code)
- [Microsoft identity platform and OAuth 2.0 authorization code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)
- [Microsoft identity platform and the OAuth 2.0 client credentials flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow)
- [Refresh token lifetime](https://learn.microsoft.com/en-us/entra/identity-platform/refresh-tokens)

### Proxy Support

In case the system is behind a corporate web proxy you can configure a proxy
that is used by the curl library when refreshing the token.

```json
{
  "client_id": "client ID goes here",
  "client_secret": "client secret goes here",
  "token_endpoint": "token endpoint goes here",
  "proxy" : "http://proxy:8080"
}
```

For supported proxy schemes please refer to the [curl library documentation](https://curl.se/libcurl/c/CURLOPT_PROXY.html)

### Testing Your Configuration

sasl-xoauth2 provides a tool, `sasl-xoauth2-tool`, that allows the
semi-interative testing of configuration and token files (which is a lot more
useful than parsing log files when trying to figure out why Postfix isn't
delivering mail correctly).

First, test your configuration file:

```
$ sasl-xoauth2-tool test-config --config-file ./bad-config.conf
sasl-xoauth2: Missing required value: client_secret
Config check failed.
$ sasl-xoauth2-tool test-config --config-file ./good-config.conf
Config check passed.
$ sasl-xoauth2-tool test-config --config-file /etc/sasl-xoauth2.conf
Config check passed.
```

(Specifying the path is only required if your configuration file isn't located
in the system-default path.)

Next, test your token file:

```
$ sasl-xoauth2-tool test-token-refresh ./bad-token.json
Config check passed.
2022-09-10 09:18:59: TokenStore::Read: file=./bad-token.json
2022-09-10 09:18:59: TokenStore::Read: grant_type=refresh_token, refresh=<redacted, 103 bytes>, access=<redacted, 215 bytes>, user=
2022-09-10 09:18:59: TokenStore::Refresh: attempt 1
2022-09-10 09:18:59: TokenStore::Refresh: token_endpoint: https://accounts.google.com/o/oauth2/token
2022-09-10 09:18:59: TokenStore::Refresh: request: grant_type=refresh_token, client_id=REDACTED, client_secret=<redacted, 35 bytes>, refresh_token=<redacted, 103 bytes>, scope=<not sent>
2022-09-10 09:19:00: TokenStore::Refresh: code=400, response={
  "error": "invalid_grant",
  "error_description": "Bad Request"
}
2022-09-10 09:19:00: TokenStore::Refresh: error=invalid_grant, description=Bad Request
2022-09-10 09:19:00: TokenStore::Refresh: hint: the refresh token was rejected (expired, revoked, or issued for a different client/tenant/scope); obtain a new one with 'sasl-xoauth2-tool get-token'
2022-09-10 09:19:00: TokenStore::Refresh: request failed
Token refresh failed.
$ sasl-xoauth2-tool test-token-refresh ./good-token.json
Config check passed.
Token refresh succeeded.
```

(Again, you'll have to specify your configuration file with
`--config-file <config file>` if it isn't located at the system-default path.)

### Restart Postfix

```
$ service postfix restart
```

## Using Multiple Mail Providers or Users Simultaneously

One instance of sasl-xoauth2 may provide tokens for different mail providers
and/or users.
Each provider will require its own client ID, client secret, and token
endpoint. Each user may require a username to be specified, if the username
automatically obtained from postfix is not correct.
In this case, each of these may be set in the token file rather than
in `/etc/sasl-xoauth2.conf`. Set them when setting the initial access token:

```json
{
  "access_token" : "access token goes here",
  "client_id": "client ID goes here",
  "client_secret": "client secret goes here, if required",
  "token_endpoint": "token endpoint goes here, for non-Gmail",
  "expiry" : "0",
  "refresh_token" : "refresh token goes here",
  "user" : "username goes here"
}
```

`sasl-xoauth2-tool` has an argument `--overwrite-existing-token` to preserve the content of these additional fields
when manually updating an expired or invalidated token.

The token file may also set `grant_type`, `scope`, `proxy`, `ca_bundle_file`,
`ca_certs_dir` and `refresh_window` (see `sasl-xoauth2.conf(5)`).

## Debugging

### Logging Options

sasl-xoauth2 collects a trace of each authentication and, depending on these
settings in `/etc/sasl-xoauth2.conf`, writes it to syslog, prefixed
`[sasl-xoauth2]` (within Postfix, under Postfix's syslog facility, normally
`mail`):

| Setting | Default | Effect |
|---|---|---|
| `log_to_syslog_on_failure` | `yes` | When authentication fails, log the last line of the trace (usually the reason, e.g. the provider's error and a hint). `no` disables all logging on failure. |
| `log_full_trace_on_failure` | `no` | When authentication fails, log the whole trace instead of only its last line. |
| `always_log_to_syslog` | `no` | Log every trace line immediately, also for successful authentications. |

Tokens and secrets are always redacted; user names, token file paths, token
endpoints and the provider's error responses are logged. The recommended
setting for production is the default, which may be spelled out to document
it:

```json
{
  "client_id": "client ID goes here",
  "client_secret": "client secret goes here",
  "log_to_syslog_on_failure": "yes",
  "log_full_trace_on_failure": "no"
}
```

Setting `log_to_syslog_on_failure` to `no` is not recommended: Postfix itself
only reports a generic SASL failure, so the cause (e.g. an expired refresh
token or client secret) would then not appear anywhere. To investigate a
problem, temporarily set `log_full_trace_on_failure` to `yes` (or run
`sasl-xoauth2-tool test-token-refresh`, which prints the full trace when the
token request fails),
and to see successful authentications as well, `always_log_to_syslog`.
Changes take effect when Postfix restarts its `smtp` processes (`postfix
reload`).

### Postfix Logging

It can be useful (thanks [@kpedro88](https://github.com/kpedro88)!) to increase
Postfix's logging level, following the instructions
[here](https://www.postfix.org/DEBUG_README.html#verbose).

### SASL Mechanisms

If Postfix complains about not finding a SASL mechanism (along the lines of
`warning: SASL authentication failure: No worthy mechs found`), it's possible
`make install` put libsasl-xoauth2.so in the wrong directory (see the
installation paths under [Building from Source](#building-from-source)).
