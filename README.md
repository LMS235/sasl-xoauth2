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

This section covers a new installation. To update an existing installation to
a newer version, see [Updating an Existing
Installation](#updating-an-existing-installation).

### Requirements

| Purpose | Requirement | Ubuntu/Debian package |
|---|---|---|
| Compiler and build tools | C++17 compiler, `make`, CMake, pkg-config | `build-essential`, `cmake`, `pkgconf` |
| HTTPS requests | libcurl (OpenSSL or GnuTLS flavor) | `libcurl4-openssl-dev` |
| Client certificates (signing client assertions) | OpenSSL (libcrypto) | `libssl-dev` |
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
OpenSSL 3, jsoncpp 1.9.6, Cyrus SASL 2.1.28, Postfix 3.10, Python 3.14).
Install the build dependencies:

```
$ sudo apt install build-essential cmake pkgconf git \
    libcurl4-openssl-dev libssl-dev libjsoncpp-dev libsasl2-dev \
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
$ sudo chown root:postfix /etc/sasl-xoauth2.conf
```

(The last step lets the Postfix user read the configuration, see [A Note on
Token File Permissions](#a-note-on-token-file-permissions); it is only needed
after the first installation.)

The build is optimized and hardened by default (`RelWithDebInfo`, with
`_FORTIFY_SOURCE`, stack protector and full RELRO), and the plugin exports
only its SASL entry point. The two `-D` options matter: with CMake's default prefix (`/usr/local`) the
plugin would be installed to `/usr/local/lib/sasl2`, where the system's Cyrus
SASL library (and thus Postfix) does not look, and the configuration file to
`/usr/local/etc`. With the options above, the following files are installed:

| File | Purpose |
|---|---|
| `/usr/lib/x86_64-linux-gnu/sasl2/libsasl-xoauth2.so` | The SASL plugin |
| `/etc/sasl-xoauth2.conf` | Configuration file template (see [Configuration](#configuration)), owner `root:root`, mode `0640`; only installed if the file does not exist yet, an existing configuration is never overwritten |
| `/usr/bin/sasl-xoauth2-tool` | Tool to obtain tokens and test the configuration |
| `/usr/lib/x86_64-linux-gnu/sasl-xoauth2/test-config` | Helper used by `sasl-xoauth2-tool test-config` and `test-token-refresh` |
| `/usr/share/man/man5/sasl-xoauth2.conf.5`, `/usr/share/man/man1/sasl-xoauth2-tool.1` | Man pages |

(On other architectures, `x86_64-linux-gnu` is replaced by the respective
multiarch directory.) Check that SASL finds the plugin:

```
$ sudo saslpluginviewer -c -m XOAUTH2
...
Plugin "sasl-xoauth2" [loaded],         API version: 4
        SASL mechanism: XOAUTH2, best SSF: 60
        security flags: NO_ANONYMOUS|NO_PLAINTEXT|PASS_CREDENTIALS
        features: WANT_CLIENT_FIRST|PROXY_AUTHENTICATION
```

`[loaded]` also means that `/etc/sasl-xoauth2.conf` was read successfully; a
missing, unreadable or invalid configuration prevents the plugin from loading.
(Hence `sudo`: the configuration is not readable for other users.)

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
`cmake` command (and skip `ctest`).

### Updating an Existing Installation

An update rebuilds the plugin from the newer sources and installs it over the
existing installation. The configuration (`/etc/sasl-xoauth2.conf`), the token
files, `/etc/postfix/sasl_passwd` and the systemd drop-in for Postfix are not
touched.

1. Change to the source directory from the original installation (if it no
   longer exists, clone the repository again as in [Ubuntu 26.04
   LTS](#ubuntu-2604-lts)). Note the installed version in case you need to go
   back, and keep a copy of the configuration:

   ```
   $ cd sasl-xoauth2
   $ git log -1 --oneline
   $ sudo cp -a /etc/sasl-xoauth2.conf /etc/sasl-xoauth2.conf.bak
   $ git remote -v
   ```

   The remote must be this repository, `LMS235/sasl-xoauth2`. A checkout of
   the original project (`tarickb/sasl-xoauth2`, e.g. from installing 0.28 or
   earlier) does not get these versions with `git pull`; switch it first:

   ```
   $ git remote set-url origin https://github.com/LMS235/sasl-xoauth2.git
   ```

   If the directory is not a git checkout (e.g. a release tarball), clone the
   repository again instead.

1. Fetch the new version, and read what changed (new entries at the top of
   `ChangeLog`; check in particular whether any configuration changes are
   needed, and, when coming from 0.28 or earlier, see [Upgrading to
   0.29](#upgrading-to-029)):

   ```
   $ git pull
   $ sed -n '1,/^ -- /p' ChangeLog
   ```

1. Build, test and install exactly as for a new installation:

   ```
   $ cmake -S . -B build -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_SYSCONFDIR=/etc
   $ cmake --build build -j"$(nproc)"
   $ ctest --test-dir build
   $ sudo cmake --install build
   ```

   The install reports `Keeping existing: /etc/sasl-xoauth2.conf`.

1. Check that the new plugin loads, and that tokens can still be refreshed:

   ```
   $ sudo saslpluginviewer -c -m XOAUTH2
   $ sasl-xoauth2-tool --version
   $ sudo -u postfix sasl-xoauth2-tool test-config
   $ sudo -u postfix sasl-xoauth2-tool test-token-refresh /etc/tokens/relay@contoso.com
   ```

   `--version` must show the new version for the tool, `test-config` and the
   plugin, and exit without a warning (see [Testing Your
   Configuration](#testing-your-configuration)).

1. Let Postfix load the new plugin. Running `smtp` processes keep the old one
   until they are replaced; `postfix reload` replaces them once they are done
   with their current delivery:

   ```
   $ sudo postfix reload
   ```

1. Send a test mail and check the mail log (`journalctl -u postfix` or
   `/var/log/mail.log`) for `status=sent`.

To go back to the previous version, check out the version noted in step 1
(`git checkout <commit>`), and repeat steps 3 to 5. Versions before the fix
for [LMS235/sasl-xoauth2#3](https://github.com/LMS235/sasl-xoauth2/pull/3)
overwrite `/etc/sasl-xoauth2.conf` when installing; restore it from the copy
made in step 1, and set its owner and mode again (`sudo chown root:postfix
/etc/sasl-xoauth2.conf && sudo chmod 640 /etc/sasl-xoauth2.conf`). Versions
before 0.29 have no `refresh-token` command: disable the [daily
refresh](#daily-token-refresh) (`sudo systemctl disable --now
sasl-xoauth2-refresh.timer`) while running one. Afterwards, `git checkout
master` returns to the current version.

If the build fails after an update with errors about the CMake cache (for
example after a major Ubuntu upgrade), remove the build directory (`rm -rf
build`) and repeat step 3.

### Upgrading to 0.29

Version 0.29 changes several defaults for security and reliability. When
upgrading from 0.28 or earlier, in addition to the steps above:

1. **Install the new build dependency** before building, or the `cmake` step
   fails (`Could NOT find OpenSSL`):

   ```
   $ sudo apt install libssl-dev
   ```

   Remove the build directory once (`sudo rm -rf build`; earlier instructions
   ran `make install` in it as root): the default build type is now an
   optimized, hardened build, and the build commands changed (see [Ubuntu
   26.04 LTS](#ubuntu-2604-lts)).
1. **Remove older copies** below `/usr/local`, and a distribution package of
   sasl-xoauth2, if any, *before* running `sudo cmake --install build` (see
   [Removing Older Installations](#removing-older-installations)): removing
   the package afterwards would delete the newly installed files.
1. **Tighten permissions.** Earlier versions rewrote token files with the
   process umask, which usually made them readable for all users, and
   installed the configuration world-readable:

   ```
   $ sudo chown -R postfix:postfix /etc/tokens
   $ sudo chmod 700 /etc/tokens
   $ sudo find /etc/tokens -type f -exec chmod 600 {} +
   $ sudo chown root:postfix /etc/sasl-xoauth2.conf
   $ sudo chmod 640 /etc/sasl-xoauth2.conf
   ```

   (With chroot, the token files are below `/var/spool/postfix/etc/tokens`.)
1. **Require verified TLS** to the relay: change `smtp_tls_security_level =
   encrypt` (or `may`) to `secure`, add `smtp_tls_secure_cert_match =
   nexthop`, and set `smtp_sasl_security_options` and
   `smtp_sasl_tls_security_options` to `noanonymous` (see [Configure Mail
   Agent](#configure-mail-agent)); check the relay with `posttls-finger`
   before reloading Postfix.
1. **Ubuntu 26.04:** earlier instructions relaxed Postfix's sandbox with
   `ProtectSystem=true`. In `sudo systemctl edit postfix.service`, remove that
   line and add `ReadWritePaths=-/etc/tokens` instead (add the drop-in if you
   had none), then `sudo systemctl restart postfix` (`postfix reload` does not
   apply unit changes) and run the check from [A Note on Ubuntu
   26.04](#a-note-on-ubuntu-2604).
1. **Check `refresh_window`:** a `refresh_window` in `/etc/sasl-xoauth2.conf`
   had no effect before 0.29 and now does; the default changed from 10 to 300
   seconds. Values above 1800, or anything that is not an integer, are now
   rejected: in the configuration, they prevent the plugin from loading (all
   mail is deferred); in a token file, they make the token file unreadable.
   `"refresh_window": "0"` entries that earlier versions wrote into token files
   are ignored and removed. Before reloading Postfix, check the configuration
   with `sudo -u postfix sasl-xoauth2-tool test-config` and each token file with
   `sudo -u postfix sasl-xoauth2-tool test-token-refresh`.
1. **Token files that override the connection:** a token file that sets its
   own `token_endpoint`, `proxy`, `ca_bundle_file` or `ca_certs_dir` no longer
   gets the `client_secret` from `/etc/sasl-xoauth2.conf`; give it its own
   `client_secret` (empty for public clients). `test-token-refresh` reports
   such files.
1. **Monitoring scripts:** `test-token-refresh` now exits with 1 (transient)
   or 2 (needs action) instead of always 1, and also fails when the token
   directory is not writable. Replace periodic `test-token-refresh` checks by
   the [daily refresh](#daily-token-refresh), which also keeps unused refresh
   tokens alive.
1. **With chroot:** `cmake --install` does not update the CA certificate hook.
   Install the new script again and run it (it now also removes certificates
   that are gone from the system):

   ```
   $ sudo install -m 755 scripts/postfix-sasl-xoauth2-update-ca-certs /etc/ca-certificates/update.d/
   $ sudo /etc/ca-certificates/update.d/postfix-sasl-xoauth2-update-ca-certs
   ```
1. **Optionally, for Way B:** switch from a client secret to a certificate
   (see [Way B](#way-b-app-only-access-with-client-credentials)).

Then run `sudo postfix reload`, send a test mail, and check the mail log.

### Removing Older Installations

Before the first installation with the paths above, make sure no older copy of
sasl-xoauth2 is installed elsewhere. In particular, an earlier build installed
with CMake's default prefix lives below `/usr/local`, and because
`/usr/local/bin` comes first in `PATH`, its `sasl-xoauth2-tool` (with its own
`test-config` helper and its own configuration file) would still be used:

```
$ ls -l /usr/local/bin/sasl-xoauth2-tool /usr/local/lib/sasl2/libsasl-xoauth2.so* \
    /usr/local/lib/sasl-xoauth2 /usr/local/etc/sasl-xoauth2.conf \
    /usr/local/share/man/man*/sasl-xoauth2* 2>/dev/null
$ dpkg -l | grep -i xoauth2
```

If the configuration in use was `/usr/local/etc/sasl-xoauth2.conf`, copy it to
`/etc/sasl-xoauth2.conf` first. Remove a distribution package, if `dpkg` lists
one, *before* installing with `sudo cmake --install build` (`sudo apt remove
sasl-xoauth2`): it owns the same files below `/usr`, so removing it afterwards
deletes the new installation (if that happened, run `sudo cmake --install
build` again). Then remove the old files:

```
$ sudo rm -rf /usr/local/bin/sasl-xoauth2-tool /usr/local/lib/sasl2/libsasl-xoauth2.so* \
    /usr/local/lib/sasl-xoauth2 /usr/local/etc/sasl-xoauth2.conf \
    /usr/local/share/man/man*/sasl-xoauth2*
$ sudo rmdir --ignore-fail-on-non-empty /usr/local/lib/sasl2
$ hash -r
```

Only the sasl-xoauth2 plugin is removed from `/usr/local/lib/sasl2`; the
directory itself is only removed if no other SASL plugins are left in it.

(`hash -r` makes the current shell forget the old location of
`sasl-xoauth2-tool`.) Then check that the new installation is the one in use:

```
$ which -a sasl-xoauth2-tool
/usr/bin/sasl-xoauth2-tool
/bin/sasl-xoauth2-tool
$ grep '^TEST_TOOL_PATH' /usr/bin/sasl-xoauth2-tool
TEST_TOOL_PATH = '/usr/lib/x86_64-linux-gnu/sasl-xoauth2/test-config'
```

(`/bin` is a link to `/usr/bin` on current systems; no path below `/usr/local`
may appear.)

To uninstall, first disable what you set up around it (the [daily
refresh](#daily-token-refresh) timer or cron job, the CA certificate hook, the
systemd drop-in for Postfix, and the Postfix settings), then remove the files
listed in `build/install_manifest.txt` of the build directory the installation
was made from, except the configuration file:

```
$ sudo systemctl disable --now sasl-xoauth2-refresh.timer
$ sudo rm -f /etc/systemd/system/sasl-xoauth2-refresh.{service,timer} /etc/cron.d/sasl-xoauth2 \
    /etc/ca-certificates/update.d/postfix-sasl-xoauth2-update-ca-certs
$ grep -v '\.conf$' build/install_manifest.txt | sudo xargs -d '\n' rm -v
$ sudo rmdir /usr/lib/x86_64-linux-gnu/sasl-xoauth2
```

`/etc/sasl-xoauth2.conf` and the token files are kept; remove them as well if
they are no longer needed (they contain credentials).

### Other Distributions

The same steps should work on other distributions with the equivalent
packages, but only Ubuntu 26.04 has been tested. Package names may differ
(e.g. `python3-argparse-manpage` is not available everywhere; without it, only
the man page of `sasl-xoauth2-tool` is missing). CMake 3.13 or later is
required; `ctest --test-dir build` needs CMake 3.20 (with older versions, run
`(cd build && ctest)`).

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
ReadWritePaths=-/etc/tokens
```

Then `sudo systemctl restart postfix`. (The `-` keeps Postfix starting even if
the directory does not exist. On Ubuntu 26.04, `postfix.service` itself runs
the Postfix master; for additional instances started via `postfix@.service`,
edit that unit instead.) Token files inside the chroot
(`/var/spool/postfix/etc/tokens`) are not affected.

To check that Postfix can write to the token directory from inside its
sandbox, run the check in the mount namespace of the running Postfix master:

```
$ pid=$(sudo cat /var/spool/postfix/pid/master.pid | tr -d ' ')
$ sudo nsenter --target "$pid" --mount -- runuser -u postfix -- test -w /etc/tokens && echo writable
writable
```

## Configuration

### Configure Mail Agent

This plugin has only been tested with Postfix. First, configure Postfix to use
SASL, and specifically the XOAUTH2 method. In `/etc/postfix/main.cf`:

```
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_sasl_tls_security_options = noanonymous
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

You can check the effective value by calling `sudo pluginviewer -c` (on Debian/Ubuntu it’s installed as `/usr/sbin/saslpluginviewer` in the `sasl2-bin` package); look for
the "SSF" value:

```
Plugin "sasl-xoauth2" [loaded],         API version: 4
        SASL mechanism: XOAUTH2, best SSF: 60
        security flags: NO_ANONYMOUS|NO_PLAINTEXT|PASS_CREDENTIALS
        features: WANT_CLIENT_FIRST|PROXY_AUTHENTICATION
Plugin "login" [loaded],        API version: 4
        SASL mechanism: LOGIN, best SSF: 0
        security flags: NO_ANONYMOUS|PASS_CREDENTIALS
        features: SERVER_FIRST
```

See https://www.cyrusimap.org/sasl/sasl/authentication_mechanisms.html#authentication-mechanisms for details on the fields.

Then require TLS **with certificate verification**:

```
smtp_tls_security_level = secure
smtp_tls_secure_cert_match = nexthop
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache
```

This is essential. XOAUTH2 sends the access token as a bearer credential:
whoever obtains it can use it (for Gmail's `https://mail.google.com/` scope,
even to read the mailbox) until it expires. TLS is the only protection, and
the levels `may` and `encrypt` do not verify the server's certificate, so an
attacker on the network path could impersonate the mail server with any
certificate and collect the token. (For compatibility with existing
configurations, the plugin declares itself as not sending plaintext
passwords, so Postfix's `noplaintext` option does not stop XOAUTH2 without
TLS; `secure` does.)

If the host also delivers mail directly to other servers and should keep
opportunistic TLS (`may`) for them, require verified TLS for the relay only:

```
smtp_tls_security_level = may
smtp_tls_policy_maps = inline:{ { [smtp.office365.com]:587 = secure match=nexthop } }
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
```

Check the relay's certificate with `posttls-finger`, which ships with
Postfix:

```
$ posttls-finger -c -l secure -P /etc/ssl/certs "[smtp.office365.com]:587"
...
posttls-finger: Verified TLS connection established to smtp.office365.com[...]:587: TLSv1.3 ...
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
$ sudo mkdir -p /etc/tokens
$ sudo chown -R postfix:postfix /etc/tokens
$ sudo chmod 700 /etc/tokens
$ sudo find /etc/tokens -type f -exec chmod 600 {} +
```

or, with chroot, the same for `/var/spool/postfix/etc/tokens`. (`find` rather
than `chmod 600 /etc/tokens/*`: once the directory belongs to `postfix`, the
`*` cannot be expanded by an unprivileged shell.)

The easiest way to get ownership right is to run `sasl-xoauth2-tool` as the
Postfix user, e.g. `sudo -u postfix sasl-xoauth2-tool get-token ...`; the
token file then belongs to `postfix` from the start.

The configuration file `/etc/sasl-xoauth2.conf` may contain a client secret as
well. Postfix reads it while still running as root, so it does not have to be
readable for others; make it readable for the `postfix` group, so that
`sasl-xoauth2-tool test-token-refresh` can run as the Postfix user:

```
$ sudo chown root:postfix /etc/sasl-xoauth2.conf
$ sudo chmod 640 /etc/sasl-xoauth2.conf
```

Updated token files keep the owner and group permission bits of the file they
replace; permissions for other users are never carried over. (Versions before
0.29 created updated token files according to the process umask, which usually
made them world-readable. Re-run the `chmod` above after upgrading.)
`sasl-xoauth2-tool` creates new token files readable by their owner only; when
it updates an existing file (`--overwrite-existing-token`), it keeps the file's
owner and group, so running it as root does not lock Postfix out, and it takes
the same lock as the plugin, so that the two cannot overwrite each other's
changes. A new file created as root still needs the `chown` above. Do not edit
token files by hand while Postfix is delivering mail through them; if you must
(e.g. to replace a client secret), stop Postfix first or use the tool.

#### SSL/TLS Certificates

If you see an error message similar to the following, you may need to copy over
root CA certificates for the TLS handshake to work within sasl-xoauth2:

```
[sasl-xoauth2] auth failed (sasl-xoauth2 0.29): token request for /etc/tokens/... to https://... failed: error setting certificate file: /etc/ssl/certs/ca-certificates.crt
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
$ sudo -u postfix sasl-xoauth2-tool get-token gmail \
    PATH_TO_TOKENS_FILE \
    --client-id=CLIENT_ID_FROM_SASL_XOAUTH2_CONF \
    --scope="https://mail.google.com/"
Please enter OAuth2 client secret:
Please open this URL in a browser ON THIS HOST (or one that has port 54332 forwarded to this host):

https://accounts.google.com/o/oauth2/auth?client_id=...&state=...&code_challenge=...
```

The tool asks for the client secret rather than taking it on the command line
(where it would end up in the shell history and be visible to other users in
`ps`). It listens on `127.0.0.1` only (use `--local-listen-address` to change
this, e.g. inside a container), accepts only the answer to its own request
(random `state` and PKCE), and serves nothing but that answer.

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
| Token file holds | A refresh token | Client ID and a certificate (recommended) or a client secret |
| Access ends when | The refresh token expires or is revoked (e.g. 90 days without use, password change, Conditional Access); the user must sign in again | The certificate or client secret expires (a secret after at most 24 months) or is removed, or the mailbox permission is removed |
| Entra ID application | Public client, delegated permission `SMTP.Send` | Confidential client with a certificate or secret, application permission `SMTP.SendAsApp` with admin consent, service principal registered in Exchange Online |
| Accounts | Personal (outlook.com) and work/school accounts | Work/school (Microsoft 365) accounts only |
| Selected by | Default (`grant_type` `refresh_token`) | `"grant_type": "client_credentials"` in the token file |

Way A is the default. Its interactive sign-in is a deliberate control: when the
refresh token stops working, a person has to confirm access again. Way B suits
unattended relays where that is not wanted; access is then bounded by the
lifetime of the certificate or client secret and by the mailbox permissions in
Exchange Online. Both can coexist on one host, each with its own token file.

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

> [!WARNING]
> When using Microsoft's HVE endpoint (smtp-hve.office365.com), set
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
$ sudo -u postfix sasl-xoauth2-tool get-token outlook \
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
$ sudo -u postfix sasl-xoauth2-tool get-token outlook \
    /etc/tokens/relay@contoso.com \
    --client-id=APPLICATION_ID \
    --tenant=TENANT_ID \
    --use-device-flow
To sign in, use a web browser to open the page https://www.microsoft.com/link and enter the code REDACTED to authenticate.
Acquired token.
Wrote token to /etc/tokens/relay@contoso.com.
```

(`sudo -u postfix` creates the file as the Postfix user, in the directory
prepared as in [A Note on Token File
Permissions](#a-note-on-token-file-permissions).)

Open the page in any browser (it does not have to be on this host), enter the
code, sign in as the mailbox user and accept the prompts. Omit `--tenant` for
personal accounts (it defaults to `consumers`), and add `--cloud` for national
clouds. The device flow needs the Python `msal` module.

If you ran the tool as another user (e.g. root), give the token file to the
Postfix user afterwards (see [A Note on Token File
Permissions](#a-note-on-token-file-permissions)).

##### A4. Test

```
$ sudo -u postfix sasl-xoauth2-tool test-token-refresh /etc/tokens/relay@contoso.com
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
$ sudo -u postfix sasl-xoauth2-tool get-token outlook \
    /etc/tokens/relay@contoso.com \
    --client-id=APPLICATION_ID \
    --tenant=TENANT_ID \
    --use-device-flow \
    --overwrite-existing-token
```

The file is replaced atomically, keeping its permissions. Postfix needs no
restart: the token file is read for every authentication.

##### A6. Monitoring

Set up the [daily token refresh](#daily-token-refresh). It requests and stores
a new token once a day, which keeps the refresh token alive (Microsoft lets an
unused refresh token expire after 90 days; each refresh issues a new one), and
it fails with exit status 2 and the reason when the refresh token no longer
works (`invalid_grant`), or 1 for transient problems.

Without it, only Postfix's own token refreshes (which happen when mail is sent)
extend the life of the stored refresh token. `sasl-xoauth2-tool
test-token-refresh` only checks a token file and does not modify it, so it
does not keep the refresh token alive.

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
$ sudo -u postfix sasl-xoauth2-tool get-token outlook \
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
token is about to expire, sasl-xoauth2 requests a new one for the
application. The mailbox itself is unchanged. All steps are done by
administrators.

The application authenticates with either of:

- **A certificate (recommended).** sasl-xoauth2 signs a short-lived client
  assertion with the certificate's private key for every token request
  ([certificate
  credentials](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials)).
  The private key never leaves the host; only the certificate (public key) is
  uploaded to Entra ID. Each assertion is bound to the token endpoint and
  valid for 5 minutes, so an intercepted one is of no use elsewhere, and the
  certificate's validity can be chosen freely. Microsoft recommends
  certificates over secrets for this flow.
- **A client secret.** Simpler to set up, but the secret itself is sent with
  every token request, and Entra ID secrets expire after at most 24 months.

##### B1. Register the Application

Use a separate application from Way A (that one is a public client without
credentials). In the Microsoft Entra admin center:

1. [Register an
   application](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app)
   for "Accounts in this organizational directory only". No redirect URI or
   platform configuration is needed, and "Allow public client flows" stays
   "no".
1. Add a credential under "Certificates & secrets":
   - **Certificate (recommended):** create a key pair and a self-signed
     certificate on the Postfix host, as the Postfix user, so that the
     private key is readable only by it:

     ```
     $ sudo -u postfix openssl req -x509 -newkey rsa:3072 -sha256 -days 730 -nodes \
         -subj "/CN=sasl-xoauth2 relay@contoso.com" \
         -keyout /etc/tokens/relay-app.key -out /etc/tokens/relay-app.crt
     $ sudo chmod 600 /etc/tokens/relay-app.key
     ```

     Upload `relay-app.crt` (never the `.key`) under "Certificates" → "Upload
     certificate", and note its expiry date. Only RSA keys are supported
     (the assertion is signed with PS256), and the key file must not be
     protected with a passphrase, as Postfix needs to use it unattended.
   - **Client secret:** create a new client secret under "Client secrets".
     Copy its *value* (it is shown only once) and note its expiry date.
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

With a **certificate**:

```shell
$ sudo -u postfix sasl-xoauth2-tool get-token outlook \
    /etc/tokens/relay@contoso.com \
    --client-credentials \
    --tenant=TENANT_ID \
    --client-id=APPLICATION_ID \
    --certificate=/etc/tokens/relay-app.crt \
    --private-key=/etc/tokens/relay-app.key \
    --mailbox=relay@contoso.com
Wrote token to /etc/tokens/relay@contoso.com.
Requesting a token with the certificate to check the setup:
Config check passed.
Token refresh succeeded.
```

The tool writes the token file and then requests a token through the plugin's
own code, so a success here means the setup works. (`--private-key` can be left
out if the key is in the certificate file.)

With a **client secret**:

```shell
$ sudo -u postfix sasl-xoauth2-tool get-token outlook \
    /etc/tokens/relay@contoso.com \
    --client-credentials \
    --tenant=TENANT_ID \
    --client-id=APPLICATION_ID \
    --mailbox=relay@contoso.com
Please enter OAuth2 client secret:
Acquired app-only token.
Wrote token to /etc/tokens/relay@contoso.com.
```

(The secret can also be passed with `--client-secret`, but then it ends up in
the shell history and is visible in `ps`.) Add `--cloud` for national clouds.

The resulting file contains everything needed to request new tokens, and is
created readable by its owner only. With a certificate:

```json
{
    "grant_type": "client_credentials",
    "scope": "https://outlook.office365.com/.default",
    "token_endpoint": "https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/token",
    "client_id": "APPLICATION_ID",
    "client_certificate_file": "/etc/tokens/relay-app.crt",
    "client_private_key_file": "/etc/tokens/relay-app.key",
    "user": "relay@contoso.com",
    "access_token": "...",
    "expiry": "..."
}
```

With a secret, `client_secret` takes the place of the two certificate fields.
If both are present, the certificate is used.

The file may also be written by hand: `access_token` and `expiry` can be left
out, and a token is then requested on first use. `user` is the mailbox to send
as; it may be left out if the user name in `sasl_passwd` already is the mailbox
address. Paths are used as they are, so with a chrooted `smtp` service they
must be valid inside the chroot (and the files must be there). `get-token`
writes the paths as given on the host (e.g. `/var/spool/postfix/etc/tokens/...`);
with chroot, change `client_certificate_file` and `client_private_key_file` in
the token file to the paths inside the chroot (e.g.
`/etc/tokens/relay-app.crt`) afterwards. (`test-token-refresh` and
`refresh-token` run outside the chroot and therefore cannot check such a file;
check it by sending a test mail.)

`/etc/sasl-xoauth2.conf` must still exist with a `client_id` (it may hold Way
A's values); the values in the token file take precedence. Alternatively,
`grant_type`, `scope`, `client_certificate_file` and `client_private_key_file`
may be set in `/etc/sasl-xoauth2.conf` to apply to all token files.

To switch a token file between certificate and secret, run the respective
`get-token` command with `--overwrite-existing-token`; the settings of the
other variant are removed. To switch a token file back to Way A, run the Way A
`get-token` command with `--overwrite-existing-token`; the tool then removes
the client credentials settings from the file.

##### B4. Test and Switch Over

```
$ sudo -u postfix sasl-xoauth2-tool test-token-refresh /etc/tokens/relay@contoso.com
Config check passed.
Token refresh succeeded.
```

If the mailbox previously used Way A, write the new token file under a
different name first, test it, then point `/etc/postfix/sasl_passwd` at it and
run `sudo postmap /etc/postfix/sasl_passwd` and `sudo postfix reload`. Keep the old token
file until you are sure; switching back is just a matter of changing the path
again.

##### B5. Renewing the Certificate or Rotating the Client Secret

Before the credential expires, add the new one in Entra ID first, so that the
old and the new one are valid at the same time:

- **Certificate:** create a new key pair and certificate as in B1 (under new
  file names), upload the new certificate, run the B3 certificate command with
  the new files and `--overwrite-existing-token`, and then delete the old
  certificate in Entra ID and the old files.
- **Client secret:** create a new secret, run the B3 secret command with
  `--overwrite-existing-token` and enter the new secret, and then delete the
  old secret.

An expired credential makes token requests fail with `invalid_client`.

##### B6. Monitoring

The [daily token refresh](#daily-token-refresh) works as for Way A and reports
an expired or deleted credential, or an unreadable key (exit status 2). Also
keep track of the expiry date of the certificate or secret. Unlike Way A,
access does not lapse when no mail is sent.

#### Shared Mailboxes

To send as a [shared
mailbox](https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth#sasl-xoauth2-authentication-for-shared-mailboxes-in-office-365),
authenticate with the token of an account that has access to it, but name
the shared mailbox in XOAUTH2's `user` field. With sasl-xoauth2, set `user` in
the token file to the shared mailbox's address (or use that address as the user
name in `/etc/postfix/sasl_passwd`):

- **Way A:** obtain the token as a user who has `FullAccess` to the shared
  mailbox (and `SendAs` for its address), then add `"user":
  "shared@contoso.com"` to the token file (or pass `--mailbox
  shared@contoso.com` to `get-token`).
- **Way B:** grant the application's service principal access to the shared
  mailbox (B2, with the shared mailbox as `-Identity`), and use `--mailbox
  shared@contoso.com`.

SMTP AUTH must be enabled for the mailbox named in `user` (see [Common
Prerequisites](#common-prerequisites)).

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
| `invalid_client`, AADSTS700027 | Way B with a certificate: the certificate is not (or no longer) registered for the application, or has expired. Upload it again (B1). |
| `client certificate: ...` (no request sent) | Way B: the certificate or key file cannot be read by the Postfix user, is not PEM, the key is not RSA, is protected with a passphrase, or does not belong to the certificate. |
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
- [Microsoft identity platform application authentication certificate credentials](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials)
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

For supported proxy schemes please refer to the [curl library documentation](https://curl.se/libcurl/c/CURLOPT_PROXY.html).
Proxy environment variables (`https_proxy` etc.) have no effect: Postfix does
not pass them to its delivery processes (and `sasl-xoauth2-tool test-config`,
`test-token-refresh` and `refresh-token` ignore them as well, so that their
tests match; `get-token` does use them). Only the token requests use the proxy;
the SMTP connection itself is made by Postfix.

### Testing Your Configuration

sasl-xoauth2 provides a tool, `sasl-xoauth2-tool`, that allows the
semi-interative testing of configuration and token files (which is a lot more
useful than parsing log files when trying to figure out why Postfix isn't
delivering mail correctly). Run it as the Postfix user, so that it also checks
that Postfix can read the configuration and token files and write to the token
directory.

First, test your configuration file:

```
$ sudo -u postfix sasl-xoauth2-tool test-config --config-file ./bad-config.conf
sasl-xoauth2: Missing required value: client_id
Config check failed.
$ sudo -u postfix sasl-xoauth2-tool test-config
Config check passed.
```

(Specifying the path is only required if your configuration file isn't located
in the system-default path; it must be readable for the Postfix user, so not,
for example, in your home directory.)

Next, test your token file:

```
$ sudo -u postfix sasl-xoauth2-tool test-token-refresh ./bad-token.json
Config check passed.
auth failed (sasl-xoauth2 0.29):
  2026-10-20 09:18:59: TokenStore::Read: file=./bad-token.json
  2026-10-20 09:18:59: TokenStore::Read: grant_type=refresh_token, refresh=<redacted, 103 bytes>, access=<redacted, 215 bytes>, user=
  2026-10-20 09:18:59: TokenStore::Refresh: attempt 1
  2026-10-20 09:18:59: TokenStore::Refresh: token_endpoint: https://accounts.google.com/o/oauth2/token
  2026-10-20 09:18:59: TokenStore::Refresh: request: grant_type=refresh_token, client_id=REDACTED, client_secret=<redacted, 35 bytes>, refresh_token=<redacted, 103 bytes>, scope=<not sent>
  2026-10-20 09:19:00: TokenStore::Refresh: code=400, response={\x0a  "error": "invalid_grant",\x0a  "error_description": "Bad Request"\x0a}
  2026-10-20 09:19:00: token request for ./bad-token.json to https://accounts.google.com/o/oauth2/token failed: HTTP 400 invalid_grant: Bad Request; hint: the refresh token was rejected (expired, revoked, or issued for a different client/tenant/scope); obtain a new one with 'sasl-xoauth2-tool get-token'
Token refresh failed.
$ echo $?
2
$ sudo -u postfix sasl-xoauth2-tool test-token-refresh ./good-token.json
Config check passed.
Token refresh succeeded.
```

(Again, you'll have to specify your configuration file with
`--config-file <config file>` if it isn't located at the system-default path.)
The token file is not modified. The exit status tells what kind of problem was
found:

| Exit status | Meaning |
|---|---|
| 0 | The configuration is valid, a token was obtained, and the token directory is writable. |
| 1 | Transient failure, e.g. the token endpoint could not be reached or answered with HTTP 429 or 5xx. Retry later. |
| 2 | Failure that needs action, e.g. an invalid configuration, an unreadable token file, a rejected refresh token, secret or certificate, or a token directory the user cannot write to. |

`sasl-xoauth2-tool --version` (or `-v`, `-V`) prints the versions of the tool,
of its `test-config` helper and of the installed plugin, with their paths, and
exits with status 1 if they differ or a component is missing -- typically a
sign of an older installation that is still in use (see [Removing Older
Installations](#removing-older-installations)):

```
$ sasl-xoauth2-tool --version
sasl-xoauth2-tool 0.29 (/usr/bin/sasl-xoauth2-tool)
test-config       0.29 (/usr/lib/x86_64-linux-gnu/sasl-xoauth2/test-config)
plugin            0.29 (/usr/lib/x86_64-linux-gnu/sasl2/libsasl-xoauth2.so)
configuration     /etc/sasl-xoauth2.conf
```

Plugins older than 0.29 show up as `unknown (older than 0.29)`. The plugin
also names its version in every failure message in the mail log.

### Restart Postfix

```
$ sudo systemctl restart postfix
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

The token file may also set `grant_type`, `scope`, `client_certificate_file`,
`client_private_key_file`, `proxy`, `ca_bundle_file`, `ca_certs_dir` and
`refresh_window` (see `sasl-xoauth2.conf(5)`).

A token file that sets a different `token_endpoint`, `proxy`, `ca_bundle_file`
or `ca_certs_dir` than `/etc/sasl-xoauth2.conf` must also set its own
`client_secret` (empty for public clients) or use a certificate: sasl-xoauth2
does not send the client secret from the configuration file anywhere else
than the configuration says.

## Running in Production

### Checklist

- **Verified TLS** to the relay: `smtp_tls_security_level = secure` (or a
  `secure` TLS policy for the relay); see [Configure Mail
  Agent](#configure-mail-agent).
- **Permissions:** `/etc/sasl-xoauth2.conf` `root:postfix` `0640`; token
  directory owned by `postfix`, `0700`; token files and private keys `0600`.
  See [A Note on Token File Permissions](#a-note-on-token-file-permissions).
- **Ubuntu 26.04:** the `ReadWritePaths=-/etc/tokens` drop-in for Postfix, and
  the check that Postfix can write there; see [A Note on Ubuntu
  26.04](#a-note-on-ubuntu-2604).
- **Daily token refresh** (systemd timer or cron); see [Daily Token
  Refresh](#daily-token-refresh).
- **Monitoring** of the refresh, the mail log and the mail queue; see
  [Monitoring](#monitoring).
- For Way B, a **certificate** rather than a client secret, and a reminder for
  its expiry date.
- The Postfix settings below left at their defaults.

### Postfix Settings That Matter

sasl-xoauth2 reports every failure (an unreachable token endpoint, a rejected
token, a broken token file) to Postfix as an authentication failure, and
Postfix then *defers* the mail: it stays in the queue and is retried. Some
settings change that:

- `smtp_sasl_auth_soft_bounce = yes` (the default) makes Postfix defer mail
  when the server rejects authentication. Keep it.
- Do not enable `smtp_sasl_auth_cache_name`. It remembers a rejected
  "password" for `smtp_sasl_auth_cache_time` (90 days by default). With
  sasl-xoauth2, the "password" is the path to the token file, which does not
  change when the token is fixed, so the cached failure would keep blocking
  delivery.
- Deferred mail is returned to the sender after `maximal_queue_lifetime` (5
  days by default). Fix authentication problems within that time.
- After an authentication failure, Postfix treats the relay as unavailable for
  a while ("delivery temporarily suspended"), for all mail that goes through
  it. If several mailboxes share one relay and should not affect each other,
  give each its own transport (see `sender_dependent_default_transport_maps`
  in the Postfix documentation).

Token requests time out after 10 seconds (connect) or 30 seconds (total). A
delivery process waits up to 45 seconds for another process that is already
requesting a token for the same file, so authentication can take up to about
75 seconds when the token endpoint is slow; with a healthy endpoint, many
parallel deliveries share a single token request.

### Monitoring

- **Token files:** the [daily token refresh](#daily-token-refresh) fails when
  a token can no longer be obtained or stored; alert on a failed
  `sasl-xoauth2-refresh.service` (e.g. `systemctl --failed`, or an
  `OnFailure=` unit that notifies you).
- **Logs:** alert on `[sasl-xoauth2] auth failed` and on `[sasl-xoauth2]
  unable to update token file` in the mail log. The plugin logs through
  Postfix's syslog connection; if Postfix writes its own log file
  (`maillog_file`), look for the plugin's messages in the system log
  (`journalctl`) instead.
- **Queue:** alert on deferred mail (e.g. `postqueue -j`, or the number of
  files in `/var/spool/postfix/deferred`).

### Daily Token Refresh

`sasl-xoauth2-tool refresh-token` requests a new token for each token file
given and stores it, under the same lock the plugin uses, even if the current
token is still valid. Run once a day, it

- keeps refresh tokens alive that expire when unused (Microsoft: after 90
  days; each refresh issues a new one, which is stored), also when no mail is
  sent;
- checks the whole setup under real conditions -- credentials, token
  endpoint, file permissions -- and fails with exit status 2 (needs action) or
  1 (transient) and the reason, like `test-token-refresh`.

Token files keep their owner and permissions, also if it runs as root. A
systemd timer, with the same file system restrictions as Postfix on Ubuntu
26.04:

```
# /etc/systemd/system/sasl-xoauth2-refresh.service
[Unit]
Description=Refresh sasl-xoauth2 OAuth tokens
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=postfix
Group=postfix
ExecStart=/usr/bin/sasl-xoauth2-tool refresh-token /etc/tokens/relay@contoso.com
ProtectSystem=full
ReadWritePaths=-/etc/tokens
PrivateTmp=yes
NoNewPrivileges=yes
```

```
# /etc/systemd/system/sasl-xoauth2-refresh.timer
[Unit]
Description=Daily refresh of sasl-xoauth2 OAuth tokens

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
```

List all token files in `ExecStart` (the exit status is the highest of
all). Then enable the timer and run the refresh once by hand:

```
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now sasl-xoauth2-refresh.timer
$ sudo systemctl start sasl-xoauth2-refresh.service
$ journalctl -u sasl-xoauth2-refresh.service
... Token refresh succeeded; token file updated.
```

Alternatively, with cron (e.g. `/etc/cron.d/sasl-xoauth2`):

```
17 6 * * * postfix /usr/bin/sasl-xoauth2-tool refresh-token /etc/tokens/relay@contoso.com >/dev/null 2>&1 || logger -p mail.err -t sasl-xoauth2-refresh "token refresh failed (exit status $?)"
```

With a chrooted `smtp` service, use the token file paths below
`/var/spool/postfix` (and `ReadWritePaths` is not needed).

### Backups

Token files, private keys and `/etc/sasl-xoauth2.conf` contain credentials.
Back them up only to storage that is at least as well protected (encrypted,
restricted access). For Way A, a restored older token file may still work, as
Microsoft and Google do not revoke a refresh token when they issue a new one;
if it does not, sign in again. For Way B, a new certificate or secret can
always be created instead of restoring one.

## Debugging

### Logging Options

sasl-xoauth2 collects a trace of each authentication and, depending on these
settings in `/etc/sasl-xoauth2.conf`, writes it to syslog, prefixed
`[sasl-xoauth2]` (within Postfix, under Postfix's syslog facility, normally
`mail`):

| Setting | Default | Effect |
|---|---|---|
| `log_to_syslog_on_failure` | `yes` | When authentication fails, log one line with the reason: which token file, which endpoint, the provider's error (e.g. HTTP status and AADSTS code) and a hint (followed by a note on how to see the full trace). `no` disables all logging on failure. |
| `log_full_trace_on_failure` | `no` | When authentication fails, log the whole trace instead of only that line. |
| `always_log_to_syslog` | `no` | Log every trace line immediately, also for successful authentications. |

Tokens and secrets are always redacted; user names, token file paths, token
endpoints and the provider's error responses are logged (with control
characters escaped and long responses cut, so they cannot forge or flood log
lines). Every failure message names the plugin version, e.g. `[sasl-xoauth2]
auth failed (sasl-xoauth2 0.29): token request for /etc/tokens/relay@contoso.com
to https://login.microsoftonline.com/... failed: HTTP 400 invalid_grant: ...`.
Independently of these settings, sasl-xoauth2 logs an error when it obtained a
new token but could not store it in the token file. The recommended
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
`cmake --install` put libsasl-xoauth2.so in the wrong directory (see the
installation paths under [Building from Source](#building-from-source)).
