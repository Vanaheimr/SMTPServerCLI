# SMTPServerCLI

A **ready-to-run, self-contained SMTP server** built on the
[Vanaheimr Hermod](https://github.com/Vanaheimr/Hermod) mail stack, with a
command line to run it from. This project is the thin runnable *instance*: the
wiring, the defaults, the crypto material and the prompt. It is meant to be
deployed on a real server straight from this git repository. The protocol engine
lives in Hermod and is documented there and in this repository:

- **[`libs/Hermod/Hermod/SMTP/README.md`](../libs/Hermod/Hermod/SMTP/README.md)**:
  the per-RFC support reference. It says what is implemented and how it was
  validated.
- **[`README.md`](../README.md)** at the root of this repository: the
  operational guide. It covers the architecture, the configuration, the
  **DNS setup guide**, deployment, API examples and the known limitations.

This README covers only what is specific to the CLI.

## Design: everything in the repository, nothing in the environment

- **Defaults are code.** Every setting is a strongly-typed constant in
  [`Configuration.cs`](Configuration.cs). This includes the hostname, ports,
  local domains, DKIM domain and selector, reporting flags, smarthost, rate
  limits and queue tuning. To change a default for good, edit that file and
  rebuild. There are **no** environment variables to set.
- **Switches change one start.** The settings that are commonly changed for a
  single run have a switch: identity, ports, certificate, DKIM, smarthost,
  folders and the console log. A switch overrides the default for that start and
  is written nowhere. `-h` lists them.
- **Crypto is generated into the repo.** On the first start the server writes a
  self-signed TLS certificate and a DKIM key pair into the git-tracked
  [`config/`](config/) folder. You can commit them, so that a fresh clone keeps
  the same DKIM key and its published DNS record stays valid. See
  [`config/README.md`](config/README.md).

## Getting it

```sh
git clone --recurse-submodules git@github.com:Vanaheimr/SMTPServerCLI.git
```

In an existing clone without the libraries:

```sh
git submodule update --init --recursive
```

You need the .NET 10 SDK.

## Building and running

From the repository root:

```sh
dotnet run --project SMTPServerCLI
```

Or build once with `./updateAndBuild.sh` and then start with `./run.sh`. Both
scripts accept the same switches.

On the first start the server generates `config/server.pfx` and
`config/dkim_default.*`. It also creates one account, `admin`, with a random
password. Then it prints the banner and starts listening. The banner shows where
the server answers, the commit each assembly was built from, its folders,
certificate, DKIM selector and outbound route. A box below the banner lists what
needs attention before the server is exposed to the Internet, including the
`admin` password. That password is shown **this once**.

The default ports are the non-privileged **2525 / 2587 / 2465**, so the server
runs anywhere without root.

A typical start for a real domain:

```sh
dotnet run --project SMTPServerCLI -- --hostname mail.example.org --local-domain example.org
```

### Switches

| Switch | What it does |
|--------|--------------|
| `--hostname <name>` | The public hostname, used in the banner, EHLO and `Received` headers. It is also the DKIM and report domain unless those are set separately. Default: `Configuration.Hostname` (`localhost`). |
| `--local-domain <domain>` | A domain whose mail is stored here. Mail for any other domain is relayed, for authenticated accounts only. Can be given several times and replaces the configured list. `localhost` is always local. |
| `--port`, `--submission-port`, `--implicit-tls-port <number>` | The MTA, submission and SMTPS ports. Defaults: 2525 / 2587 / 2465. On the Internet these are 25 / 587 / 465. |
| `--certificate <file.pfx>`, `--certificate-password <pw>` | Use a real certificate (PKCS#12) instead of the generated self-signed one. |
| `--require-starttls` | Refuse `MAIL FROM` on the MTA port until STARTTLS has been negotiated. |
| `--dkim-domain <domain>`, `--dkim-selector <selector>` | The DKIM `d=` and `s=` values. A selector without a key yet gets a newly generated key pair. |
| `--smarthost <host[:port]>`, `--smarthost-user <name>`, `--smarthost-password <pw>` | Relay all outgoing mail through this server instead of each recipient domain's MX. Use this where outbound port 25 is blocked. |
| `--ssh-port <number>` | The port the command line is served on over SSH. Default: 22525. |
| `--ssh-any` | Serve SSH on every address instead of the loopback only. |
| `--no-ssh` | Do not serve the command line over SSH. |
| `--authorize-ssh-key <account>=<file.pub>` | Let an account in over SSH with the public key in the file: an OpenSSH `.pub`, or what PuTTYgen saves. Can be given several times. |
| `--config <dir>`, `--mailstore <dir>` | Override where the crypto material and the runtime data live. |
| `--verbose`, `--quiet`, `--log-level <level>` | How much of the log the console shows: `debug`, `info` (the default), `warning`, `error` or `off`. |
| `--version` | Print the commit each assembly was built from, then exit. |

Exit codes: 0 after a requested stop, 1 when the server could not start (for
example, a port is already in use), 2 when the switches were invalid.

## Typing at it

Once the server is up, the console shows a prompt (`smtp@<hostname>> `). The
log scrolls past above the prompt without breaking the line being typed.

- **Tab** completes commands and their arguments: subcommands, account names,
  queue ids and stored messages.
- **Up/Down** step through the history.
- `quit`, **Ctrl+C** or a service manager's SIGTERM stop the server. Ctrl+C
  also cancels a command that is still running.

The server stops accepting connections, lets running sessions finish and leaves
the outbound queue on disk for the next start.

| Command | What it does |
|---------|--------------|
| `help` | Lists the commands. |
| `status` | Shows uptime, the outbound queue (pending / deferred / in delivery / failed / delivered), the number of stored messages, the accounts and the log level. |
| `config` | Prints the banner again: ports, build, folders, certificate, DKIM, outbound route and reporting. |
| `user [list]` | Lists the accounts and the SASL mechanisms each can use. Accounts with a well-known password are flagged. |
| `user add <name> [<password>]` | Adds an account. Without a password, one is generated and shown once. |
| `user passwd <name> [<password>]` | Gives an account a new password. Without a password, one is generated and shown once. |
| `user remove <name>` | Removes an account. |
| `queue [list]` | Lists what waits to go out, including deferred mail, with its next attempt and last error. |
| `queue failed` | Lists what gave up (the newest 50). |
| `queue show <id>` | Shows one queue entry in full: envelope, subject, attempts, remote MX and its last answer. Tab completes the id, and a unique prefix is enough. |
| `queue flush` | Retries everything that is deferred, now. |
| `queue remove <id>` | Drops a pending entry. No bounce is sent. |
| `mailbox [list [<count>]]` | Shows the newest received messages (default 20). Each line has the envelope, subject and the SPF/DKIM/DMARC results. |
| `mailbox show <message>` | Prints a stored message (up to 200 lines). |
| `mailbox delete <message>` | Deletes a stored message. |
| `dns [records]` | Prints the DNS records this server needs: MX, A/AAAA, PTR, SPF, DKIM, DMARC, TLS-RPT, and DANE/TLSA when the certificate is a real one. The DKIM record is computed from the key the server actually signs with and is split into 255-character strings. |
| `dns check` | Looks those records up through the server's own resolver and reports which are missing. It also checks whether the published DKIM key matches the server's key. |
| `testmail <to> [<from>]` | Queues a short DKIM-signed test message to an external address. Read SPF, DKIM and DMARC from the recipient's "show original". |
| `log [debug\|info\|warning\|error\|off]` | Shows or changes how much of the log the console shows. In an SSH session it changes only that session's log. |
| `who` | Lists who is signed in over SSH: account, address, key and since when. |
| `history`, `quit` / `exit` | From Styx's command line. |

When the server runs under systemd, from a script, or with its output
redirected, there is no prompt. It simply runs until SIGTERM, and the console
shows only the log. The command line is then reached over SSH.

## Typing at it over SSH

The same command line is served over SSH, on `127.0.0.1:22525` by default.
This is how you reach it on a server started by systemd, which has no console.
You get the same commands, Tab completion, history and log above the line being
typed. `quit`, `exit` or Ctrl+D end the session; the server keeps running.

Only the command line is served: no shell of the machine, no files, no tunnels.
Sign-in is by **public key only**. The SSH accounts are separate from the SMTP
accounts in `users.txt`: an SMTP account may send mail, an SSH account may run
the server. That way the password of a mail client is never a way into the
console.

To let yourself in, start once with your public key:

```sh
dotnet run --project SMTPServerCLI -- --authorize-ssh-key alice=path/to/id_ed25519.pub
```

The key is written to `config/ssh/authorized/alice`, a file in OpenSSH's
`authorized_keys` format, and stays there for later starts. You can also edit
that file by hand; it is read again at every sign-in. Options such as `from=`,
`no-pty` and `expiry-time=` are honoured; a line with an option the server
cannot enforce is refused rather than half-honoured.

Then connect:

```sh
ssh -p 22525 alice@localhost
```

From another machine, use a tunnel (`ssh -L 22525:127.0.0.1:22525 you@mail.example.com`)
or start with `--ssh-any`. The first connection shows the server's host key;
compare it with the fingerprint in the banner (`SSH` line). The host key is
generated on the first start and kept in `config/ssh/ssh_host_ed25519_key`.

Each session has its own log level (`log`), and the server's log names who did
what: `'alice' over SSH from 127.0.0.1:51682 added the account 'bob'.` Sign-ins,
failed attempts and refused requests are logged as well. With no account
having a key, SSH listens and lets nobody in.

### Adding a command

A command is one file in [`CLI/CLICommands/`](CLI/CLICommands/), and nothing
needs to be registered. Any class in this assembly that implements Styx's
`ICLICommand` and has a constructor taking an `SMTPCLI` is found and registered
automatically. Through `cli.Server` (an [`SMTPServerInstance`](SMTPServerInstance.cs))
a command can reach the settings, the queue, the accounts, the DNS client and the
log. [`LogCommand.cs`](CLI/CLICommands/LogCommand.cs) is the smallest example.

## Folders

When run from a checkout, both folders are next to this project, regardless of
the directory you start from. A published server uses the current directory
instead. `--config` and `--mailstore` override either location.

| Folder | Contents | Committed? |
|--------|----------|------------|
| [`config/`](config/) | TLS certificate, DKIM keys and SSH host key, generated on the first start, and the public keys of the SSH accounts (`config/ssh/authorized/`). | Tracked. Commit the keys if you want them to stay stable. |
| `mailstore/` | Received `.eml` files, the outbound queue (`queue/pending`, `queue/failed`, `queue/delivered`), `users.txt` and the reporting state. | **Git-ignored**: runtime data, including credential hashes. |

## User accounts

Accounts live in `mailstore/users.txt`. Each line has a SHA-256 password hash
for PLAIN/LOGIN, SCRAM-SHA-256 credentials, and optional client-certificate
thumbprints for SASL `EXTERNAL`. The server re-reads the file whenever it
changes, so the `user` command takes effect at the next AUTH without a restart.

On the first start the CLI writes the file itself, with the single account
`admin` and a random password. Without this step, Hermod would write a file
without any accounts, and nobody could submit or relay. An existing file is left
alone. Older Hermod versions wrote demo accounts with published passwords
(`admin` / `user` = `test123`, `demo` = `demo`) into it; accounts that still
have one of those passwords are flagged in the banner and by `user list`.

A client certificate authenticates an account only if its **thumbprint**
(SHA-1 or SHA-256) is listed for that account. The CLI checks this with
[`PinnedCertificateUserStore`](PinnedCertificateUserStore.cs), which reads the
thumbprints the same way `user list` shows them; Hermod's own store does the
same since Hermod #104. (`AUTH EXTERNAL` is not usable yet anyway, because the
server does not request a client certificate. See the limitations in the
[operational guide](../README.md#production-readiness--limitations).)

Generated passwords are the safer choice. A password typed after `user add` or
`user passwd` stays in the command line's history until the server stops.

## Running on a real Internet server

1. **Set its identity.** Either start with `--hostname mail.example.com
   --local-domain example.com --port 25 --submission-port 587
   --implicit-tls-port 465`, or set the same values in `Configuration.cs` and
   rebuild.
2. **Bind the privileged ports.** Ports 25, 587 and 465 need elevated
   privileges. Either give the binary a capability (`AmbientCapabilities=` in
   the unit below, or `setcap 'cap_net_bind_service=+ep'` on the published
   binary), or put a port-forward in front of the default ports.
3. **Use a real TLS certificate** for the MX hostname, for example from Let's
   Encrypt, exported as PKCS#12. Pass it with `--certificate` and
   `--certificate-password`, or replace `config/server.pfx`.
4. **Publish DNS.** `dns` prints the records for this server, and `dns check`
   confirms they are published. The background on each record is in the
   [DNS setup guide](../README.md#dns-setup-guide).
5. **Use a static IP with a matching PTR** (FCrDNS). Open the firewall for ports
   25/587/465 inbound and 25 outbound, or use `--smarthost`. Make sure the IP is
   not on a blocklist.
6. **Test it.** Send a message with `testmail you@gmail.com` and check
   *Show original*.
7. **Run it as a service** (systemd example):

   ```ini
   [Unit]
   Description=Hermod SMTP server
   After=network-online.target

   [Service]
   WorkingDirectory=/opt/hermod-smtp        # config/ and mailstore/ live here
   ExecStart=/usr/bin/dotnet /opt/hermod-smtp/SMTPServerCLI.dll --hostname mail.example.com --local-domain example.com --port 25 --submission-port 587 --implicit-tls-port 465
   Restart=on-failure
   AmbientCapabilities=CAP_NET_BIND_SERVICE  # to bind 25/587/465

   [Install]
   WantedBy=multi-user.target
   ```

   Under systemd there is no prompt. The server logs to the journal and stops
   on SIGTERM. Its command line is reached with `ssh -p 22525 <account>@localhost`
   on the machine; see [Typing at it over SSH](#typing-at-it-over-ssh).

## Tests and CI

```sh
dotnet test SMTPServerCLITests
```

[`SMTPServerCLITests/`](../SMTPServerCLITests/) covers the switches, `users.txt`
and the certificate lookup, the SSH accounts, and the server itself: started on
free ports in a temporary folder, sent a message over SMTP, typed at through
its commands and Tab completion, and signed in to over SSH with Hermod's own
client. Nothing in it depends on name servers elsewhere.

[CI](../.github/workflows/ci.yml) builds the whole solution and runs these tests
on Windows and Debian 13, for every push and pull request. On Debian it also
starts the program the way systemd does: no terminal, output into a file. It
then checks that both SMTP ports greet with `220`, that SSH answers, and that
SIGTERM stops the server with exit code 0.

## Status

This is an RFC-conformant reference implementation, **not** a hardened
production MX. It has no anti-spam or abuse layer, accepts any recipient at a
local domain (catch-all), and has not been security-audited. Before exposing it
to untrusted mail, read the
[production-readiness section](../README.md#production-readiness--limitations).

## License

Apache License 2.0. See [`LICENSE`](../LICENSE).
