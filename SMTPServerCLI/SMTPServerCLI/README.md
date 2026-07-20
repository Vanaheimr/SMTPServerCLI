# Hermod SMTP Server — CLI

A **ready-to-run, self-contained SMTP server** built on the
[Vanaheimr Hermod](https://github.com/Vanaheimr/Hermod) mail stack. This project is the thin runnable
*instance* — wiring, configuration, and crypto material — meant to be deployed on a real server
straight from this git repository. The protocol engine (ESMTP, STARTTLS, SASL, SPF/DKIM/DMARC/ARC,
MTA-STS/DANE/TLS-RPT, DSN/MDN, OpenPGP) lives in Hermod and is documented there:

- **[SMTP_SUPPORT.md](../../libs/Hermod/SMTP_SUPPORT.md)** — the per-RFC support reference (what is
  implemented and how it was validated).
- **[docs/SMTP-Server.md](../../docs/SMTP-Server.md)** — the operational guide (architecture, the
  full configuration reference, the **DNS setup guide**, deployment, and API examples).

This README only covers what is specific to *this* CLI project.

## Design: everything in the repository, nothing in the environment

The guiding principle is **no fiddling with environment variables on the host**. Everything the
server needs lives in the repository:

- **Configuration is code.** All settings — hostname, ports, local domains, DKIM domain/selector,
  verification and reporting flags, smarthost, rate limits — are strongly-typed constants in
  [`Configuration.cs`](Configuration.cs). To reconfigure, edit that file and rebuild. There are **no**
  environment variables to set.
- **Crypto is generated into the repo.** On first run the server writes a self-signed TLS certificate
  and a DKIM key pair into the git-tracked [`config/`](config/) folder. You can then commit them so a
  fresh clone keeps the same DKIM key (and its published DNS record stays valid). See
  [`config/README.md`](config/README.md).

## Quick start

```sh
git submodule update --init --depth 1 libs/Hermod libs/Styx
cd SMTPServerCLI/SMTPServerCLI
dotnet run
```

On first run it generates `config/server.pfx` and `config/dkim_default.*`, prints the effective
configuration, and starts listening. The default ports are the non-privileged **2525 / 2587 / 2465**,
so it runs anywhere without root.

> The `config/` and `mailstore/` folders are resolved relative to the **current working directory**,
> so run from the project directory (as above) in development, or from the published folder in
> production — the crypto and data folders sit next to the app in both cases.

## Configuration

Open [`Configuration.cs`](Configuration.cs) — it is the single source of truth, grouped and commented:

| Setting | Default | Notes |
|---------|---------|-------|
| `Hostname` | `localhost` | Banner / EHLO / Received / default DKIM & report domain |
| `Port` / `SubmissionPort` / `ImplicitTlsPort` | `2525` / `2587` / `2465` | **Production: 25 / 587 / 465** (needs privileges — see below) |
| `LocalDomains` | `["localhost"]` | Mail to these is delivered locally; everything else is authenticated relay |
| `RequireAuthForRelay` | `true` | **Keep true** — prevents an open relay |
| `VerifyDkim` / `VerifySpf` / `VerifyDmarc` | `true` | Inbound authentication checks |
| `DkimDomain` / `DkimSelector` | `Hostname` / `default` | Outbound DKIM signing (key auto-generated) |
| `CertificatePassword` | `smtp-test-password` | Protects `config/server.pfx` |
| `SmartHost*` | `null` | Optional relay host; null = direct-to-MX |
| `EnableDane` / `EnableTlsRpt*` / `EnableDmarcReporting` / `EnableAutoMdn` | `false` | Opt-in features |
| Rate limits, queue concurrency, session timeout | see file | Operational tuning |

## Folders

| Folder | Contents | Committed? |
|--------|----------|------------|
| [`config/`](config/) | TLS certificate + DKIM keys (generated on first run) | tracked — commit the keys when you want them stable |
| `mailstore/` | Received `.eml`, the outbound queue, `users.txt`, reporting state | **git-ignored** (runtime data, contains credential hashes) |

## User accounts

Accounts live in `mailstore/users.txt` (SHA-256 password hashes + SCRAM credentials + optional client-
certificate thumbprints for SASL `EXTERNAL`). On first run three demo users are created —
`admin` / `test123`, `user` / `test123`, `demo` / `demo`. **Change them before any real use.**

## Running on a real Internet server

1. **Set your identity.** In `Configuration.cs`: `Hostname = "mail.example.com"`,
   `LocalDomains = ["example.com"]`, `DkimDomain = "example.com"`, and the standard ports
   `Port = 25`, `SubmissionPort = 587`, `ImplicitTlsPort = 465`. Rebuild.
2. **Bind privileged ports.** 25/587/465 need elevated privileges — either run with a capability
   (`sudo setcap 'cap_net_bind_service=+ep' $(which dotnet)` or on the published binary) or put a
   port-forward in front.
3. **Use a real TLS certificate.** Replace the self-signed `config/server.pfx` with a real certificate
   for the MX hostname (e.g. Let's Encrypt, exported as PKCS#12 with `CertificatePassword`).
4. **Publish DNS.** MX, SPF, the DKIM record from `config/dkim_<selector>.dns.txt`, DMARC, and
   (optionally) MTA-STS / TLS-RPT / DANE — the full record set and verification commands are in the
   [DNS setup guide](../../docs/SMTP-Server.md#dns-setup-guide).
5. **Static IP with matching PTR** (FCrDNS), open the firewall for 25/587/465 inbound and 25 outbound
   (or configure a `SmartHost`), and don't be on a blocklist.
6. **Run as a service** (systemd example):

   ```ini
   [Unit]
   Description=Hermod SMTP server
   After=network-online.target

   [Service]
   WorkingDirectory=/opt/hermod-smtp        # config/ and mailstore/ live here
   ExecStart=/usr/bin/dotnet /opt/hermod-smtp/SMTPServerCLI.dll
   Restart=on-failure
   AmbientCapabilities=CAP_NET_BIND_SERVICE  # to bind 25/587/465

   [Install]
   WantedBy=multi-user.target
   ```

## Status

This is an RFC-conformant reference implementation, **not** a hardened production MX: there is no
anti-spam/abuse layer, recipients are accepted catch-all, and the code has not been security-audited.
Read the [production-readiness section](../../docs/SMTP-Server.md#production-readiness--limitations)
before exposing it to untrusted mail.

## License

Apache License 2.0 — see the file headers.
