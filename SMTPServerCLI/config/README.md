# `config/` — crypto material

This folder holds the server's crypto material. It is **generated on first run** and is safe to
commit to the repository (that is the point of this self-contained CLI — see
[Configuration.cs](../Configuration.cs)):

| File | What it is | Commit? |
|------|------------|---------|
| `server.pfx` | TLS certificate + private key for STARTTLS / implicit TLS. A **self-signed** cert is generated on first run — replace it with a real certificate (e.g. Let's Encrypt) for the MX hostname before going live. | your call |
| `dkim_<selector>.private.pem` | DKIM signing key (the private half). Keep it stable so the published DNS record stays valid. | yes (so the key is stable) |
| `dkim_<selector>.public.pem` | DKIM public key. | yes |
| `dkim_<selector>.dns.txt` | The `TXT` record to publish at `<selector>._domainkey.<domain>`, for the domain the key was generated with. The `dns` command at the server's prompt prints the current record, already split into 255-character strings. | yes |

Nothing here is read from environment variables. To change a default for good (the hostname,
DKIM domain/selector, certificate password, ports and every other setting), edit
[`Configuration.cs`](../Configuration.cs) and rebuild. To change one for a single start, use a
switch: `--config <dir>` puts this folder elsewhere, `--certificate <file.pfx>` uses a real
certificate instead of `server.pfx`, and `--dkim-selector <name>` generates a new key pair next to
the old one. `-h` lists all switches.

> **Security note:** committing private keys is a deliberate trade-off for a self-contained,
> deploy-from-git server. Keep this repository private, and regenerate the keys (delete the files and
> re-run) if they are ever exposed.
