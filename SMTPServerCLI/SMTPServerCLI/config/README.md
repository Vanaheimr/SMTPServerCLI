# `config/` — crypto material

This folder holds the server's crypto material. It is **generated on first run** and is safe to
commit to the repository (that is the point of this self-contained CLI — see
[Configuration.cs](../Configuration.cs)):

| File | What it is | Commit? |
|------|------------|---------|
| `server.pfx` | TLS certificate + private key for STARTTLS / implicit TLS. A **self-signed** cert is generated on first run — replace it with a real certificate (e.g. Let's Encrypt) for the MX hostname before going live. | your call |
| `dkim_<selector>.private.pem` | DKIM signing key (the private half). Keep it stable so the published DNS record stays valid. | yes (so the key is stable) |
| `dkim_<selector>.public.pem` | DKIM public key. | yes |
| `dkim_<selector>.dns.txt` | The `TXT` record to publish at `<selector>._domainkey.<domain>`. | yes |

Nothing here is read from environment variables — edit
[`Configuration.cs`](../Configuration.cs) to change the hostname, DKIM domain/selector, certificate
password, ports, and every other setting, then rebuild.

> **Security note:** committing private keys is a deliberate trade-off for a self-contained,
> deploy-from-git server. Keep this repository private, and regenerate the keys (delete the files and
> re-run) if they are ever exposed.
