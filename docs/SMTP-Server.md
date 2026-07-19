# Hermod SMTP Server & Client

A from-scratch SMTP server and outbound client built on the
[Vanaheimr Hermod](https://github.com/Vanaheimr/Hermod) libraries (namespace
`org.GraphDefined.Vanaheimr.Hermod.SMTP.New`). It implements the modern SMTP
stack — ESMTP, STARTTLS, SASL AUTH, SPF, DKIM, DMARC, MTA-STS, DSN — with a
strong focus on RFC-correct behaviour, cross-validated against independent
reference implementations.

> ### ⚠️ Status: RFC-conformant reference implementation — not a hardened production MX
>
> The **protocol layer** is implemented correctly and tested. It can send and
> receive mail between known hosts and, with a real certificate and correct DNS,
> on an experimental domain. It is **not** ready to be a primary Internet-facing
> MX for untrusted mail without the work listed under
> [Production readiness](#production-readiness--limitations) — most importantly:
> there is no anti-spam/abuse layer, recipients are accepted catch-all, and the
> code has not been security audited. Read that section before deploying.

---

## Contents

- [Architecture](#architecture)
- [Supported SMTP / ESMTP](#supported-smtp--esmtp)
- [Authentication (SASL)](#authentication-sasl)
- [Transport security (TLS)](#transport-security-tls)
- [Email authentication (SPF / DKIM / DMARC)](#email-authentication-spf--dkim--dmarc)
- [Message handling](#message-handling)
- [Standards conformance](#standards-conformance)
- [Testing & reference implementations](#testing--reference-implementations)
- [Configuration](#configuration)
- [DNS setup guide](#dns-setup-guide)
- [Deployment](#deployment)
- [Production readiness & limitations](#production-readiness--limitations)
- [Not implemented / roadmap](#not-implemented--roadmap)

---

## Architecture

| Component | File | Purpose |
|-----------|------|---------|
| `SMTPServer` | `SMTPServerCLI/SMTPServer/SMTPServer.cs` | TCP listeners for the MTA (25), submission (587) and implicit-TLS submission (465) ports |
| `SMTPSession` | `SMTPSession.cs` | Per-connection state machine, command handling, DATA/BDAT |
| `SmtpAuthManager` + handlers | `SMTPAuth.cs` | SASL PLAIN / LOGIN / SCRAM-SHA-256 / EXTERNAL |
| `DNSVerifier` | `DNSVerifications/DNSVerifier.cs` | SPF, DKIM, DMARC, MX/A/AAAA/PTR — all via the Hermod `DNSClient` |
| `DkimSigner` + `DkimCanonicalization` | `DNSVerifications/` | RFC 6376 signing / shared canonicalizer |
| `SpfMacros` | `DNSVerifications/SpfMacros.cs` | RFC 7208 §7 macro expansion |
| `MailAddressParser` | `MailAddressParser.cs` | RFC 5322 From/To address parsing |
| `SMTPOutboundClient` | `SMTPOutboundClient.cs` | MX lookup, STARTTLS, DKIM signing, relay |
| `MailQueue` / `QueueProcessor` / `BounceHandler` | root | Persistent outbound queue, retries, DSN bounces |
| `FileMailStorage` | `MailStorage/FileMailStorage.cs` | Stores inbound mail as `.eml` files |
| `MtaStsResolver` | `MtaSts.cs` | RFC 8461 policy fetch (DNS TXT + HTTPS) |

All DNS lookups (TXT, MX, A/AAAA, PTR, MTA-STS) go through the injected Hermod
`DNSClient` — there are no `nslookup`/`dig` subprocesses or `System.Net.Dns`
calls in the active code.

---

## Supported SMTP / ESMTP

**Commands:** `HELO`, `EHLO`, `STARTTLS`, `AUTH`, `MAIL FROM`, `RCPT TO`,
`DATA`, `BDAT`, `RSET`, `NOOP`, `QUIT`, `VRFY` (returns `252`, does not verify).

**EHLO extensions advertised:**

| Extension | RFC | Notes |
|-----------|-----|-------|
| `SIZE` | [RFC 1870](https://www.rfc-editor.org/rfc/rfc1870) | Advertised with the configured max (default 25 MB) |
| `8BITMIME` | [RFC 6152](https://www.rfc-editor.org/rfc/rfc6152) | 8-bit content accepted |
| `PIPELINING` | [RFC 2920](https://www.rfc-editor.org/rfc/rfc2920) | Command groups processed in order; buffered reader is pipeline-safe |
| `SMTPUTF8` | [RFC 6531](https://www.rfc-editor.org/rfc/rfc6531) | Internationalized email; UTF-8 preserved end-to-end |
| `ENHANCEDSTATUSCODES` | [RFC 2034](https://www.rfc-editor.org/rfc/rfc2034) | `x.y.z` codes on responses |
| `CHUNKING` (`BDAT`) | [RFC 3030](https://www.rfc-editor.org/rfc/rfc3030) | Binary-safe, dot-stuffing-free transfer |
| `DSN` | [RFC 3461](https://www.rfc-editor.org/rfc/rfc3461) | `ENVID`, `RET`, `NOTIFY`, `ORCPT` parsed |
| `STARTTLS` | [RFC 3207](https://www.rfc-editor.org/rfc/rfc3207) | Advertised until TLS is active |
| `REQUIRETLS` | [RFC 8689](https://www.rfc-editor.org/rfc/rfc8689) | Advertised only after STARTTLS |
| `AUTH` | [RFC 4954](https://www.rfc-editor.org/rfc/rfc4954) | Mechanisms depend on TLS state |

**Line/transfer correctness:**

- Dot-stuffing / de-stuffing on `DATA` per RFC 5321 §4.5.2.
- `BDAT` chunking (RFC 3030), binary-safe.
- Line-length limits (RFC 5321 §4.5.3.1): configurable command (default 1024)
  and text-line (default 2048) limits; over-long DATA lines are rejected only
  after the terminating `.` so the connection stays in sync.
- UTF-8 preserved on both the `DATA` and `BDAT` paths; CRLF forced independent
  of host OS.
- **PIPELINING** (RFC 2920): commands are read from a buffered reader and
  answered in order, so a client may send whole command groups
  (`MAIL`/`RCPT`/`DATA`) without waiting for each reply. Replies are flushed per
  command, so all responses preceding `DATA` are on the wire before the message
  body is read. Buffered plaintext is discarded across `STARTTLS`, preventing
  the pipelined plaintext-injection attack (RFC 3207 §4.2).

---

## Authentication (SASL)

Implemented in `SMTPAuth.cs` per [RFC 4954](https://www.rfc-editor.org/rfc/rfc4954):

| Mechanism | RFC | Requires TLS | Notes |
|-----------|-----|:---:|-------|
| `PLAIN` | [RFC 4616](https://www.rfc-editor.org/rfc/rfc4616) | yes | Rejected in cleartext (`538`) |
| `LOGIN` | draft-murchison-sasl-login | yes | Rejected in cleartext |
| `SCRAM-SHA-256` | [RFC 7677](https://www.rfc-editor.org/rfc/rfc7677) | no | Password never transmitted; mutual auth |
| `EXTERNAL` | [RFC 4422](https://www.rfc-editor.org/rfc/rfc4422) | yes | Uses the TLS client certificate |

- Submission port (587) requires authentication (RFC 6409).
- Relay to non-local domains requires authentication (no open relay).
- Per-IP auth-attempt and connection rate limiting.

User store is a flat file (`<mailstore>/users.txt`) — SHA-256 password hashes
plus SCRAM credentials. **Demonstration only**; use a real database/LDAP for
production.

---

## Transport security (TLS)

- **STARTTLS** (RFC 3207) on the MTA (25) and submission (587) ports, TLS 1.2 / 1.3.
- **Implicit TLS** (RFC 8314) on the submission port **465**: the connection is
  TLS from the first byte, with no plaintext `STARTTLS` upgrade (so no
  downgrade-stripping window). The port is only bound when a certificate is
  configured; disable it with `EnableImplicitTls = false`. On this port
  `STARTTLS` is not advertised (already encrypted) and cleartext-sensitive AUTH
  (`PLAIN`/`LOGIN`) is available immediately. Both STARTTLS and implicit TLS
  share one handshake path (`SMTPSession.EstablishTlsAsync`).
- **Inbound** certificate: loaded from a PKCS#12 file; a self-signed cert is
  auto-generated for testing. Replace with a real certificate for the MX
  hostname in production.
- **Outbound** certificate validation is **policy-aware**
  (`SMTPOutboundClient.ValidateServerCertificate`):
  - *Opportunistic TLS* ([RFC 7435](https://www.rfc-editor.org/rfc/rfc7435),
    the default MTA→MTA case): a bad certificate is logged but accepted —
    encryption still beats cleartext.
  - *Enforced TLS* (MTA-STS `enforce`, REQUIRETLS, `RequireStartTls`, or the
    `RequireValidCertificate` flag): the certificate must chain to a trusted
    root and match the MX host name (RFC 8461 §4.1); otherwise the handshake is
    refused and delivery is **deferred**, never downgraded.
- **MTA-STS** ([RFC 8461](https://www.rfc-editor.org/rfc/rfc8461)): policy is
  fetched via `_mta-sts` TXT + `https://mta-sts.<domain>/.well-known/mta-sts.txt`;
  MX hosts are filtered against the policy in enforce mode.
- **REQUIRETLS** ([RFC 8689](https://www.rfc-editor.org/rfc/rfc8689)): honored on
  `MAIL FROM` and propagated to enforced outbound delivery.

---

## Email authentication (SPF / DKIM / DMARC)

Inbound mail from unauthenticated senders is evaluated and the results are
written into an `Authentication-Results` header
([RFC 8601](https://www.rfc-editor.org/rfc/rfc8601)) and stored `X-*` metadata.

### SPF — [RFC 7208](https://www.rfc-editor.org/rfc/rfc7208) ✅ complete

- Mechanisms `all`, `ip4`, `ip6`, `a`, `mx`, `exists`, `include`; modifier
  `redirect`. `ptr` is parsed and counted but not evaluated (deprecated per
  §5.5). Unknown mechanisms → `PermError`.
- Correct `include` result mapping (§5.2), dual-CIDR lengths, and the shared
  **10-DNS-lookup limit** (§4.6.4).
- **Macro expansion** (§7): `s l o d i p v h`, digit/`r`/delimiter transformers,
  `%% %_ %-`, uppercase URL-escaping. Validated against the RFC 7208 §7.4 vectors.
- Hard `-all` failures are rejected at RCPT/DATA (`550 5.7.23`).

### DKIM — [RFC 6376](https://www.rfc-editor.org/rfc/rfc6376) ✅ complete

- Signing and verification share one canonicalizer (`DkimCanonicalization`),
  operating on the **raw** message bytes so `simple` and `relaxed` are exact.
- Hashing over UTF-8 octets (fixes 8-bit/UTF-8 bodies); tag-aware `b=` removal;
  `h=` selected bottom-up per RFC 6376 §5.4.2; correct empty-body handling.
- A broken/absent signature is **advisory** (§6.1) — it does not by itself
  cause rejection; the result is recorded and left to DMARC.
- Outbound mail can be DKIM-signed (`rsa-sha256`, relaxed/relaxed by default).

### DMARC — [RFC 7489](https://www.rfc-editor.org/rfc/rfc7489) ✅

- The policy record is looked up on the **`From:` (RFC5322.From) domain**, with a
  fallback to the **organizational domain** (whose `sp=` then governs sub-domains).
  The record is fully parsed: `p`, `sp`, `adkim`, `aspf`, `pct`.
- **Identifier alignment (§3.1) is computed.** DMARC passes when SPF **or** DKIM
  produced a `pass` whose authenticated domain is aligned with the `From:` domain
  — relaxed (equal organizational domain, the default) or strict (`adkim=s`/
  `aspf=s`, exact match). SPF alignment uses the `MAIL FROM` domain; DKIM alignment
  uses the passing signature's `d=`.
- On failure the applicable policy (`p`, or `sp` for a sub-domain) is enforced,
  with `pct` sampling demoting the remainder (`reject`→`quarantine`→`none`,
  §6.6.4). `reject` → `550`, `quarantine` → delivered with an
  `X-DMARC-Quarantine` marker.
- The organizational domain is derived from an **embedded Mozilla Public Suffix
  List** snapshot (`DNSVerifications/public_suffix_list.dat`; validated against
  all official `test_psl.txt` vectors), so multi-label suffixes like `co.uk` and
  private suffixes like `github.io` are handled correctly.
- **Not yet implemented:** aggregate/forensic **report generation** (`rua`/`ruf`).
  The tags are parsed but no reports are emitted — this does not affect inbound
  enforcement.

---

## Message handling

- **Trace headers:** each hop prepends a `Received:` header (RFC 5321 §4.4,
  RFC 3848 protocol names `ESMTP`/`ESMTPS`/`ESMTPA`/`ESMTPSA`), best-effort
  reverse DNS, and a `for` clause only for a single recipient (privacy).
- **Authentication-Results** (RFC 8601) above the `Received` header, with
  accurate `spf=… smtp.mailfrom=`, `dkim=… header.d=` (the signature's `d=`),
  and `dmarc=… header.from=` (the `From` domain).
- **Address parsing** (`MailAddressParser`): RFC 5322 display names, angle
  addresses, quoted local-parts, domain-literals, comments, groups, IDN/UTF-8,
  and comma-aware list splitting.
- **DSN / bounces** (RFC 3461/3464): delivery-status notifications and
  `multipart/report` bounces; null sender (`<>`) handled to avoid bounce loops.
- **Outbound queue:** file-persistent, exponential-backoff retries, MX priority
  ordering, per-domain concurrency limits.

---

## Standards conformance

| RFC | Title | Status |
|-----|-------|--------|
| 5321 | SMTP | ✅ core commands, trace, dot-stuffing, line limits |
| 5322 | Internet Message Format | ✅ address parsing (From/To) |
| 1870 | SMTP SIZE | ✅ |
| 6152 | 8BITMIME | ✅ |
| 6531 / 6532 | SMTPUTF8 / Internationalized headers | ✅ transport; header i18n partial |
| 2034 | Enhanced status codes | ✅ |
| 3030 | CHUNKING / BDAT | ✅ |
| 3207 | STARTTLS | ✅ |
| 3461 / 3464 | DSN | ✅ |
| 4954 | SMTP AUTH | ✅ |
| 4616 / 7677 / 4422 | PLAIN / SCRAM-SHA-256 / EXTERNAL | ✅ |
| 6409 | Message submission | ✅ (auth required on 587) |
| 8689 | REQUIRETLS | ✅ |
| 8461 | MTA-STS | ✅ (TLS-RPT not implemented) |
| 7208 | SPF (incl. macros §7) | ✅ complete |
| 6376 | DKIM | ✅ complete, cross-validated |
| 8601 | Authentication-Results | ✅ |
| 7435 | Opportunistic security (TLS) | ✅ outbound cert policy |
| 7489 | DMARC | ✅ identifier alignment + PSL; ⚠️ no `rua`/`ruf` reports |
| 2920 | PIPELINING | ✅ |
| 8314 | Implicit TLS (port 465) | ✅ implicit-TLS submission |
| 8617 | ARC | ❌ not implemented |

---

## Testing & reference implementations

Correctness is validated against **independent** implementations and the RFC
example vectors, not just self-consistency. Test harnesses live in the
scratchpad (`dnstest/`, `pgp_smtp_test.py`, `dkim_sign.py`, `dkim_verify.py`).

| Area | Reference / method |
|------|--------------------|
| **DKIM** | Cross-validated **both directions** with Python **[`dkimpy`](https://launchpad.net/dkimpy)**: dkimpy verifies our signature (incl. UTF-8), and our verifier accepts a dkimpy-signed message. Plus RFC 6376 §3.4.5 canonicalization vectors and sign↔verify roundtrips (ASCII/UTF-8, simple + relaxed) with tamper detection. |
| **SPF macros** | All **RFC 7208 §7.4** example vectors (25 assertions). |
| **DMARC / Public Suffix List** | All **78 official `test_psl.txt`** vectors from publicsuffix.org; alignment building-block checks (exact/relaxed/private-suffix); live-DNS end-to-end (`google.com`→fail/reject, `github.com`→fail/quarantine — real published policies). |
| **PGP / dot-stuffing** | Messages signed with **GnuPG** (`gpg` clearsign + PGP/MIME) delivered over `DATA` and `BDAT`; signatures re-verified after the server round-trip to prove byte-exact preservation. |
| **DNS** | Live queries via the Hermod **`DNSClient`** against real domains (gmail.com, google.com, `dns.google`, `one.one.one.one`). |
| **Address parser** | 20 unit assertions incl. the previously-broken cases (`user@localhost`, `user+tag@`, quoted local-parts, domain-literals, IDN, groups). |
| **Outbound TLS** | Tested against our own self-signed server: opportunistic → `Success 250`; strict → `TempFail 454`. |
| **Implicit TLS (465)** | A real `SslStream` client handshakes from the first byte, receives the `220` greeting and `EHLO` response over TLS, and confirms `STARTTLS` is not advertised while `AUTH PLAIN/LOGIN` is; the plaintext 587 port still advertises `STARTTLS`. |
| **PIPELINING** | A client sends `MAIL`/`RCPT`/`DATA` as one socket write (and, in a second test, the entire `EHLO`…`DATA`…body…`QUIT` session in a single write); all replies come back in order and both messages land on disk. |

---

## Configuration

Configured via environment variables (see `SMTPServerCLI/Program.cs`):

| Variable | Default | Purpose |
|----------|---------|---------|
| `SMTP_HOSTNAME` | `localhost` | Server hostname (used in banners, HELO, Received) |
| `SMTP_PORT` | `2525` | MTA port (use **25** in production) |
| `SMTP_SUBMISSION_PORT` | `2587` | Submission port (use **587** in production) |
| `SMTP_IMPLICIT_TLS_PORT` | `2465` | Implicit-TLS submission port (use **465** in production; needs a certificate) |
| `SMTP_MAIL_PATH` | `./mailstore` | Storage dir (`.eml` files, `users.txt`, DKIM keys) |
| `SMTP_LOCAL_DOMAINS` | `<hostname>` | Comma/space list of domains delivered locally |
| `DKIM_DOMAIN` | `<hostname>` | DKIM `d=` domain |
| `DKIM_SELECTOR` | `default` | DKIM selector |
| `DKIM_AUTO_GENERATE` | – | `true` → generate a keypair if none exists |
| `SMTP_SMARTHOST` | – | Optional relay host for outbound |
| `SMTP_SMARTHOST_PORT` / `_USER` / `_PASS` | `25` / – / – | Smarthost port & credentials |

Ports default to 2525/2587 so the server runs without root. A self-signed TLS
certificate (`server.pfx`) and default users (`admin`/`user` = `test123`,
`demo` = `demo`) are generated on first run — **change these before any real
use.**

### Run

```sh
git submodule update --init --depth 1 libs/Hermod libs/Styx
dotnet run --project SMTPServerCLI/SMTPServerCLI/SMTPServerCLI.csproj
```

---

## DNS setup guide

To receive and authenticate mail for `example.com` from a host `mail.example.com`
at IP `192.0.2.10`, publish the following records. Replace names/IPs accordingly.

### 1. MX — where mail for the domain goes

```dns
example.com.            IN  MX   10 mail.example.com.
mail.example.com.       IN  A    192.0.2.10
mail.example.com.       IN  AAAA 2001:db8::10        ; if you have IPv6
```

### 2. PTR (reverse DNS) — set at your hosting/IP provider

```dns
10.2.0.192.in-addr.arpa. IN PTR mail.example.com.
```

The PTR **must** resolve back to a name that forward-resolves to the same IP
(FCrDNS) and should match your HELO name — Gmail/Outlook reject or spam-fold
senders without it.

### 3. SPF — authorize who may send for the domain

A single TXT record at the domain root:

```dns
example.com.  IN TXT "v=spf1 mx a:mail.example.com -ip4:192.0.2.10 ~all"
```

- `mx` authorizes your MX hosts, `a:` / `ip4:` authorize specific hosts.
- Start with `~all` (softfail) while testing; move to `-all` (hardfail) once
  you're confident. Keep total DNS-lookup terms ≤ 10.

### 4. DKIM — publish the public key

On first run the server writes the key material to `<mailstore>/dkim_<selector>.*`.
The `.dns.txt` file already contains the record to publish:

```dns
default._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkq...QAB"
```

Long keys must be split into 255-char character-strings inside the TXT record.
The `d=` domain and `s=` selector in outgoing signatures must match this record.

### 5. DMARC — publish a policy (see the alignment caveat above)

```dns
_dmarc.example.com. IN TXT "v=DMARC1; p=none; rua=mailto:dmarc@example.com; adkim=r; aspf=r"
```

Start with `p=none` and a `rua` reporting address; only tighten to
`quarantine`/`reject` once SPF+DKIM are aligned and reports look clean.

### 6. MTA-STS (optional, recommended) — enforce TLS for inbound

```dns
_mta-sts.example.com.  IN TXT "v=STSv1; id=20260719T000000;"
```

Serve the policy over HTTPS at
`https://mta-sts.example.com/.well-known/mta-sts.txt`:

```
version: STSv1
mode: enforce
mx: mail.example.com
max_age: 604800
```

### Verify your setup

```sh
dig +short MX      example.com
dig +short TXT     example.com                     # SPF
dig +short TXT     default._domainkey.example.com  # DKIM
dig +short TXT     _dmarc.example.com              # DMARC
dig +short -x      192.0.2.10                      # PTR
```

Send a test message to a Gmail account and read the *Show original* →
`SPF/DKIM/DMARC: PASS` lines, or use a checker like mail-tester.com.

---

## Deployment

1. **Real TLS certificate** for `mail.example.com` (e.g. Let's Encrypt); load it
   as PKCS#12 and point `CertificatePath`/`CertificatePassword` at it. Do not
   ship the self-signed default.
2. **Bind to ports 25, 587 and 465** (465 needs a certificate). This needs
   elevated privileges or a capability/`setcap`; or run behind a port-forward.
3. **Open the firewall** for 25/587/465 inbound and **25 outbound** (many
   networks block outbound 25 — you then need a smarthost).
4. **Static IP with matching PTR** (see DNS guide) and not on any blocklist.
5. **Replace the demo user store** and rotate DKIM keys periodically.
6. **Monitor** the queue, logs, and DMARC/TLS reports.

---

## Production readiness & limitations

Honest list of what stands between this and a production Internet MX:

- **DMARC reports are not generated** — identifier alignment and policy
  enforcement are implemented (with an embedded Public Suffix List), but no
  aggregate (`rua`) or forensic (`ruf`) reports are emitted. This is a
  good-neighbour feature and does not affect inbound anti-spoofing enforcement.
- **No anti-spam / anti-abuse** — no greylisting, DNSBL/RBL, SpamAssassin/rspamd
  integration, or reputation. An open MX is attacked immediately.
- **Catch-all recipients** — any address at a local domain is accepted; there is
  no mailbox-existence check, which enables backscatter.
- **No mailbox access** — inbound mail is written as flat `.eml` files; no
  IMAP/POP for users to read it.
- **Self-signed inbound cert by default** — must be replaced.
- **Not security-audited** — the parsers process untrusted Internet input and
  have not been fuzzed or reviewed for DoS/injection.
- **Operational gaps** — no mail-loop/`Received`-hop-count limit,
  no metrics/alerting; queue durability is not battle-tested.
- **Header internationalization** (RFC 2047 encoded-words / RFC 6532) is only
  partially handled.

For anything beyond experiments, pair it with — or defer to — a hardened MTA
(Postfix, Exim) for the parts above, or treat this as the protocol/authentication
core it is designed to be.

---

## Not implemented / roadmap

- DMARC aggregate/forensic (`rua`/`ruf`) report generation. _(Identifier
  alignment and the Public Suffix List are now implemented.)_
- ARC ([RFC 8617](https://www.rfc-editor.org/rfc/rfc8617)) for forwarding.
- TLS-RPT (RFC 8460).
- DANE / TLSA ([RFC 7672](https://www.rfc-editor.org/rfc/rfc7672)).
- SPF `exp=` explanation strings and the `ptr` mechanism.
- A real mailbox store (IMAP/POP or Maildir) and quota handling.
- Anti-spam / greylisting / DNSBL integration.
