# Achim SMTP Server

Ein vollständiger SMTP-Server in C# .NET 10 mit StartTLS, SMTP-AUTH, DKIM, DNS-Validierung und **Outbound Mail Queue**.

## Features

### Eingehend (Inbound)
- **SMTP-Protokoll**: Vollständige Implementierung nach RFC 5321
- **STARTTLS**: TLS 1.2 und TLS 1.3 Unterstützung
- **SMTP-AUTH**: PLAIN, LOGIN, SCRAM-SHA-256, EXTERNAL (mTLS)
- **CHUNKING/BDAT**: RFC 3030 - große Nachrichten ohne Dot-Stuffing
- **DSN**: RFC 3461/3464 - Delivery Status Notifications
- **REQUIRETLS**: RFC 8689 - TLS-Pflicht für sensible Mails
- **DKIM-Verifizierung**: Überprüfung von DKIM-Signaturen
- **SPF-Validierung**: Sender Policy Framework Prüfung
- **DMARC-Enforcement**: Policy-basierte Ablehnung/Quarantäne
- **Dateispeicherung**: E-Mails werden als .eml-Dateien gespeichert

### Ausgehend (Outbound)
- **Mail Queue**: Persistente Warteschlange mit Retry-Logik
- **MX Lookup**: Automatische DNS-Auflösung für Ziel-Domains
- **DKIM Signing**: Ausgehende E-Mails signieren
- **MTA-STS**: RFC 8461 - Strict Transport Security
- **Smarthost**: Optionale Relay-Unterstützung
- **Bounce Handling**: NDRs (Non-Delivery Reports) generieren
- **Rate Limiting**: Pro-Domain Throttling

### Sicherheit
- **Rate Limiting**: Schutz vor Brute-Force und DoS
- **Connection Limits**: Max. Verbindungen pro IP
- **SPF Hard-Fail Reject**: Strikte SPF-Durchsetzung
- **DKIM Fail Reject**: Ungültige Signaturen ablehnen
- **DMARC Policy Enforcement**: p=reject wird durchgesetzt
- **IP Blacklist/Whitelist**: Manuelle Zugriffskontrolle

## Architektur

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Achim SMTP Server                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────┐         ┌──────────────┐         ┌─────────────┐ │
│  │  Inbound     │         │  Mail Queue  │         │  Outbound   │ │
│  │  SMTP Server │────────►│  (Persistent)│────────►│  SMTP Client│ │
│  └──────────────┘         └──────────────┘         └─────────────┘ │
│         │                        │                        │        │
│         ▼                        ▼                        ▼        │
│  ┌──────────────┐         ┌──────────────┐         ┌─────────────┐ │
│  │  Verification│         │  Queue       │         │  MX Lookup  │ │
│  │  SPF/DKIM/   │         │  Processor   │         │  DKIM Sign  │ │
│  │  DMARC       │         │  (Retry)     │         │  STARTTLS   │ │
│  └──────────────┘         └──────────────┘         └─────────────┘ │
│         │                        │                        │        │
│         ▼                        ▼                        ▼        │
│  ┌──────────────┐         ┌──────────────┐         ┌─────────────┐ │
│  │  FileStorage │         │  Bounce      │         │  Remote MX  │ │
│  │  (.eml)      │         │  Handler     │         │  Server     │ │
│  └──────────────┘         └──────────────┘         └─────────────┘ │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Schnellstart

```bash
# Server starten (nur localhost als lokale Domain)
dotnet run --project AchimSmtpServer.csproj

# Mit eigenen lokalen Domains
SMTP_LOCAL_DOMAINS="example.com,mail.example.com" dotnet run

# Mit DKIM-Schlüssel generieren
DKIM_AUTO_GENERATE=true dotnet run --project AchimSmtpServer.csproj

# Mit Smarthost (Relay)
SMTP_SMARTHOST=smtp.provider.com SMTP_SMARTHOST_USER=user SMTP_SMARTHOST_PASS=pass dotnet run
```

## Inbound vs Outbound (Relay)

Der Server unterscheidet automatisch zwischen:

| Szenario | Erkennungsmerkmal | Aktion |
|----------|-------------------|--------|
| **Inbound** (anderer Server → hier) | Port 25, Empfänger in LocalDomains | Lokal speichern |
| **Outbound** (Client → anderer Server) | Port 587 + AUTH, Empfänger extern | Relay via Queue |
| **Open Relay Versuch** | Keine AUTH, Empfänger extern | **ABGELEHNT** |

### Port-Bedeutung

```
Port 25 (SMTP):
  └─► MTA-zu-MTA (Server-zu-Server)
  └─► Keine AUTH nötig für lokale Domains
  └─► Externe Empfänger: ABGELEHNT (ohne AUTH)

Port 587 (Submission):
  └─► MUA-zu-MTA (Client-zu-Server)
  └─► AUTH erforderlich (RFC 6409)
  └─► Nach AUTH: Relay zu externen Domains erlaubt
```

### Beispiel-Ablauf

```
┌─────────────────────────────────────────────────────────────────┐
│  Gmail Server → Port 25 → user@example.com (lokal)             │
│                                                                 │
│  1. EHLO gmail.com                                             │
│  2. MAIL FROM:<sender@gmail.com>                               │
│  3. RCPT TO:<user@example.com>  ← Lokal? JA → OK              │
│  4. DATA → Lokal speichern                                     │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  Thunderbird → Port 587 → extern@gmail.com                     │
│                                                                 │
│  1. EHLO client                                                │
│  2. STARTTLS                                                   │
│  3. AUTH PLAIN (user/pass)  ← Authentifiziert!                 │
│  4. MAIL FROM:<user@example.com>                               │
│  5. RCPT TO:<extern@gmail.com>  ← Extern? JA, aber AUTH → OK  │
│  6. DATA → In Queue für Outbound                               │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  Spammer → Port 25 → victim@somewhere.com                      │
│                                                                 │
│  1. EHLO spammer                                               │
│  2. MAIL FROM:<fake@example.com>                               │
│  3. RCPT TO:<victim@somewhere.com>                             │
│     └─► 550 5.7.1 Relay access denied. Authentication required.│
└─────────────────────────────────────────────────────────────────┘
```

## Konfiguration

### Umgebungsvariablen

| Variable | Standard | Beschreibung |
|----------|----------|--------------|
| `SMTP_HOSTNAME` | `localhost` | Hostname für HELO/EHLO und DKIM |
| `SMTP_PORT` | `2525` | SMTP-Port (MTA-zu-MTA) |
| `SMTP_SUBMISSION_PORT` | `2587` | Submission-Port (MUA-zu-MTA) |
| `SMTP_MAIL_PATH` | `./mailstore` | Speicherort für E-Mails und Queue |
| `SMTP_LOCAL_DOMAINS` | `$SMTP_HOSTNAME` | Komma-getrennte lokale Domains |
| `DKIM_DOMAIN` | `$SMTP_HOSTNAME` | Domain für DKIM-Signatur |
| `DKIM_SELECTOR` | `default` | DKIM-Selector |
| `DKIM_AUTO_GENERATE` | `false` | DKIM-Schlüssel automatisch generieren |
| `SMTP_SMARTHOST` | - | Relay-Server (optional) |
| `SMTP_SMARTHOST_PORT` | `25` | Relay-Port |
| `SMTP_SMARTHOST_USER` | - | Relay-Benutzername |
| `SMTP_SMARTHOST_PASS` | - | Relay-Passwort |

## Outbound Mail System

### Queue-Verzeichnisstruktur

```
mailstore/
├── queue/
│   ├── pending/     # Wartende E-Mails
│   ├── failed/      # Fehlgeschlagene E-Mails
│   └── delivered/   # Zugestellte E-Mails (optional)
├── users.txt        # Benutzerdatenbank
└── dkim_default.private.pem  # DKIM Private Key
```

### Queue-Verarbeitung (Event-basiert)

Der Queue Processor verwendet `Channel<T>` für **zero-latency** Zustellung:

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   SmtpSession.HandleDataAsync()                                 │
│        │                                                        │
│        ▼                                                        │
│   mailQueue.EnqueueAsync()                                      │
│        │                                                        │
│        ├──► File: ./queue/pending/*.json (Persistenz)          │
│        │                                                        │
│        └──► Channel.WriteAsync() ─────────────────────────┐    │
│                                                            │    │
│   ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  │    │
│                                                            ▼    │
│   QueueProcessor (2 Consumer-Tasks)                             │
│        │                                                        │
│        ├──► NewMailConsumer:    await foreach (Channel)        │
│        │         └──► Sofortige Zustellung                     │
│        │                                                        │
│        └──► RetryCheckConsumer: Timer alle 60s                 │
│                  └──► Deferred Mails prüfen                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Vorteile gegenüber Polling:**

| Aspekt | Polling (alt) | Channel (neu) |
|--------|---------------|---------------|
| Latenz | 0-30 Sekunden | < 1 ms |
| CPU-Last | Konstant | Nur bei Arbeit |
| Skalierung | Begrenzt | Hocheffizient |

**Kein Polling** - neue E-Mails werden sofort zugestellt:

```csharp
// Producer (SmtpSession)
await mailQueue.EnqueueAsync(mail);  // Schreibt in Channel

// Consumer (QueueProcessor) - wartet blockierend
await foreach (var mail in queue.NewMailReader.ReadAllAsync(ct))
{
    await DeliverMailAsync(mail);    // Sofort!
}
```

### Retry-Logik (RFC 5321)

| Versuch | Wartezeit | Kumulativ |
|---------|-----------|-----------|
| 1 | 15 min | 15 min |
| 2 | 30 min | 45 min |
| 3 | 1 h | 1:45 h |
| 4 | 2 h | 3:45 h |
| 5 | 4 h | 7:45 h |
| 6 | 8 h | 15:45 h |
| 7 | 12 h | 27:45 h |
| 8+ | 24 h | bis 5 Tage |

Nach 5 Tagen: Bounce (NDR) an Absender

### DKIM-Konfiguration

```bash
# Schlüssel manuell generieren
dotnet run --project AchimSmtpServer.csproj << 'EOF'
DkimKeyGenerator.SaveKeyPair("./mailstore", "example.com", "default");
EOF

# Generierte Dateien:
# - dkim_default.private.pem  → Server (geheim halten!)
# - dkim_default.public.pem   → Referenz
# - dkim_default.dns.txt      → DNS-Eintrag
```

DNS-Eintrag hinzufügen:
```
default._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=MIIBIjAN..."
```

### Bounce Messages (NDR)

Bei permanenten Fehlern (5xx) wird automatisch ein NDR generiert:

```
From: Mail Delivery System <mailer-daemon@server.example.com>
To: sender@example.com
Subject: Undelivered Mail Returned to Sender
Content-Type: multipart/report; report-type=delivery-status

This is the mail system at host server.example.com.

I'm sorry to have to inform you that your message could not
be delivered to one or more recipients.

<recipient@target.com>: delivery failed
    Remote server: mx.target.com
    Error: 550 5.1.1 User unknown
```

## DNS-Voraussetzungen für Outbound

Damit andere Server deine E-Mails akzeptieren:

```dns
; MX Record
example.com.     IN MX  10 mail.example.com.

; A Record für Mailserver
mail.example.com. IN A   203.0.113.1

; Reverse DNS (PTR) - SEHR WICHTIG!
1.113.0.203.in-addr.arpa. IN PTR mail.example.com.

; SPF
example.com.     IN TXT "v=spf1 mx ip4:203.0.113.1 -all"

; DKIM
default._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=..."

; DMARC
_dmarc.example.com. IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
```

## Authentifizierungsmechanismen

| Mechanismus | Sicherheit | TLS erforderlich | Beschreibung |
|-------------|------------|------------------|--------------|
| **PLAIN** | Basis | ✓ Ja | Base64-kodiertes Passwort |
| **LOGIN** | Basis | ✓ Ja | Zwei-Schritt Base64 |
| **SCRAM-SHA-256** | Hoch | ✗ Nein | Challenge-Response |
| **EXTERNAL** | Sehr hoch | ✓ Ja (mTLS) | Client-Zertifikat |

## Dateien

| Datei | Beschreibung |
|-------|--------------|
| `SmtpServer.cs` | Inbound SMTP Server, Session-Handling |
| `SmtpAuth.cs` | Authentifizierungsmechanismen |
| `SmtpOutbound.cs` | Outbound SMTP Client |
| `MailQueue.cs` | Persistente Mail Queue |
| `QueueProcessor.cs` | Queue-Verarbeitung mit Retry |
| `DkimSigner.cs` | DKIM-Signierung |
| `BounceHandler.cs` | NDR-Generierung |
| `Program.cs` | Entry Point |

## Wichtige Hinweise für Produktion

| Thema | Empfehlung |
|-------|------------|
| **Reverse DNS (PTR)** | Ohne korrekten PTR lehnen viele Server ab |
| **IP-Reputation** | Neue IPs werden oft als Spam eingestuft |
| **Warmup** | Langsam Volumen steigern |
| **Blacklists** | IP regelmäßig gegen RBLs prüfen |
| **TLS** | `RequireStartTls = true` in Produktion |
| **Ports** | 25 und 587 benötigen Root/Admin |

## Erweiterungsmöglichkeiten

- [ ] DMARC-Alignment-Prüfung
- [ ] ARC (Authenticated Received Chain)
- [ ] Greylisting
- [ ] XOAUTH2 / OAUTHBEARER
- [ ] Maildir-Format
- [ ] Prometheus-Metriken
- [ ] Web-Interface für Queue-Management
- [ ] Milter-Support

## Lizenz

MIT License
