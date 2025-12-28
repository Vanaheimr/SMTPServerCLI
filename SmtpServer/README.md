# Achim SMTP Server

Ein vollständiger SMTP-Server in C# .NET 10 mit StartTLS, DKIM-Verifizierung und DNS-Validierung.

## Features

- **SMTP-Protokoll**: Vollständige Implementierung nach RFC 5321
- **STARTTLS**: TLS 1.2 und TLS 1.3 Unterstützung
- **DKIM-Verifizierung**: Überprüfung von DKIM-Signaturen
- **SPF-Validierung**: Sender Policy Framework Prüfung
- **DMARC-Analyse**: Domain-based Message Authentication
- **MX-Record-Abfrage**: Überprüfung der Sender-DNS-Konfiguration
- **Dateispeicherung**: E-Mails werden als .eml-Dateien gespeichert
- **Keine externen Abhängigkeiten**: Pure .NET-Implementierung

## Voraussetzungen

- .NET 10 SDK
- Linux: `dig` Befehl für DNS-Abfragen
- Windows: `nslookup` für DNS-Abfragen

## Schnellstart

```bash
# Server starten
dotnet run --project AchimSmtpServer.csproj

# In einem anderen Terminal: Testclient ausführen
dotnet run --project TestClient/SmtpTestClient.csproj
```

## Konfiguration

Der Server kann über Umgebungsvariablen konfiguriert werden:

| Variable | Standard | Beschreibung |
|----------|----------|--------------|
| `SMTP_HOSTNAME` | `localhost` | Hostname für HELO/EHLO |
| `SMTP_PORT` | `2525` | SMTP-Port (25 benötigt Root) |
| `SMTP_SUBMISSION_PORT` | `2587` | Submission-Port |
| `SMTP_MAIL_PATH` | `./mailstore` | Speicherort für E-Mails |

## Architektur

```
┌─────────────────────────────────────────────────────────────────┐
│                        SmtpServer                               │
├─────────────────────────────────────────────────────────────────┤
│  TcpListener (Port 25/587)                                      │
│       │                                                         │
│       ▼                                                         │
│  SmtpSession ──────────────────────────────────────────────────┤
│       │                                                         │
│       ├──► HELO/EHLO                                           │
│       ├──► STARTTLS ──► SslStream                              │
│       ├──► MAIL FROM                                           │
│       ├──► RCPT TO                                             │
│       └──► DATA ──► EmailMessage.Parse()                       │
│                         │                                       │
│                         ▼                                       │
│              ┌─────────────────────┐                           │
│              │   DnsVerifier       │                           │
│              ├─────────────────────┤                           │
│              │ • VerifySpfAsync()  │                           │
│              │ • VerifyDkimAsync() │                           │
│              │ • VerifyDmarcAsync()│                           │
│              │ • GetMxRecordsAsync()│                          │
│              └─────────────────────┘                           │
│                         │                                       │
│                         ▼                                       │
│              ┌─────────────────────┐                           │
│              │   FileMailStorage   │                           │
│              │   → ./mailstore/    │                           │
│              │   → .eml files      │                           │
│              └─────────────────────┘                           │
└─────────────────────────────────────────────────────────────────┘
```

## SMTP-Befehle

| Befehl | Beschreibung |
|--------|--------------|
| `HELO` | Einfache Begrüßung |
| `EHLO` | Extended HELO mit Capabilities |
| `STARTTLS` | TLS-Verbindung initiieren |
| `MAIL FROM:` | Absender angeben |
| `RCPT TO:` | Empfänger angeben |
| `DATA` | Nachrichteninhalt senden |
| `RSET` | Transaktion zurücksetzen |
| `NOOP` | Keine Operation |
| `QUIT` | Verbindung beenden |
| `VRFY` | Adresse verifizieren (deaktiviert) |

## E-Mail-Speicherformat

E-Mails werden mit zusätzlichen Metadaten gespeichert:

```
X-Envelope-From: sender@example.com
X-Envelope-To: recipient@localhost
X-Received-At: 2024-12-23T10:00:00.000Z
X-SPF-Result: Pass
X-DKIM-Result: Pass
X-DMARC-Result: Pass
X-MX-Records: mail.example.com, mail2.example.com

From: sender@example.com
To: recipient@localhost
Subject: Test
...
```

## DNS-Verifizierung

### SPF (Sender Policy Framework)

Der Server überprüft:
- `ip4:` und `ip6:` Mechanismen
- `a:` und `mx:` Lookups
- `include:` rekursive Abfragen
- `all` Qualifier (+, -, ~, ?)

### DKIM (DomainKeys Identified Mail)

Verifiziert:
- Body-Hash (`bh=`)
- Header-Signatur (`b=`)
- Canonicalization (simple/relaxed)
- Öffentlicher Schlüssel aus DNS

### DMARC

Prüft:
- `_dmarc.domain.com` TXT-Record
- Policy-Extraktion (none, quarantine, reject)
- Organizational Domain Fallback

## TLS-Konfiguration

### Selbstsigniertes Zertifikat (automatisch)

Beim ersten Start wird automatisch ein selbstsigniertes Zertifikat erstellt.

### Eigenes Zertifikat

```csharp
var config = new SmtpServerConfig
{
    CertificatePath = "/path/to/certificate.pfx",
    CertificatePassword = "your-password",
    RequireStartTls = true  // TLS erforderlich
};
```

### Let's Encrypt

```bash
# Zertifikat konvertieren
openssl pkcs12 -export -out server.pfx \
    -inkey privkey.pem -in fullchain.pem
```

## Beispiel: E-Mail senden

```bash
# Mit telnet testen
telnet localhost 2525

EHLO myclient
MAIL FROM:<me@example.com>
RCPT TO:<you@localhost>
DATA
From: me@example.com
To: you@localhost
Subject: Test

Hello World!
.
QUIT
```

## Sicherheitshinweise

⚠️ **Produktionsempfehlungen:**

1. **Ports**: Verwende die Standardports 25 und 587 (erfordert Root/Admin)
2. **TLS**: Aktiviere `RequireStartTls = true` für Produktion
3. **Zertifikat**: Verwende ein gültiges Zertifikat (Let's Encrypt)
4. **Firewall**: Beschränke Zugriff auf vertrauenswürdige IPs
5. **Rate Limiting**: Implementiere zusätzliche Schutzmaßnahmen

## Erweiterungsmöglichkeiten

- [ ] DMARC-Alignment-Prüfung
- [ ] ARC (Authenticated Received Chain)
- [ ] Greylisting
- [ ] Spam-Filterung (SpamAssassin-Integration)
- [ ] SMTP-AUTH (PLAIN, LOGIN, CRAM-MD5)
- [ ] Maildir-Format
- [ ] Queue-System für Retry
- [ ] Prometheus-Metriken

## Lizenz

MIT License

---

Erstellt für Achim's EU-Regulierungs- und Infrastruktur-Projekte.
