# Achim SMTP Server

Ein vollständiger SMTP-Server in C# .NET 10 mit StartTLS, SMTP-AUTH, DKIM-Verifizierung und DNS-Validierung.

## Features

- **SMTP-Protokoll**: Vollständige Implementierung nach RFC 5321
- **STARTTLS**: TLS 1.2 und TLS 1.3 Unterstützung
- **SMTP-AUTH**: PLAIN, LOGIN, SCRAM-SHA-256, EXTERNAL (mTLS)
- **DKIM-Verifizierung**: Überprüfung von DKIM-Signaturen
- **SPF-Validierung**: Sender Policy Framework Prüfung
- **DMARC-Analyse**: Domain-based Message Authentication
- **MX-Record-Abfrage**: Überprüfung der Sender-DNS-Konfiguration
- **Dateispeicherung**: E-Mails werden als .eml-Dateien gespeichert
- **Keine externen Abhängigkeiten**: Pure .NET-Implementierung

## Authentifizierungsmechanismen

| Mechanismus | Sicherheit | TLS erforderlich | Beschreibung |
|-------------|------------|------------------|--------------|
| **PLAIN** | Basis | ✓ Ja | Base64-kodiertes Passwort |
| **LOGIN** | Basis | ✓ Ja | Zwei-Schritt Base64 (veraltet) |
| **SCRAM-SHA-256** | Hoch | ✗ Nein | Challenge-Response, kein Passwort übertragen |
| **EXTERNAL** | Sehr hoch | ✓ Ja (mTLS) | Client-Zertifikat-Authentifizierung |

### SCRAM-SHA-256 Vorteile

- Passwort wird **nie** übertragen (auch nicht als Hash)
- Server speichert nur `StoredKey` und `ServerKey`
- Mutual Authentication (Server beweist auch seine Identität)
- Replay-Angriffe durch Nonces verhindert
- Sicher auch ohne TLS (aber TLS empfohlen)

### EXTERNAL (mTLS) Vorteile

- Kein Passwort nötig
- Zertifikat-basierte Authentifizierung
- Ideal für Server-zu-Server-Kommunikation
- Integration mit PKI-Infrastruktur

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

## Benutzer-Verwaltung

Benutzer werden in `mailstore/users.txt` gespeichert:

```
# Format: username:password_sha256:scram_salt:scram_stored_key:scram_server_key:iterations:cert_thumbprints

admin:a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3:SALT:STOREDKEY:SERVERKEY:4096:
certuser:::::::AABBCCDD11223344
```

Beim ersten Start werden automatisch Testbenutzer angelegt:
- `admin` / `test123`
- `user` / `test123`  
- `demo` / `demo`

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
│       ├──► STARTTLS ──► SslStream ──► Client Certificate       │
│       ├──► AUTH ─────► SmtpAuthManager                         │
│       │                    ├──► PlainAuthHandler               │
│       │                    ├──► LoginAuthHandler               │
│       │                    ├──► ScramSha256AuthHandler         │
│       │                    └──► ExternalAuthHandler            │
│       ├──► MAIL FROM                                           │
│       ├──► RCPT TO                                             │
│       └──► DATA ──► EmailMessage.Parse()                       │
│                         │                                       │
│                         ▼                                       │
│              ┌─────────────────────┐                           │
│              │   DnsVerifier       │                           │
│              └─────────────────────┘                           │
│                         │                                       │
│                         ▼                                       │
│              ┌─────────────────────┐                           │
│              │   FileMailStorage   │                           │
│              └─────────────────────┘                           │
└─────────────────────────────────────────────────────────────────┘
```

## SMTP-Befehle

| Befehl | Beschreibung |
|--------|--------------|
| `HELO` | Einfache Begrüßung |
| `EHLO` | Extended HELO mit Capabilities |
| `STARTTLS` | TLS-Verbindung initiieren |
| `AUTH` | Authentifizierung starten |
| `MAIL FROM:` | Absender angeben |
| `RCPT TO:` | Empfänger angeben |
| `DATA` | Nachrichteninhalt senden |
| `RSET` | Transaktion zurücksetzen |
| `NOOP` | Keine Operation |
| `QUIT` | Verbindung beenden |

## AUTH Beispiele

### AUTH PLAIN

```
C: AUTH PLAIN AGFkbWluAHRlc3QxMjM=
S: 235 2.7.0 Authentication successful
```

Der Base64-String enthält: `\0admin\0test123`

### AUTH LOGIN

```
C: AUTH LOGIN
S: 334 VXNlcm5hbWU6
C: YWRtaW4=
S: 334 UGFzc3dvcmQ6
C: dGVzdDEyMw==
S: 235 2.7.0 Authentication successful
```

### AUTH SCRAM-SHA-256

```
C: AUTH SCRAM-SHA-256 biwsbj1hZG1pbixyPWNsaWVudE5vbmNl
S: 334 cj1jbGllbnROb25jZXNlcnZlck5vbmNlLHM9c2FsdCxpPTQwOTY=
C: Yz1iaXdzLHI9Y2xpZW50Tm9uY2VzZXJ2ZXJOb25jZSxwPVByb29m
S: 235 2.7.0 Authentication successful dj1TZXJ2ZXJTaWduYXR1cmU=
```

### AUTH EXTERNAL (mit Client-Zertifikat)

```
C: AUTH EXTERNAL
S: 235 2.7.0 Authentication successful
```

## Client-Zertifikat für EXTERNAL

```bash
# Client-Zertifikat erstellen
openssl req -x509 -newkey rsa:2048 -keyout client.key -out client.crt \
    -days 365 -nodes -subj "/CN=admin"

# Als PKCS#12 exportieren
openssl pkcs12 -export -out client.pfx -inkey client.key -in client.crt

# Thumbprint anzeigen
openssl x509 -in client.crt -fingerprint -sha1 -noout
```

Dann den Thumbprint in `users.txt` eintragen.

## E-Mail-Speicherformat

E-Mails werden mit zusätzlichen Metadaten gespeichert:

```
X-Envelope-From: sender@example.com
X-Envelope-To: recipient@localhost
X-Received-At: 2024-12-23T10:00:00.000Z
X-SPF-Result: Pass
X-DKIM-Result: Pass
X-DMARC-Result: Pass
X-MX-Records: mail.example.com

From: sender@example.com
To: recipient@localhost
Subject: Test
...
```

## Sicherheitshinweise

⚠️ **Produktionsempfehlungen:**

1. **Ports**: Verwende die Standardports 25 und 587 (erfordert Root/Admin)
2. **TLS**: Aktiviere `RequireStartTls = true` für Produktion
3. **Zertifikat**: Verwende ein gültiges Zertifikat (Let's Encrypt)
4. **AUTH**: SCRAM-SHA-256 oder EXTERNAL bevorzugen
5. **Firewall**: Beschränke Zugriff auf vertrauenswürdige IPs

## Erweiterungsmöglichkeiten

- [ ] DMARC-Alignment-Prüfung
- [ ] ARC (Authenticated Received Chain)
- [ ] Greylisting
- [ ] XOAUTH2 / OAUTHBEARER
- [ ] SMTP-Relay mit AUTH
- [ ] Maildir-Format
- [ ] Queue-System für Retry
- [ ] Prometheus-Metriken

## Lizenz

MIT License

---

Erstellt für Achim's EU-Regulierungs- und Infrastruktur-Projekte.
