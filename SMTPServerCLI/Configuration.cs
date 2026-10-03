/*
 * Copyright (c) 2010-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr Hermod <https://www.github.com/Vanaheimr/Hermod>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace org.GraphDefined.Vanaheimr.Hermod.SMTP.CLI
{

    /// <summary>
    /// The defaults of this SMTP server instance.
    ///
    /// Everything the server needs lives here in the repository - there are NO environment variables
    /// to set on the host. To change a default for good, edit the values below and rebuild; to change
    /// one for a single start, the switches (-h lists them) override the most common ones - hostname,
    /// local domains, ports, certificate, DKIM domain/selector, smarthost, folders and the console
    /// log level - without writing them anywhere. Crypto material (the TLS certificate and the DKIM
    /// key pair) is generated on first run into the repo-tracked <c>config/</c> folder and can then be
    /// committed; see <see cref="ServerSettings.ConfigDirectory"/>.
    /// </summary>
    public static class Configuration
    {

        #region Identity & ports

        /// <summary>The public hostname — used in the SMTP banner, EHLO/HELO, Received headers, and as the DKIM/report default domain.</summary>
        public const String    Hostname               = "localhost";

        // Defaults are the non-privileged 2525/2587/2465 so the server runs anywhere without root.
        // For a real Internet-facing server change these to the standard 25 / 587 / 465 (needs elevated
        // privileges or a capability such as `setcap 'cap_net_bind_service=+ep'`, or a port-forward).
        /// <summary>MTA port (inbound mail from other servers). Production: 25.</summary>
        public const UInt16    Port                   = 2525;

        /// <summary>Message submission port (authenticated clients, STARTTLS). Production: 587.</summary>
        public const UInt16    SubmissionPort         = 2587;

        /// <summary>Implicit-TLS submission port (TLS from the first byte). Production: 465. Only bound when a certificate exists.</summary>
        public const UInt16    ImplicitTlsPort        = 2465;

        #endregion

        #region Local delivery & relay

        /// <summary>
        /// Domains delivered locally (stored as .eml). Mail to any other domain is treated as relay and
        /// requires authentication (see <see cref="RequireAuthForRelay"/>) — never an open relay.
        /// "localhost" and "localhost.localdomain" are always added.
        /// </summary>
        public static readonly String[]  LocalDomains = [ "localhost" ];

        /// <summary>Require authentication before relaying to non-local domains. MUST stay true to prevent an open relay.</summary>
        public const Boolean   RequireAuthForRelay    = true;

        /// <summary>Require authentication on the submission port (RFC 6409).</summary>
        public const Boolean   RequireAuthOnSubmission = true;

        #endregion

        #region Transport security (TLS)

        /// <summary>Refuse to accept mail until STARTTLS has been negotiated. Off by default so plaintext peers still interoperate.</summary>
        public const Boolean   RequireStartTls        = false;

        /// <summary>
        /// Password protecting the generated <c>config/server.pfx</c>. A self-signed certificate is
        /// generated on first run; replace it with a real certificate (e.g. Let's Encrypt) for the MX
        /// hostname before exposing the server to the Internet.
        /// </summary>
        public const String    CertificatePassword    = "smtp-test-password";

        #endregion

        #region Inbound authentication checks (SPF / DKIM / DMARC)

        // False skips the check; the stored .eml then records "none" for it.
        public const Boolean   VerifyDkim             = true;
        public const Boolean   VerifySpf              = true;
        public const Boolean   VerifyDmarc            = true;

        #endregion

        #region Outbound DKIM signing

        /// <summary>DKIM <c>d=</c> domain for outgoing mail. Defaults to the hostname.</summary>
        public const String    DkimDomain             = Hostname;

        /// <summary>DKIM selector (<c>s=</c>). The public key must be published at <c>&lt;selector&gt;._domainkey.&lt;domain&gt;</c> — see <c>config/dkim_&lt;selector&gt;.dns.txt</c>.</summary>
        public const String    DkimSelector           = "default";

        #endregion

        #region Message limits

        public const Int32     MaxMessageSize         = 25 * 1024 * 1024;   // 25 MiB
        public const Int32     MaxRecipients          = 100;

        #endregion

        #region Outbound delivery / smarthost

        /// <summary>Prefer STARTTLS on outbound relay (opportunistic). </summary>
        public const Boolean   OutboundPreferStartTls = true;

        /// <summary>Require STARTTLS on outbound relay (refuse cleartext delivery). Off = opportunistic.</summary>
        public const Boolean   OutboundRequireStartTls = false;

        /// <summary>DANE/TLSA (RFC 7672): DNSSEC-validated certificate pinning for outbound delivery.</summary>
        public const Boolean   EnableDane             = false;

        /// <summary>Optional smarthost to relay all outbound mail through. Null = direct-to-MX delivery.</summary>
        public const String?   SmartHost              = null;
        public const UInt16    SmartHostPort          = 25;
        public const String?   SmartHostUsername      = null;
        public const String?   SmartHostPassword      = null;

        #endregion

        #region Receipts (MDN)

        /// <summary>Auto-generate a read receipt (MDN) on local delivery when the message requested one. Privacy-sensitive (RFC 8098 §2.1).</summary>
        public const Boolean   EnableAutoMdn          = false;

        #endregion

        #region DMARC reporting (RFC 7489 §7) — opt-in

        public const Boolean   EnableDmarcReporting   = false;
        public const Boolean   EnableDmarcForensic    = false;
        /// <summary>From/return-path for DMARC reports. Null → <c>dmarc-reports@&lt;hostname&gt;</c>.</summary>
        public const String?   DmarcReportEmail       = null;
        /// <summary><c>org_name</c> in DMARC reports. Null → the hostname.</summary>
        public const String?   DmarcReportOrgName     = null;

        #endregion

        #region SMTP TLS Reporting (RFC 8460) — opt-in

        /// <summary>Emit outbound TLS-RPT aggregate reports about our own outbound TLS sessions.</summary>
        public static readonly Boolean EnableTlsRptReporting = false;
        /// <summary>Ingest inbound TLS-RPT reports delivered to our reporting mailbox.</summary>
        public const Boolean   EnableTlsRptIngestion  = false;
        /// <summary>From/return-path for outbound TLS reports. Null → <c>tls-reports@&lt;hostname&gt;</c>.</summary>
        public const String?   TlsRptReportEmail      = null;
        /// <summary><c>organization-name</c> in outbound TLS reports. Null → the hostname.</summary>
        public const String?   TlsRptReportOrgName    = null;

        #endregion

        #region Connection rate limiting

        public const Int32     MaxTotalConnections          = 100;
        public const Int32     MaxConnectionsPerIp          = 10;
        public const Int32     MaxConnectionsPerIpPerMinute = 30;
        public const Int32     MaxAuthAttemptsPerIpPerHour  = 10;
        public const Int32     MaxMessagesPerIpPerHour      = 50;
        public const Int32     MaxInvalidCommands           = 5;
        public const Int32     AuthFailDelayMs              = 3000;

        #endregion

        #region Outbound queue processor

        public const Int32     MaxConcurrentDeliveries      = 10;
        public const Int32     MaxDeliveriesPerDomain       = 5;
        public const Boolean   SendDelayNotifications       = true;

        #endregion

        #region Session

        public static readonly TimeSpan  SessionTimeout      = TimeSpan.FromMinutes(5);
        public static readonly TimeSpan  ReportingInterval   = TimeSpan.FromHours(24);

        #endregion

    }

}
