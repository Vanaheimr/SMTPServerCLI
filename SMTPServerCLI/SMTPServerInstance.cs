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

#region Usings

using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SMTP.Server;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SMTP.CLI
{

    /// <summary>
    /// One running SMTP server: the listeners, the outbound queue and what
    /// drains it, DKIM signing, the optional reporting - and the files all of
    /// that lives in.
    /// </summary>
    /// <remarks>
    /// Everything the command line can be asked about is reachable from here,
    /// so that a command is a way of looking at this and never a second
    /// implementation of it.
    /// </remarks>
    public sealed class SMTPServerInstance : IAsyncDisposable
    {

        #region Data

        /// <summary>
        /// The account the first start makes up, where there are none.
        /// </summary>
        public const String FirstAccountName = "admin";

        private readonly  CancellationTokenSource  stopping  = new();
        private           SMTPServer?              server;
        private           Task?                    serverTask;

        #endregion

        #region Properties

        /// <summary>What this start runs with.</summary>
        public ServerSettings          Settings                 { get; }

        /// <summary>The log on the console.</summary>
        public CLILogger               Logger                   { get; }

        /// <summary>The name servers SPF, DKIM, DMARC, MX and DANE are asked through.</summary>
        public DNSClient               DNSClient                { get; } = new();

        /// <summary>The accounts the server authenticates.</summary>
        public UsersFile               Users                    { get; }

        /// <summary>The outbound queue.</summary>
        public FileMailQueue           MailQueue                { get; private set; } = null!;

        /// <summary>What drains the outbound queue.</summary>
        public QueueProcessor          QueueProcessor           { get; private set; } = null!;

        /// <summary>How the command line sends mail: through the queue, DKIM-signed on its way out.</summary>
        public MailSender              MailSender               { get; private set; } = null!;

        /// <summary>Outbound TLS reporting (RFC 8460), where it is switched on.</summary>
        public TlsRptReportService?    TlsRptService            { get; private set; }

        /// <summary>The server's certificate file, generated or given.</summary>
        public String                  CertificatePath          { get; private set; } = "";

        /// <summary>The server's certificate, for the banner and status.</summary>
        public X509Certificate2?       Certificate              { get; private set; }

        /// <summary>Whether the certificate is self-signed - generated on a first start, most likely.</summary>
        public Boolean                 CertificateSelfSigned    { get; private set; }

        /// <summary>The private DKIM key.</summary>
        public String                  DkimPrivateKeyPath
            => Path.Combine(Settings.ConfigDirectory, $"dkim_{Settings.DkimSelector}.private.pem");

        /// <summary>The password made up at the first start, to be shown once; null on any other.</summary>
        public String?                 FirstAccountPassword     { get; private set; }

        /// <summary>What the first start had to generate, line by line, for the banner.</summary>
        public List<String>            Generated                { get; } = [];

        /// <summary>When the server started answering.</summary>
        public DateTimeOffset          StartedAt                { get; private set; }

        /// <summary>Whether its listeners are still accepting.</summary>
        public Boolean                 IsRunning
            => serverTask is { IsCompleted: false };

        #endregion

        #region Constructor(s)

        /// <summary>
        /// A server with the given settings, not yet started.
        /// </summary>
        /// <param name="Settings">What it runs with.</param>
        /// <param name="Logger">Its log.</param>
        public SMTPServerInstance(ServerSettings  Settings,
                                  CLILogger       Logger)
        {

            this.Settings  = Settings;
            this.Logger    = Logger;
            this.Users     = new UsersFile(Settings.UsersFilePath);

        }

        #endregion


        #region Start()

        /// <summary>
        /// Generate what a first start needs, build the server and its queue,
        /// and bind the listeners. Throws where a port cannot be bound or a file
        /// cannot be read - the server is then not running.
        /// </summary>
        public async Task Start()
        {

            Directory.CreateDirectory(Settings.ConfigDirectory);
            Directory.CreateDirectory(Settings.MailStoragePath);

            #region TLS certificate - the one given, or a self-signed one generated on the first start

            if (Settings.CertificatePath is String given)
                CertificatePath = Path.GetFullPath(given);

            else
            {

                CertificatePath = Path.Combine(Settings.ConfigDirectory, "server.pfx");

                if (!File.Exists(CertificatePath))
                {
                    GenerateSelfSignedCertificate(CertificatePath, Settings.CertificatePassword, Settings.Hostname);
                    Generated.Add($"a self-signed TLS certificate for '{Settings.Hostname}': {CertificatePath}");
                }

            }

            Certificate           = X509CertificateLoader.LoadPkcs12FromFile(CertificatePath, Settings.CertificatePassword);
            CertificateSelfSigned = Certificate.Subject == Certificate.Issuer;

            #endregion

            #region DKIM key pair - generated on the first start

            if (!File.Exists(DkimPrivateKeyPath))
            {
                DkimKeyGenerator.SaveKeyPair(Settings.ConfigDirectory, Settings.DkimDomain, Settings.DkimSelector);
                Generated.Add($"a DKIM key pair for selector '{Settings.DkimSelector}': {DkimPrivateKeyPath}");
            }

            var dkimSigner = new DkimSigner(new DkimConfig {
                                 Domain         = Settings.DkimDomain,
                                 Selector       = Settings.DkimSelector,
                                 PrivateKeyPem  = await File.ReadAllTextAsync(DkimPrivateKeyPath)
                             }, Logger);

            #endregion

            #region Accounts - one with a made-up password, rather than none

            // Before the server is made: Hermod writes a users.txt without
            // accounts where it finds none - a server nobody can submit to -
            // and leaves one it finds alone.
            if (Users.CreateWithFirstAccount(FirstAccountName, out var password))
                FirstAccountPassword = password;

            #endregion

            #region Server configuration

            var smtpServerConfig = new SMTPServerConfig {

                Hostname                 = Settings.Hostname,
                Port                     = Settings.Port,
                SubmissionPort           = Settings.SubmissionPort,
                ImplicitTlsPort          = Settings.ImplicitTlsPort,
                MailStoragePath          = Settings.MailStoragePath,
                CertificatePath          = CertificatePath,
                CertificatePassword      = Settings.CertificatePassword,
                RequireStartTls          = Settings.RequireStartTls,
                VerifyDkim               = Settings.VerifyDkim,
                VerifySpf                = Settings.VerifySpf,
                VerifyDmarc              = Settings.VerifyDmarc,
                MaxMessageSize           = Configuration.MaxMessageSize,
                MaxRecipients            = Configuration.MaxRecipients,
                SessionTimeout           = Configuration.SessionTimeout,

                // Mail to local domains is stored locally; anything else is relay and requires authentication.
                LocalDomains             = LocalDomains(Settings.LocalDomains),
                RequireAuthForRelay      = Configuration.RequireAuthForRelay,
                RequireAuthOnSubmission  = Configuration.RequireAuthOnSubmission,

                EnableDmarcReporting     = Configuration.EnableDmarcReporting,
                EnableDmarcForensic      = Configuration.EnableDmarcForensic,
                DmarcReportEmail         = Configuration.DmarcReportEmail   ?? $"dmarc-reports@{Settings.Hostname}",
                DmarcReportOrgName       = Configuration.DmarcReportOrgName ?? Settings.Hostname,
                DmarcReportInterval      = Configuration.ReportingInterval,

                EnableTlsRptIngestion    = Configuration.EnableTlsRptIngestion,
                EnableAutoMdn            = Configuration.EnableAutoMdn

            };

            var rateLimitConfig = new RateLimitConfig {
                MaxTotalConnections           = Configuration.MaxTotalConnections,
                MaxConnectionsPerIp           = Configuration.MaxConnectionsPerIp,
                MaxConnectionsPerIpPerMinute  = Configuration.MaxConnectionsPerIpPerMinute,
                MaxAuthAttemptsPerIpPerHour   = Configuration.MaxAuthAttemptsPerIpPerHour,
                MaxMessagesPerIpPerHour       = Configuration.MaxMessagesPerIpPerHour,
                MaxInvalidCommands            = Configuration.MaxInvalidCommands,
                AuthFailDelayMs               = Configuration.AuthFailDelayMs
            };

            #endregion

            #region Outbound queue, relay client and reporting

            MailQueue = new FileMailQueue(Settings.MailStoragePath, Logger);

            var outboundConfig = new SmtpOutboundConfig {
                LocalHostname      = Settings.Hostname,
                PreferStartTls     = Configuration.OutboundPreferStartTls,
                RequireStartTls    = Configuration.OutboundRequireStartTls,
                EnableDane         = Configuration.EnableDane,
                SmartHost          = Settings.SmartHost,
                SmartHostPort      = Settings.SmartHostPort,
                SmartHostUsername  = Settings.SmartHostUsername,
                SmartHostPassword  = Settings.SmartHostPassword
            };

            // TLS-RPT (RFC 8460) outbound reporting.
            if (Configuration.EnableTlsRptReporting)
            {

                var tlsRptEmail   = Configuration.TlsRptReportEmail ?? $"tls-reports@{Settings.Hostname}";
                var tlsRptOptions = new TlsRptReportingOptions(
                                        OrgName:            Configuration.TlsRptReportOrgName ?? Settings.Hostname,
                                        ReportFromDisplay:  $"TLS Reports <{tlsRptEmail}>",
                                        ReportFromAddress:  tlsRptEmail,
                                        ReportingDomain:    Settings.Hostname,
                                        ContactInfo:        $"postmaster@{Settings.Hostname}",
                                        Interval:           Configuration.ReportingInterval
                                    );

                TlsRptService = new TlsRptReportService(
                                    new TlsRptAggregator(Path.Combine(Settings.MailStoragePath, "tlsrpt-state.json"), Logger),
                                    new TlsRptResolver(DNSClient, Logger),
                                    MailQueue,
                                    tlsRptOptions,
                                    Logger
                                );

            }

            var outboundClient  = new SMTPOutboundClient(outboundConfig, dkimSigner, DNSClient, Logger,
                                                         TlsRptService is not null ? TlsRptService.Record : null);

            QueueProcessor      = new QueueProcessor(
                                      MailQueue,
                                      outboundClient,
                                      new BounceHandler(smtpServerConfig, MailQueue, Logger),
                                      new QueueProcessorConfig {
                                          MaxConcurrentDeliveries  = Configuration.MaxConcurrentDeliveries,
                                          MaxDeliveriesPerDomain   = Configuration.MaxDeliveriesPerDomain,
                                          SendDelayNotifications   = Configuration.SendDelayNotifications
                                      },
                                      Logger
                                  );

            MailSender          = new MailSender(MailQueue, Logger, outboundClient);

            #endregion

            #region Start-up

            server = new SMTPServer(
                         smtpServerConfig,
                         DNSClient,
                         logger:           Logger,
                         userStore:        new PinnedCertificateUserStore(Users),
                         mailQueue:        MailQueue,
                         rateLimitConfig:  rateLimitConfig
                     );

            await QueueProcessor.StartAsync(stopping.Token);

            if (TlsRptService is not null)
                _ = TlsRptService.RunAsync(stopping.Token);

            // Everything up to the listeners is bound before Start first
            // awaits, so a port somebody else has is a faulted task by now -
            // and a server that did not start says so here rather than later.
            serverTask = server.Start(stopping.Token);

            if (serverTask.IsFaulted)
                await serverTask;

            StartedAt = Timestamp.Now;

            #endregion

        }

        #endregion

        #region Listeners

        /// <summary>
        /// Where the server answers, and what: the MTA port, the submission
        /// port and - with a certificate - the implicit-TLS port.
        /// </summary>
        public IEnumerable<(String Label, String Value)> Listeners()
        {

            yield return ("SMTP (MTA)",    $"port {Settings.Port}, all addresses - mail from other servers" +
                                           (Settings.RequireStartTls ? ", STARTTLS required" : ", STARTTLS offered"));

            yield return ("submission",    $"port {Settings.SubmissionPort} - clients, STARTTLS, " +
                                           (Configuration.RequireAuthOnSubmission ? "authentication required" : "authentication optional"));

            yield return ("SMTPS",         Certificate is not null
                                               ? $"port {Settings.ImplicitTlsPort} - clients, TLS from the first byte"
                                               : "off - no certificate");

        }

        #endregion

        #region BuiltFrom()

        /// <summary>
        /// What this was built from: each repository's assembly with the commit
        /// its build stamped into it - see Directory.Build.props.
        /// </summary>
        public static IEnumerable<String> BuiltFrom()
        {

            foreach (var assembly in new[] { typeof(Program).Assembly,
                                             typeof(SMTPServer).Assembly,
                                             typeof(org.GraphDefined.Vanaheimr.CLI.ICLI).Assembly })
            {

                var metadata    = assembly.GetCustomAttributes<AssemblyMetadataAttribute>().ToArray();
                var repository  = metadata.FirstOrDefault(entry => entry.Key == "GitRepository")?.Value ?? assembly.GetName().Name;
                var commit      = metadata.FirstOrDefault(entry => entry.Key == "GitCommit")?.    Value ?? "unknown";

                yield return $"{repository,-15}{commit}";

            }

        }

        #endregion


        #region (static) LocalDomains(Domains)

        /// <summary>
        /// The local domains as the server compares them, with localhost always among them.
        /// </summary>
        public static HashSet<String> LocalDomains(IEnumerable<String> Domains)
        {

            var result = Domains.Select (domain => domain.Trim().TrimEnd('.').ToLowerInvariant()).
                                 Where  (domain => !String.IsNullOrEmpty(domain)).
                                 ToHashSet();

            // Always deliver localhost mail locally.
            result.Add("localhost");
            result.Add("localhost.localdomain");

            return result;

        }

        #endregion

        #region (private static) GenerateSelfSignedCertificate(Path, Password, Hostname)

        private static void GenerateSelfSignedCertificate(String Path, String Password, String Hostname)
        {

            using var rsa = RSA.Create(4096);

            var request = new CertificateRequest(
                              $"CN={Hostname}",
                              rsa,
                              HashAlgorithmName.SHA256,
                              RSASignaturePadding.Pkcs1
                          );

            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(false, false, 0, false)
            );

            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                    false
                )
            );

            request.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(
                    [new("1.3.6.1.5.5.7.3.1")],   // Server Authentication
                    critical: false
                )
            );

            var sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddDnsName(Hostname);
            sanBuilder.AddDnsName("localhost");
            sanBuilder.AddIpAddress(System.Net.IPAddress.Loopback);
            sanBuilder.AddIpAddress(System.Net.IPAddress.IPv6Loopback);
            request.CertificateExtensions.Add(sanBuilder.Build());

            using var cert = request.CreateSelfSigned(
                                 DateTimeOffset.UtcNow.AddDays(-1),
                                 DateTimeOffset.UtcNow.AddYears(1)
                             );

            File.WriteAllBytes(Path, cert.Export(X509ContentType.Pfx, Password));

        }

        #endregion


        #region DisposeAsync()

        /// <summary>
        /// Stop accepting, let the sessions that are running finish, stop the
        /// queue - what is in it stays on disk for the next start - and let go
        /// of the files.
        /// </summary>
        public async ValueTask DisposeAsync()
        {

            await stopping.CancelAsync();

            if (server is not null)
                await server.DisposeAsync();

            if (QueueProcessor is not null)
                await QueueProcessor.DisposeAsync();

            MailQueue?.Dispose();
            Certificate?.Dispose();
            stopping.Dispose();

        }

        #endregion

    }

}
