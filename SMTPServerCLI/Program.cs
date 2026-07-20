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

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SMTP.Server;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SMTP.CLI
{

    /// <summary>
    /// Entry point for a fully self-contained SMTP server instance.
    ///
    /// All configuration lives in <see cref="Configuration"/> (there are NO environment variables),
    /// and the crypto material (TLS certificate + DKIM key pair) is generated on first run into the
    /// repo-tracked <c>config/</c> folder, so a fresh clone runs with a single <c>dotnet run</c>.
    /// </summary>
    public static class Program
    {

        #region (private) ParseLocalDomains(Domains)

        private static HashSet<String> ParseLocalDomains(IEnumerable<String> Domains)
        {

            var result = Domains.Select(d => d.Trim().ToLowerInvariant())
                                .Where(d => !String.IsNullOrEmpty(d))
                                .ToHashSet();

            // Always deliver localhost mail locally.
            result.Add("localhost");
            result.Add("localhost.localdomain");

            return result;

        }

        #endregion

        #region (private) GenerateSelfSignedCertificate(Path, Password, Hostname)

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

            System.IO.File.WriteAllBytes(Path, cert.Export(X509ContentType.Pfx, Password));

        }

        #endregion


        #region Main(args)

        public static async Task Main(String[] args)
        {

            var logger      = new ConsoleLogger();
            var dnsClient   = new DNSClient();

            var configDir   = Configuration.ConfigDirectory;
            var mailStore   = Configuration.MailStoragePath;

            Directory.CreateDirectory(configDir);
            Directory.CreateDirectory(mailStore);


            #region TLS certificate — generate a self-signed one on first run

            var certPath      = Path.Combine(configDir, "server.pfx");
            var certPassword  = Configuration.CertificatePassword;

            if (!File.Exists(certPath)) {
                Console.WriteLine($"Generating self-signed TLS certificate for '{Configuration.Hostname}'...");
                GenerateSelfSignedCertificate(certPath, certPassword, Configuration.Hostname);
                Console.WriteLine($"  → {certPath}  (replace with a real certificate for production)");
            }

            #endregion

            #region DKIM key pair — generate on first run, then sign outbound mail

            var dkimKeyPath = Path.Combine(configDir, $"dkim_{Configuration.DkimSelector}.private.pem");

            if (!File.Exists(dkimKeyPath)) {
                Console.WriteLine($"Generating DKIM key pair for '{Configuration.DkimDomain}' (selector '{Configuration.DkimSelector}')...");
                DkimKeyGenerator.SaveKeyPair(configDir, Configuration.DkimDomain, Configuration.DkimSelector);
                Console.WriteLine($"  → {dkimKeyPath}");
                Console.WriteLine($"  → publish the DNS TXT record from: {Path.Combine(configDir, $"dkim_{Configuration.DkimSelector}.dns.txt")}");
            }

            var dkimSigner = new DkimSigner(new DkimConfig {
                                 Domain         = Configuration.DkimDomain,
                                 Selector       = Configuration.DkimSelector,
                                 PrivateKeyPem  = File.ReadAllText(dkimKeyPath)
                             }, logger);

            #endregion


            #region Server configuration

            var smtpServerConfig = new SMTPServerConfig {

                Hostname                 = Configuration.Hostname,
                Port                     = Configuration.Port,
                SubmissionPort           = Configuration.SubmissionPort,
                ImplicitTlsPort          = Configuration.ImplicitTlsPort,
                MailStoragePath          = mailStore,
                CertificatePath          = certPath,
                CertificatePassword      = certPassword,
                RequireStartTls          = Configuration.RequireStartTls,
                VerifyDkim               = Configuration.VerifyDkim,
                VerifySpf                = Configuration.VerifySpf,
                VerifyDmarc              = Configuration.VerifyDmarc,
                MaxMessageSize           = Configuration.MaxMessageSize,
                MaxRecipients            = Configuration.MaxRecipients,
                SessionTimeout           = Configuration.SessionTimeout,

                // Mail to local domains is stored locally; anything else is relay and requires authentication.
                LocalDomains             = ParseLocalDomains(Configuration.LocalDomains),
                RequireAuthForRelay      = Configuration.RequireAuthForRelay,
                RequireAuthOnSubmission  = Configuration.RequireAuthOnSubmission,

                EnableDmarcReporting     = Configuration.EnableDmarcReporting,
                EnableDmarcForensic      = Configuration.EnableDmarcForensic,
                DmarcReportEmail         = Configuration.DmarcReportEmail   ?? $"dmarc-reports@{Configuration.Hostname}",
                DmarcReportOrgName       = Configuration.DmarcReportOrgName ?? Configuration.Hostname,

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

            var mailQueue = new FileMailQueue(mailStore, logger);

            var outboundConfig = new SmtpOutboundConfig {
                LocalHostname      = Configuration.Hostname,
                PreferStartTls     = Configuration.OutboundPreferStartTls,
                RequireStartTls    = Configuration.OutboundRequireStartTls,
                EnableDane         = Configuration.EnableDane,
                SmartHost          = Configuration.SmartHost,
                SmartHostPort      = Configuration.SmartHostPort,
                SmartHostUsername  = Configuration.SmartHostUsername,
                SmartHostPassword  = Configuration.SmartHostPassword
            };

            // TLS-RPT (RFC 8460) outbound reporting.
            TlsRptReportService? tlsRptService = null;
            if (Configuration.EnableTlsRptReporting) {

                var tlsRptEmail   = Configuration.TlsRptReportEmail ?? $"tls-reports@{Configuration.Hostname}";
                var tlsRptOptions = new TlsRptReportingOptions(
                                        OrgName:           Configuration.TlsRptReportOrgName ?? Configuration.Hostname,
                                        ReportFromDisplay: $"TLS Reports <{tlsRptEmail}>",
                                        ReportFromAddress: tlsRptEmail,
                                        ReportingDomain:   Configuration.Hostname,
                                        ContactInfo:       $"postmaster@{Configuration.Hostname}",
                                        Interval:          Configuration.ReportingInterval);

                var tlsRptAggregator = new TlsRptAggregator(Path.Combine(mailStore, "tlsrpt-state.json"), logger);
                var tlsRptResolver   = new TlsRptResolver(dnsClient, logger);
                tlsRptService        = new TlsRptReportService(tlsRptAggregator, tlsRptResolver, mailQueue, tlsRptOptions, logger);

            }

            var outboundClient = new SMTPOutboundClient(outboundConfig, dkimSigner, dnsClient, logger,
                                                        tlsRptService is not null ? tlsRptService.Record : null);

            var bounceHandler  = new BounceHandler(smtpServerConfig, mailQueue, logger);

            var queueProcessor = new QueueProcessor(mailQueue, outboundClient, bounceHandler, new QueueProcessorConfig {
                                     MaxConcurrentDeliveries  = Configuration.MaxConcurrentDeliveries,
                                     MaxDeliveriesPerDomain   = Configuration.MaxDeliveriesPerDomain,
                                     SendDelayNotifications   = Configuration.SendDelayNotifications
                                 }, logger);

            #endregion


            Console.WriteLine($"""

                Hermod SMTP server — self-contained configuration (edit Configuration.cs)

                  Hostname:       {smtpServerConfig.Hostname}
                  SMTP Port:      {smtpServerConfig.Port}
                  Submission:     {smtpServerConfig.SubmissionPort}
                  Implicit TLS:   {(smtpServerConfig.EnableImplicitTls && smtpServerConfig.CertificatePath is not null ? smtpServerConfig.ImplicitTlsPort.ToString() : "off")}
                  Local Domains:  {String.Join(", ", smtpServerConfig.LocalDomains)}
                  Config folder:  {configDir}
                  Mail Storage:   {Path.GetFullPath(smtpServerConfig.MailStoragePath)}
                  TLS Available:  {smtpServerConfig.CertificatePath is not null}
                  Require TLS:    {smtpServerConfig.RequireStartTls}
                  Verify DKIM:    {smtpServerConfig.VerifyDkim}
                  Verify SPF:     {smtpServerConfig.VerifySpf}
                  Verify DMARC:   {smtpServerConfig.VerifyDmarc}
                  DKIM Signing:   on ({Configuration.DkimSelector}._domainkey.{Configuration.DkimDomain})
                  DMARC Reports:  {(smtpServerConfig.EnableDmarcReporting ? $"on (forensic={smtpServerConfig.EnableDmarcForensic})" : "off")}
                  TLS-RPT Ingest: {(smtpServerConfig.EnableTlsRptIngestion ? "on (RFC 8460 inbound)" : "off")}
                  Smarthost:      {outboundConfig.SmartHost ?? "(direct delivery)"}
                  DANE (out):     {(outboundConfig.EnableDane ? "on (RFC 7672, DNSSEC TLSA)" : "off")}
                  TLS-RPT (out):  {(tlsRptService is not null ? "on (RFC 8460)" : "off")}
                  Auto-MDN:       {(smtpServerConfig.EnableAutoMdn ? "on" : "off")}
                  Relay Auth:     Required (prevents open relay)
                """);


            #region Start-up and graceful shutdown

            await using var server = new SMTPServer(
                                         smtpServerConfig,
                                         dnsClient,
                                         logger:          logger,
                                         mailQueue:       mailQueue,
                                         rateLimitConfig: rateLimitConfig
                                     );

            var cts = new CancellationTokenSource();

            Console.CancelKeyPress += (_, e) => {
                e.Cancel = true;
                Console.WriteLine("\nShutdown requested...");
                cts.Cancel();
            };

            AppDomain.CurrentDomain.ProcessExit += (_, _) => {
                cts.Cancel();
            };

            try {

                await queueProcessor.StartAsync(cts.Token);

                if (tlsRptService is not null)
                    _ = tlsRptService.RunAsync(cts.Token);

                await server.Start(cts.Token);

            }
            catch (OperationCanceledException) {
                Console.WriteLine("Server stopped gracefully.");
            }
            finally {
                await queueProcessor.DisposeAsync();
                mailQueue.Dispose();
            }

            #endregion

        }

        #endregion

    }

}
