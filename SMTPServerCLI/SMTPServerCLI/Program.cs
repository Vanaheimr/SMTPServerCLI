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
using org.GraphDefined.Vanaheimr.Hermod.SMTP.New;

#endregion


// Generate self-signed certificate for testing if not exists
var certPath      = Path.Combine(AppContext.BaseDirectory, "server.pfx");
var certPassword  = "smtp-test-password";

if (!File.Exists(certPath))
{
    Console.WriteLine("Generating self-signed certificate for STARTTLS...");
    GenerateSelfSignedCertificate(certPath, certPassword, "localhost");
    Console.WriteLine($"Certificate saved to: {certPath}");
}

var dnsClient         = new DNSClient();
var hostname          = Environment.GetEnvironmentVariable("SMTP_HOSTNAME")  ?? "localhost";
var mailStoragePath   = Environment.GetEnvironmentVariable("SMTP_MAIL_PATH") ?? "./mailstore";

// Configure the server
var smtpServerConfig  = new SMTPServerConfig {

                            Hostname                 = hostname,
                            Port                     = UInt16.TryParse(Environment.GetEnvironmentVariable("SMTP_PORT"),               out var p)   ? p   : (UInt16) 2525,
                            SubmissionPort           = UInt16.TryParse(Environment.GetEnvironmentVariable("SMTP_SUBMISSION_PORT"),    out var sp)  ? sp  : (UInt16) 2587,
                            ImplicitTlsPort          = UInt16.TryParse(Environment.GetEnvironmentVariable("SMTP_IMPLICIT_TLS_PORT"),  out var ip)  ? ip  : (UInt16) 2465,
                            MailStoragePath          = mailStoragePath,
                            CertificatePath          = certPath,
                            CertificatePassword      = certPassword,
                            RequireStartTls          = false,
                            VerifyDkim               = true,
                            VerifySpf                = true,
                            VerifyDmarc              = true,
                            MaxMessageSize           = 25 * 1024 * 1024,
                            MaxRecipients            = 100,
                            SessionTimeout           = TimeSpan.FromMinutes(5),

                            // Local domains - mail to these is stored locally
                            // Mail to other domains requires authentication (relay)
                            LocalDomains             = ParseLocalDomains(Environment.GetEnvironmentVariable("SMTP_LOCAL_DOMAINS") ?? hostname),
                            RequireAuthForRelay      = true,   // MUST be true to prevent open relay!
                            RequireAuthOnSubmission  = true

                        };

var logger = new ConsoleLogger();

// Rate limiting configuration
var rateLimitConfig = new RateLimitConfig {
                          MaxTotalConnections           = 100,
                          MaxConnectionsPerIp           = 10,
                          MaxConnectionsPerIpPerMinute  = 30,
                          MaxAuthAttemptsPerIpPerHour   = 10,
                          MaxMessagesPerIpPerHour       = 50,
                          MaxInvalidCommands            = 5,
                          AuthFailDelayMs               = 3000
                      };

// Setup DKIM signer (optional)
DkimSigner? dkimSigner = null;
var dkimKeyPath   = Path.Combine(mailStoragePath, "dkim_default.private.pem");
var dkimDomain    = Environment.GetEnvironmentVariable("DKIM_DOMAIN")   ?? hostname;
var dkimSelector  = Environment.GetEnvironmentVariable("DKIM_SELECTOR") ?? "default";

if (File.Exists(dkimKeyPath))
{
    var privateKeyPem = File.ReadAllText(dkimKeyPath);
    dkimSigner = new DkimSigner(new DkimConfig {
        Domain         = dkimDomain,
        Selector       = dkimSelector,
        PrivateKeyPem  = privateKeyPem
    }, logger);
}
else
{

    Console.WriteLine($"No DKIM key found at {dkimKeyPath}");
    Console.WriteLine($"Generate with: DkimKeyGenerator.SaveKeyPair(\"{mailStoragePath}\", \"{dkimDomain}\", \"{dkimSelector}\")");

    // Auto-generate DKIM keys for testing
    if (Environment.GetEnvironmentVariable("DKIM_AUTO_GENERATE") == "true")
    {
        Console.WriteLine("Auto-generating DKIM keys...");
        DkimKeyGenerator.SaveKeyPair(mailStoragePath, dkimDomain, dkimSelector);
        var privateKeyPem = File.ReadAllText(dkimKeyPath);
        dkimSigner = new DkimSigner(new DkimConfig {
            Domain         = dkimDomain,
            Selector       = dkimSelector,
            PrivateKeyPem  = privateKeyPem
        }, logger);
        Console.WriteLine($"DKIM keys generated. Add DNS record from: {Path.Combine(mailStoragePath, $"dkim_{dkimSelector}.dns.txt")}");
    }

}

// Setup mail queue
var mailQueue = new FileMailQueue(mailStoragePath, logger);

// Setup outbound client
var outboundConfig = new SmtpOutboundConfig {
    LocalHostname      = hostname,
    PreferStartTls     = true,
    RequireStartTls    = false,
    SmartHost          =                 Environment.GetEnvironmentVariable("SMTP_SMARTHOST"),
    SmartHostPort      = UInt16.TryParse(Environment.GetEnvironmentVariable("SMTP_SMARTHOST_PORT"), out var shp) ? shp : (UInt16) 25,
    SmartHostUsername  =                 Environment.GetEnvironmentVariable("SMTP_SMARTHOST_USER"),
    SmartHostPassword  =                 Environment.GetEnvironmentVariable("SMTP_SMARTHOST_PASS")
};

var outboundClient = new SMTPOutboundClient(outboundConfig, dkimSigner, dnsClient, logger);

// Setup bounce handler
var bounceHandler = new BounceHandler(smtpServerConfig, mailQueue, logger);

// Setup queue processor (event-based, no polling)
var queueProcessorConfig = new QueueProcessorConfig {
    MaxConcurrentDeliveries  = 10,
    MaxDeliveriesPerDomain   = 5,
    SendDelayNotifications   = true
};
var queueProcessor = new QueueProcessor(mailQueue, outboundClient, bounceHandler, queueProcessorConfig, logger);


Console.WriteLine($"""
    Configuration:
      Hostname:       {smtpServerConfig.Hostname}
      SMTP Port:      {smtpServerConfig.Port}
      Submission:     {smtpServerConfig.SubmissionPort}
      Implicit TLS:   {(smtpServerConfig.EnableImplicitTls && smtpServerConfig.CertificatePath is not null ? smtpServerConfig.ImplicitTlsPort.ToString() : "off")}
      Local Domains:  {String.Join(", ", smtpServerConfig.LocalDomains)}
      Mail Storage:   {Path.GetFullPath(smtpServerConfig.MailStoragePath)}
      TLS Available:  {smtpServerConfig.CertificatePath is not null}
      Require TLS:    {smtpServerConfig.RequireStartTls}
      Verify DKIM:    {smtpServerConfig.VerifyDkim}
      Verify SPF:     {smtpServerConfig.VerifySpf}
      Verify DMARC:   {smtpServerConfig.VerifyDmarc}
      DKIM Signing:   {dkimSigner is not null}
      Smarthost:      {outboundConfig.SmartHost ?? "(direct delivery)"}
      Relay Auth:     Required (prevents open relay)
    """);

static HashSet<String> ParseLocalDomains(String domainsString)
{

    var domains = domainsString.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries)
                               .Select(d => d.Trim().ToLowerInvariant())
                               .Where(d => !String.IsNullOrEmpty(d))
                               .ToHashSet();

    // Always include localhost
    domains.Add("localhost");
    domains.Add("localhost.localdomain");

    return domains;

}

// Create and start server
await using var server = new SMTPServer(
                             smtpServerConfig,
                             dnsClient,
                             mailQueue: mailQueue
                         );

// Handle shutdown
var cts = new CancellationTokenSource();

Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    Console.WriteLine("\nShutdown requested...");
    cts.Cancel();
};

AppDomain.CurrentDomain.ProcessExit += (_, _) =>
{
    cts.Cancel();
};

try
{

    // Start queue processor
    await queueProcessor.StartAsync(cts.Token);

    // Start SMTP server
    await server.Start(cts.Token);

}
catch (OperationCanceledException)
{
    Console.WriteLine("Server stopped gracefully.");
}
finally
{
    await queueProcessor.DisposeAsync();
    mailQueue.Dispose();
}

static void GenerateSelfSignedCertificate(String path, String password, String hostname)
{

    using var rsa = RSA.Create(4096);

    var request = new CertificateRequest(
        $"CN={hostname}",
        rsa,
        HashAlgorithmName.SHA256,
        RSASignaturePadding.Pkcs1
    );

    // Add extensions
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
            [ new("1.3.6.1.5.5.7.3.1") ], // Server Authentication
            critical: false
        )
    );

    // Subject Alternative Names
    var sanBuilder = new SubjectAlternativeNameBuilder();
    sanBuilder.AddDnsName(hostname);
    sanBuilder.AddDnsName("localhost");
    sanBuilder.AddIpAddress(System.Net.IPAddress.Loopback);
    sanBuilder.AddIpAddress(System.Net.IPAddress.IPv6Loopback);
    request.CertificateExtensions.Add(sanBuilder.Build());

    // Create certificate
    var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
    var notAfter  = DateTimeOffset.UtcNow.AddYears(1);

    using var cert = request.CreateSelfSigned(notBefore, notAfter);

    // Export with private key
    var pfxBytes = cert.Export(X509ContentType.Pfx, password);
    File.WriteAllBytes(path, pfxBytes);

}
