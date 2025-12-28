// SMTP Server - Entry Point
// .NET 10 / C# 13

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AchimSmtpServer;

Console.WriteLine("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║          Achim SMTP Server - .NET 10 Edition                  ║
    ║  StartTLS • DKIM Verification • SPF/DMARC • File Storage     ║
    ╚═══════════════════════════════════════════════════════════════╝
    """);

// Generate self-signed certificate for testing if not exists
var certPath = Path.Combine(AppContext.BaseDirectory, "server.pfx");
var certPassword = "smtp-test-password";

if (!File.Exists(certPath))
{
    Console.WriteLine("Generating self-signed certificate for STARTTLS...");
    GenerateSelfSignedCertificate(certPath, certPassword, "localhost");
    Console.WriteLine($"Certificate saved to: {certPath}");
}

// Configure the server
var config = new SmtpServerConfig
{
    Hostname            = Environment.GetEnvironmentVariable("SMTP_HOSTNAME") ?? "localhost",
    Port                = int.TryParse(Environment.GetEnvironmentVariable("SMTP_PORT"), out var p) ? p : 2525,
    SubmissionPort      = int.TryParse(Environment.GetEnvironmentVariable("SMTP_SUBMISSION_PORT"), out var sp) ? sp : 2587,
    MailStoragePath     = Environment.GetEnvironmentVariable("SMTP_MAIL_PATH") ?? "./mailstore",
    CertificatePath     = certPath,
    CertificatePassword = certPassword,
    RequireStartTls     = false,
    VerifyDkim          = true,
    VerifySpf           = true,
    VerifyDmarc         = true,
    MaxMessageSize      = 25 * 1024 * 1024,
    MaxRecipients       = 100,
    SessionTimeout      = TimeSpan.FromMinutes(5)
};

Console.WriteLine($"""
    Configuration:
      Hostname:       {config.Hostname}
      SMTP Port:      {config.Port}
      Submission:     {config.SubmissionPort}
      Mail Storage:   {Path.GetFullPath(config.MailStoragePath)}
      TLS Available:  {config.CertificatePath is not null}
      Require TLS:    {config.RequireStartTls}
      Verify DKIM:    {config.VerifyDkim}
      Verify SPF:     {config.VerifySpf}
      Verify DMARC:   {config.VerifyDmarc}
    """);

// Create and start server
await using var server = new SmtpServer(config);

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
    await server.StartAsync(cts.Token);
}
catch (OperationCanceledException)
{
    Console.WriteLine("Server stopped gracefully.");
}

static void GenerateSelfSignedCertificate(string path, string password, string hostname)
{
    using var rsa = RSA.Create(2048);
    
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
            new OidCollection
            {
                new("1.3.6.1.5.5.7.3.1") // Server Authentication
            },
            false
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
    var notAfter = DateTimeOffset.UtcNow.AddYears(1);

    using var cert = request.CreateSelfSigned(notBefore, notAfter);
    
    // Export with private key
    var pfxBytes = cert.Export(X509ContentType.Pfx, password);
    File.WriteAllBytes(path, pfxBytes);
}
