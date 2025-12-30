//// SMTP Server - Entry Point
//// .NET 10 / C# 13

//using System.Security.Cryptography;
//using System.Security.Cryptography.X509Certificates;
//using AchimSmtpServer;

//Console.WriteLine("""
//    ╔═══════════════════════════════════════════════════════════════╗
//    ║          Achim SMTP Server - .NET 10 Edition                  ║
//    ║  StartTLS • SMTP-AUTH • DKIM • SPF/DMARC • Outbound Queue    ║
//    ╚═══════════════════════════════════════════════════════════════╝
//    """);

//// Generate self-signed certificate for testing if not exists
//var certPath = Path.Combine(AppContext.BaseDirectory, "server.pfx");
//var certPassword = "smtp-test-password";

//if (!File.Exists(certPath))
//{
//    Console.WriteLine("Generating self-signed certificate for STARTTLS...");
//    GenerateSelfSignedCertificate(certPath, certPassword, "localhost");
//    Console.WriteLine($"Certificate saved to: {certPath}");
//}

//// Configure the server
//var mailStoragePath = Environment.GetEnvironmentVariable("SMTP_MAIL_PATH") ?? "./mailstore";
//var hostname = Environment.GetEnvironmentVariable("SMTP_HOSTNAME") ?? "localhost";

//var config = new SmtpServerConfig
//{
//    Hostname            = hostname,
//    Port                = int.TryParse(Environment.GetEnvironmentVariable("SMTP_PORT"), out var p) ? p : 2525,
//    SubmissionPort      = int.TryParse(Environment.GetEnvironmentVariable("SMTP_SUBMISSION_PORT"), out var sp) ? sp : 2587,
//    MailStoragePath     = mailStoragePath,
//    CertificatePath     = certPath,
//    CertificatePassword = certPassword,
//    RequireStartTls     = false,
//    VerifyDkim          = true,
//    VerifySpf           = true,
//    VerifyDmarc         = true,
//    MaxMessageSize      = 25 * 1024 * 1024,
//    MaxRecipients       = 100,
//    SessionTimeout      = TimeSpan.FromMinutes(5),
    
//    // Local domains - mail to these is stored locally
//    // Mail to other domains requires authentication (relay)
//    LocalDomains        = ParseLocalDomains(Environment.GetEnvironmentVariable("SMTP_LOCAL_DOMAINS") ?? hostname),
//    RequireAuthForRelay = true,   // MUST be true to prevent open relay!
//    RequireAuthOnSubmission = true
//};

//var logger = new ConsoleLogger();

//// Setup DKIM signer (optional)
//DkimSigner? dkimSigner = null;
//var dkimKeyPath = Path.Combine(mailStoragePath, "dkim_default.private.pem");
//var dkimDomain = Environment.GetEnvironmentVariable("DKIM_DOMAIN") ?? hostname;
//var dkimSelector = Environment.GetEnvironmentVariable("DKIM_SELECTOR") ?? "default";

//if (File.Exists(dkimKeyPath))
//{
//    var privateKeyPem = File.ReadAllText(dkimKeyPath);
//    dkimSigner = new DkimSigner(new DkimConfig
//    {
//        Domain = dkimDomain,
//        Selector = dkimSelector,
//        PrivateKeyPem = privateKeyPem
//    }, logger);
//}
//else
//{
//    Console.WriteLine($"No DKIM key found at {dkimKeyPath}");
//    Console.WriteLine($"Generate with: DkimKeyGenerator.SaveKeyPair(\"{mailStoragePath}\", \"{dkimDomain}\", \"{dkimSelector}\")");
    
//    // Auto-generate DKIM keys for testing
//    if (Environment.GetEnvironmentVariable("DKIM_AUTO_GENERATE") == "true")
//    {
//        Console.WriteLine("Auto-generating DKIM keys...");
//        DkimKeyGenerator.SaveKeyPair(mailStoragePath, dkimDomain, dkimSelector);
//        var privateKeyPem = File.ReadAllText(dkimKeyPath);
//        dkimSigner = new DkimSigner(new DkimConfig
//        {
//            Domain = dkimDomain,
//            Selector = dkimSelector,
//            PrivateKeyPem = privateKeyPem
//        }, logger);
//        Console.WriteLine($"DKIM keys generated. Add DNS record from: {Path.Combine(mailStoragePath, $"dkim_{dkimSelector}.dns.txt")}");
//    }
//}

//// Setup mail queue
//var mailQueue = new FileMailQueue(mailStoragePath, logger);

//// Setup outbound client
//var outboundConfig = new SmtpOutboundConfig
//{
//    LocalHostname = hostname,
//    PreferStartTls = true,
//    RequireStartTls = false,
//    SmartHost = Environment.GetEnvironmentVariable("SMTP_SMARTHOST"),
//    SmartHostPort = int.TryParse(Environment.GetEnvironmentVariable("SMTP_SMARTHOST_PORT"), out var shp) ? shp : 25,
//    SmartHostUsername = Environment.GetEnvironmentVariable("SMTP_SMARTHOST_USER"),
//    SmartHostPassword = Environment.GetEnvironmentVariable("SMTP_SMARTHOST_PASS")
//};
//var outboundClient = new SmtpOutboundClient(outboundConfig, dkimSigner, logger);

//// Setup bounce handler
//var bounceHandler = new BounceHandler(config, mailQueue, logger);

//// Setup queue processor (event-based, no polling)
//var queueProcessorConfig = new QueueProcessorConfig
//{
//    MaxConcurrentDeliveries = 10,
//    MaxDeliveriesPerDomain = 5,
//    SendDelayNotifications = true
//};
//var queueProcessor = new QueueProcessor(mailQueue, outboundClient, bounceHandler, queueProcessorConfig, logger);

//Console.WriteLine($"""
//    Configuration:
//      Hostname:       {config.Hostname}
//      SMTP Port:      {config.Port} (MTA-to-MTA)
//      Submission:     {config.SubmissionPort} (MUA-to-MTA, requires AUTH)
//      Local Domains:  {string.Join(", ", config.LocalDomains)}
//      Mail Storage:   {Path.GetFullPath(config.MailStoragePath)}
//      TLS Available:  {config.CertificatePath is not null}
//      DKIM Signing:   {dkimSigner is not null}
//      Smarthost:      {outboundConfig.SmartHost ?? "(direct delivery)"}
//      Relay Auth:     Required (prevents open relay)
//    """);

//static HashSet<string> ParseLocalDomains(string domainsString)
//{
//    var domains = domainsString
//        .Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries)
//        .Select(d => d.Trim().ToLowerInvariant())
//        .Where(d => !string.IsNullOrEmpty(d))
//        .ToHashSet();
    
//    // Always include localhost
//    domains.Add("localhost");
//    domains.Add("localhost.localdomain");
    
//    return domains;
//}

//// Create and start server
//await using var server = new SmtpServer(config, logger, mailQueue: mailQueue);

//// Handle shutdown
//var cts = new CancellationTokenSource();
//Console.CancelKeyPress += (_, e) =>
//{
//    e.Cancel = true;
//    Console.WriteLine("\nShutdown requested...");
//    cts.Cancel();
//};

//AppDomain.CurrentDomain.ProcessExit += (_, _) =>
//{
//    cts.Cancel();
//};

//try
//{
//    // Start queue processor
//    await queueProcessor.StartAsync(cts.Token);
    
//    // Start SMTP server
//    await server.StartAsync(cts.Token);
//}
//catch (OperationCanceledException)
//{
//    Console.WriteLine("Server stopped gracefully.");
//}
//finally
//{
//    await queueProcessor.DisposeAsync();
//    mailQueue.Dispose();
//}

//static void GenerateSelfSignedCertificate(string path, string password, string hostname)
//{
//    using var rsa = RSA.Create(2048);
    
//    var request = new CertificateRequest(
//        $"CN={hostname}",
//        rsa,
//        HashAlgorithmName.SHA256,
//        RSASignaturePadding.Pkcs1
//    );

//    // Add extensions
//    request.CertificateExtensions.Add(
//        new X509BasicConstraintsExtension(false, false, 0, false)
//    );

//    request.CertificateExtensions.Add(
//        new X509KeyUsageExtension(
//            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
//            false
//        )
//    );

//    request.CertificateExtensions.Add(
//        new X509EnhancedKeyUsageExtension(
//            new OidCollection
//            {
//                new("1.3.6.1.5.5.7.3.1") // Server Authentication
//            },
//            false
//        )
//    );

//    // Subject Alternative Names
//    var sanBuilder = new SubjectAlternativeNameBuilder();
//    sanBuilder.AddDnsName(hostname);
//    sanBuilder.AddDnsName("localhost");
//    sanBuilder.AddIpAddress(System.Net.IPAddress.Loopback);
//    sanBuilder.AddIpAddress(System.Net.IPAddress.IPv6Loopback);
//    request.CertificateExtensions.Add(sanBuilder.Build());

//    // Create certificate
//    var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
//    var notAfter = DateTimeOffset.UtcNow.AddYears(1);

//    using var cert = request.CreateSelfSigned(notBefore, notAfter);
    
//    // Export with private key
//    var pfxBytes = cert.Export(X509ContentType.Pfx, password);
//    File.WriteAllBytes(path, pfxBytes);
//}
