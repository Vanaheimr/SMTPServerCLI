//// SMTP Test Client
//// Tests SMTP server with and without STARTTLS

//using System.Net.Security;
//using System.Net.Sockets;
//using System.Security.Cryptography.X509Certificates;
//using System.Text;

//Console.WriteLine("SMTP Server Test Client\n");

//var host = args.Length > 0 ? args[0] : "localhost";
//var port = args.Length > 1 && int.TryParse(args[1], out var p) ? p : 2525;

//Console.WriteLine($"Connecting to {host}:{port}...\n");

//await TestWithoutTlsAsync(host, port);
//Console.WriteLine("\n" + new string('─', 60) + "\n");
//await TestWithStartTlsAsync(host, port);

//static async Task TestWithoutTlsAsync(string host, int port)
//{
//    Console.WriteLine("═══ Test 1: Plain SMTP (no TLS) ═══\n");

//    using var client = new TcpClient();
//    await client.ConnectAsync(host, port);

//    await using var stream = client.GetStream();
//    using var reader = new StreamReader(stream, Encoding.ASCII);
//    await using var writer = new StreamWriter(stream, Encoding.ASCII) { AutoFlush = true };

//    // Read greeting
//    await ReadResponseAsync(reader);

//    // EHLO
//    await SendCommandAsync(writer, reader, "EHLO testclient.local");

//    // MAIL FROM
//    await SendCommandAsync(writer, reader, "MAIL FROM:<test@example.com>");

//    // RCPT TO
//    await SendCommandAsync(writer, reader, "RCPT TO:<recipient@localhost>");

//    // DATA
//    await SendCommandAsync(writer, reader, "DATA");

//    // Send message
//    var message = """
//        From: Test Sender <test@example.com>
//        To: Recipient <recipient@localhost>
//        Subject: Test Email (Plain)
//        Date: Mon, 23 Dec 2024 10:00:00 +0000
//        Message-ID: <test123@example.com>
//        MIME-Version: 1.0
//        Content-Type: text/plain; charset=utf-8
        
//        This is a test email sent without TLS.
        
//        Best regards,
//        Test Client
//        .
//        """;

//    await writer.WriteAsync(message.Replace("\n", "\r\n"));
//    await ReadResponseAsync(reader);

//    // QUIT
//    await SendCommandAsync(writer, reader, "QUIT");

//    Console.WriteLine("✓ Plain SMTP test completed");
//}

//static async Task TestWithStartTlsAsync(string host, int port)
//{
//    Console.WriteLine("═══ Test 2: SMTP with STARTTLS ═══\n");

//    using var client = new TcpClient();
//    await client.ConnectAsync(host, port);

//    Stream stream = client.GetStream();
//    StreamReader reader = new(stream, Encoding.ASCII);
//    StreamWriter writer = new(stream, Encoding.ASCII) { AutoFlush = true };

//    // Read greeting
//    await ReadResponseAsync(reader);

//    // EHLO
//    await SendCommandAsync(writer, reader, "EHLO testclient.local");

//    // STARTTLS
//    Console.WriteLine("C: STARTTLS");
//    await writer.WriteLineAsync("STARTTLS");
//    var response = await reader.ReadLineAsync();
//    Console.WriteLine($"S: {response}");

//    if (response?.StartsWith("220") == true)
//    {
//        Console.WriteLine("\n→ Upgrading to TLS...\n");

//        var sslStream = new SslStream(
//            stream,
//            false,
//            (sender, cert, chain, errors) => true // Accept self-signed for testing
//        );

//        await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
//        {
//            TargetHost = host,
//            EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 |
//                                  System.Security.Authentication.SslProtocols.Tls13
//        });

//        Console.WriteLine($"TLS established: {sslStream.SslProtocol}, {sslStream.CipherAlgorithm}");
//        Console.WriteLine($"Server certificate: {sslStream.RemoteCertificate?.Subject}\n");

//        stream = sslStream;
//        reader = new StreamReader(sslStream, Encoding.ASCII);
//        writer = new StreamWriter(sslStream, Encoding.ASCII) { AutoFlush = true };

//        // New EHLO after TLS
//        await SendCommandAsync(writer, reader, "EHLO testclient.local");

//        // MAIL FROM
//        await SendCommandAsync(writer, reader, "MAIL FROM:<secure@example.com>");

//        // RCPT TO
//        await SendCommandAsync(writer, reader, "RCPT TO:<recipient@localhost>");

//        // DATA
//        await SendCommandAsync(writer, reader, "DATA");

//        // Send message with DKIM-like header (for testing)
//        var secureMessage = """
//            From: Secure Sender <secure@example.com>
//            To: Recipient <recipient@localhost>
//            Subject: Test Email (TLS Encrypted)
//            Date: Mon, 23 Dec 2024 10:01:00 +0000
//            Message-ID: <secure456@example.com>
//            MIME-Version: 1.0
//            Content-Type: text/plain; charset=utf-8
//            DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
//                d=example.com; s=selector1;
//                h=from:to:subject:date:message-id;
//                bh=BASE64BODYHASH;
//                b=BASE64SIGNATURE
            
//            This is a test email sent over TLS!
            
//            The connection is now encrypted.
            
//            Best regards,
//            Secure Test Client
//            .
//            """;

//        await writer.WriteAsync(secureMessage.Replace("\n", "\r\n"));
//        await ReadResponseAsync(reader);

//        // QUIT
//        await SendCommandAsync(writer, reader, "QUIT");

//        Console.WriteLine("✓ STARTTLS test completed");
//    }
//    else
//    {
//        Console.WriteLine("✗ STARTTLS not available");
//    }
//}

//static async Task SendCommandAsync(StreamWriter writer, StreamReader reader, string command)
//{
//    Console.WriteLine($"C: {command}");
//    await writer.WriteLineAsync(command);
//    await ReadResponseAsync(reader);
//}

//static async Task ReadResponseAsync(StreamReader reader)
//{
//    while (true)
//    {
//        var line = await reader.ReadLineAsync();
//        if (line is null) break;

//        Console.WriteLine($"S: {line}");

//        // Check if this is a multiline response (character 4 is '-')
//        if (line.Length < 4 || line[3] != '-')
//            break;
//    }
//}
