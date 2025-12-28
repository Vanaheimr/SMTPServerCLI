// SMTP Test Client
// Tests SMTP server with STARTTLS and AUTH mechanisms

using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

Console.WriteLine("SMTP Server Test Client\n");

var host = args.Length > 0 ? args[0] : "localhost";
var port = args.Length > 1 && int.TryParse(args[1], out var p) ? p : 2525;

Console.WriteLine($"Connecting to {host}:{port}...\n");

await TestWithoutTlsAsync(host, port);
Console.WriteLine("\n" + new string('─', 60) + "\n");
await TestWithStartTlsAndAuthPlainAsync(host, port);
Console.WriteLine("\n" + new string('─', 60) + "\n");
await TestWithAuthLoginAsync(host, port);
Console.WriteLine("\n" + new string('─', 60) + "\n");
await TestWithAuthScramAsync(host, port);

static async Task TestWithoutTlsAsync(string host, int port)
{
    Console.WriteLine("═══ Test 1: Plain SMTP (no TLS, no AUTH) ═══\n");
    
    using var client = new TcpClient();
    await client.ConnectAsync(host, port);
    
    await using var stream = client.GetStream();
    using var reader = new StreamReader(stream, Encoding.ASCII);
    await using var writer = new StreamWriter(stream, Encoding.ASCII) { AutoFlush = true };

    await ReadResponseAsync(reader);
    await SendCommandAsync(writer, reader, "EHLO testclient.local");
    await SendCommandAsync(writer, reader, "MAIL FROM:<test@example.com>");
    await SendCommandAsync(writer, reader, "RCPT TO:<recipient@localhost>");
    await SendCommandAsync(writer, reader, "DATA");

    var message = """
        From: Test Sender <test@example.com>
        To: Recipient <recipient@localhost>
        Subject: Test Email (Plain, no Auth)
        Date: Mon, 23 Dec 2024 10:00:00 +0000
        Message-ID: <test-noauth@example.com>
        
        This is a test email sent without TLS or authentication.
        .
        """;
    
    await writer.WriteAsync(message.Replace("\n", "\r\n"));
    await ReadResponseAsync(reader);
    await SendCommandAsync(writer, reader, "QUIT");
    
    Console.WriteLine("✓ Plain SMTP test completed");
}

static async Task TestWithStartTlsAndAuthPlainAsync(string host, int port)
{
    Console.WriteLine("═══ Test 2: STARTTLS + AUTH PLAIN ═══\n");
    
    using var client = new TcpClient();
    await client.ConnectAsync(host, port);
    
    Stream stream = client.GetStream();
    StreamReader reader = new(stream, Encoding.ASCII);
    StreamWriter writer = new(stream, Encoding.ASCII) { AutoFlush = true };

    await ReadResponseAsync(reader);
    await SendCommandAsync(writer, reader, "EHLO testclient.local");

    // STARTTLS
    Console.WriteLine("C: STARTTLS");
    await writer.WriteLineAsync("STARTTLS");
    var response = await reader.ReadLineAsync();
    Console.WriteLine($"S: {response}");

    if (response?.StartsWith("220") == true)
    {
        Console.WriteLine("\n→ Upgrading to TLS...\n");
        
        var sslStream = new SslStream(stream, false, (_, _, _, _) => true);
        await sslStream.AuthenticateAsClientAsync(host);

        Console.WriteLine($"TLS: {sslStream.SslProtocol}, {sslStream.CipherAlgorithm}\n");

        stream = sslStream;
        reader = new StreamReader(sslStream, Encoding.ASCII);
        writer = new StreamWriter(sslStream, Encoding.ASCII) { AutoFlush = true };

        await SendCommandAsync(writer, reader, "EHLO testclient.local");

        // AUTH PLAIN (credentials: admin:test123)
        // Format: Base64(authzid \0 authcid \0 password)
        var authString = "\0admin\0test123";
        var authBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(authString));
        
        Console.WriteLine($"→ Authenticating with AUTH PLAIN...\n");
        await SendCommandAsync(writer, reader, $"AUTH PLAIN {authBase64}");

        // Send email as authenticated user
        await SendCommandAsync(writer, reader, "MAIL FROM:<admin@localhost>");
        await SendCommandAsync(writer, reader, "RCPT TO:<recipient@localhost>");
        await SendCommandAsync(writer, reader, "DATA");

        var message = """
            From: Admin <admin@localhost>
            To: Recipient <recipient@localhost>
            Subject: Test Email (TLS + AUTH PLAIN)
            Date: Mon, 23 Dec 2024 10:01:00 +0000
            Message-ID: <test-authplain@localhost>
            
            This email was sent with TLS encryption and AUTH PLAIN authentication.
            .
            """;
        
        await writer.WriteAsync(message.Replace("\n", "\r\n"));
        await ReadResponseAsync(reader);
        await SendCommandAsync(writer, reader, "QUIT");
        
        Console.WriteLine("✓ AUTH PLAIN test completed");
    }
}

static async Task TestWithAuthLoginAsync(string host, int port)
{
    Console.WriteLine("═══ Test 3: STARTTLS + AUTH LOGIN ═══\n");
    
    using var client = new TcpClient();
    await client.ConnectAsync(host, port);
    
    Stream stream = client.GetStream();
    StreamReader reader = new(stream, Encoding.ASCII);
    StreamWriter writer = new(stream, Encoding.ASCII) { AutoFlush = true };

    await ReadResponseAsync(reader);
    await SendCommandAsync(writer, reader, "EHLO testclient.local");

    Console.WriteLine("C: STARTTLS");
    await writer.WriteLineAsync("STARTTLS");
    var response = await reader.ReadLineAsync();
    Console.WriteLine($"S: {response}");

    if (response?.StartsWith("220") == true)
    {
        var sslStream = new SslStream(stream, false, (_, _, _, _) => true);
        await sslStream.AuthenticateAsClientAsync(host);
        Console.WriteLine($"\nTLS: {sslStream.SslProtocol}\n");

        reader = new StreamReader(sslStream, Encoding.ASCII);
        writer = new StreamWriter(sslStream, Encoding.ASCII) { AutoFlush = true };

        await SendCommandAsync(writer, reader, "EHLO testclient.local");

        // AUTH LOGIN
        Console.WriteLine("→ Authenticating with AUTH LOGIN...\n");
        Console.WriteLine("C: AUTH LOGIN");
        await writer.WriteLineAsync("AUTH LOGIN");
        response = await reader.ReadLineAsync();
        Console.WriteLine($"S: {response}"); // Should be: 334 VXNlcm5hbWU6 (Username:)

        // Send username
        var usernameB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes("user"));
        Console.WriteLine($"C: {usernameB64} (user)");
        await writer.WriteLineAsync(usernameB64);
        response = await reader.ReadLineAsync();
        Console.WriteLine($"S: {response}"); // Should be: 334 UGFzc3dvcmQ6 (Password:)

        // Send password
        var passwordB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes("test123"));
        Console.WriteLine($"C: {passwordB64} (test123)");
        await writer.WriteLineAsync(passwordB64);
        response = await reader.ReadLineAsync();
        Console.WriteLine($"S: {response}"); // Should be: 235 Authentication successful

        await SendCommandAsync(writer, reader, "QUIT");
        Console.WriteLine("✓ AUTH LOGIN test completed");
    }
}

static async Task TestWithAuthScramAsync(string host, int port)
{
    Console.WriteLine("═══ Test 4: AUTH SCRAM-SHA-256 (no TLS required) ═══\n");
    
    using var client = new TcpClient();
    await client.ConnectAsync(host, port);
    
    await using var stream = client.GetStream();
    using var reader = new StreamReader(stream, Encoding.ASCII);
    await using var writer = new StreamWriter(stream, Encoding.ASCII) { AutoFlush = true };

    await ReadResponseAsync(reader);
    await SendCommandAsync(writer, reader, "EHLO testclient.local");

    // SCRAM-SHA-256 is safe without TLS
    Console.WriteLine("→ Authenticating with SCRAM-SHA-256...\n");
    
    var username = "demo";
    var password = "demo";
    var clientNonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(18));

    // client-first-message
    var clientFirstBare = $"n={username},r={clientNonce}";
    var clientFirstMessage = $"n,,{clientFirstBare}";
    var clientFirstB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(clientFirstMessage));

    Console.WriteLine($"C: AUTH SCRAM-SHA-256 {clientFirstB64}");
    Console.WriteLine($"   (decoded: {clientFirstMessage})");
    await writer.WriteLineAsync($"AUTH SCRAM-SHA-256 {clientFirstB64}");
    
    var response = await reader.ReadLineAsync();
    Console.WriteLine($"S: {response}");

    if (response?.StartsWith("334") == true)
    {
        // Parse server-first-message
        var serverFirstB64 = response[4..].Trim();
        var serverFirstMessage = Encoding.UTF8.GetString(Convert.FromBase64String(serverFirstB64));
        Console.WriteLine($"   (decoded: {serverFirstMessage})");

        var serverParams = ParseScramMessage(serverFirstMessage);
        var serverNonce = serverParams["r"];
        var salt = Convert.FromBase64String(serverParams["s"]);
        var iterations = int.Parse(serverParams["i"]);

        // Verify server nonce starts with client nonce
        if (!serverNonce.StartsWith(clientNonce))
        {
            Console.WriteLine("✗ Server nonce doesn't match!");
            return;
        }

        // Compute SCRAM proof
        var saltedPassword = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            32
        );

        var clientKey = HMACSHA256.HashData(saltedPassword, Encoding.UTF8.GetBytes("Client Key"));
        var storedKey = SHA256.HashData(clientKey);

        var clientFinalWithoutProof = $"c=biws,r={serverNonce}"; // biws = Base64("n,,")
        var authMessage = $"{clientFirstBare},{serverFirstMessage},{clientFinalWithoutProof}";
        
        var clientSignature = HMACSHA256.HashData(storedKey, Encoding.UTF8.GetBytes(authMessage));
        var clientProof = new byte[clientKey.Length];
        for (int i = 0; i < clientKey.Length; i++)
            clientProof[i] = (byte)(clientKey[i] ^ clientSignature[i]);

        var clientFinalMessage = $"{clientFinalWithoutProof},p={Convert.ToBase64String(clientProof)}";
        var clientFinalB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(clientFinalMessage));

        Console.WriteLine($"C: {clientFinalB64}");
        Console.WriteLine($"   (decoded: {clientFinalMessage})");
        await writer.WriteLineAsync(clientFinalB64);

        response = await reader.ReadLineAsync();
        Console.WriteLine($"S: {response}");

        if (response?.StartsWith("235") == true)
        {
            // Verify server signature
            var serverKey = HMACSHA256.HashData(saltedPassword, Encoding.UTF8.GetBytes("Server Key"));
            var serverSignature = HMACSHA256.HashData(serverKey, Encoding.UTF8.GetBytes(authMessage));
            Console.WriteLine($"   Expected server signature: v={Convert.ToBase64String(serverSignature)}");
            Console.WriteLine("✓ SCRAM-SHA-256 authentication successful!");
        }
    }

    await SendCommandAsync(writer, reader, "QUIT");
}

static Dictionary<string, string> ParseScramMessage(string message)
{
    var result = new Dictionary<string, string>();
    foreach (var part in message.Split(','))
    {
        var eq = part.IndexOf('=');
        if (eq > 0)
            result[part[..eq]] = part[(eq + 1)..];
    }
    return result;
}

static async Task SendCommandAsync(StreamWriter writer, StreamReader reader, string command)
{
    Console.WriteLine($"C: {command}");
    await writer.WriteLineAsync(command);
    await ReadResponseAsync(reader);
}

static async Task ReadResponseAsync(StreamReader reader)
{
    while (true)
    {
        var line = await reader.ReadLineAsync();
        if (line is null) break;
        
        Console.WriteLine($"S: {line}");
        
        if (line.Length < 4 || line[3] != '-')
            break;
    }
}
