// SMTP Outbound Client - Send mail to remote MX servers
// .NET 10 / C# 13

using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace AchimSmtpServer;

#region Send Result

public enum SendStatus
{
    Success,
    TempFail,   // 4xx - retry later
    PermFail    // 5xx - permanent failure, don't retry
}

public sealed record SendResult(
    SendStatus  Status,
    int         ResponseCode,
    string      ResponseText,
    string?     RemoteMx = null,
    TimeSpan?   Duration = null
)
{
    public static SendResult Success(string response, string mx, TimeSpan duration) =>
        new(SendStatus.Success, 250, response, mx, duration);

    public static SendResult TempFail(int code, string response, string? mx = null) =>
        new(SendStatus.TempFail, code, response, mx);

    public static SendResult PermFail(int code, string response, string? mx = null) =>
        new(SendStatus.PermFail, code, response, mx);

    public static SendResult TempFail(string error) =>
        new(SendStatus.TempFail, 0, error);

    public static SendResult PermFail(string error) =>
        new(SendStatus.PermFail, 0, error);
}

#endregion

#region MX Record

public sealed record MxRecord(string Host, int Priority);

#endregion

#region Outbound Client Configuration

public sealed record SmtpOutboundConfig
{
    public required string  LocalHostname       { get; init; }
    public          int     ConnectTimeoutMs    { get; init; } = 30_000;
    public          int     ReadTimeoutMs       { get; init; } = 60_000;
    public          int     WriteTimeoutMs      { get; init; } = 60_000;
    public          bool    RequireStartTls     { get; init; } = false;
    public          bool    PreferStartTls      { get; init; } = true;
    public          string? SmartHost           { get; init; }  // Optional relay host
    public          int     SmartHostPort       { get; init; } = 25;
    public          string? SmartHostUsername   { get; init; }
    public          string? SmartHostPassword   { get; init; }
}

#endregion

#region SMTP Outbound Client

public sealed partial class SmtpOutboundClient(
    SmtpOutboundConfig  config,
    DkimSigner?         dkimSigner,
    ILogger             logger)
{
    public async Task<SendResult> SendAsync(
        string              targetDomain,
        string              envelopeFrom,
        string[]            recipients,
        string              messageContent,
        CancellationToken   ct = default)
    {
        var startTime = DateTime.UtcNow;

        try
        {
            // Sign message with DKIM if signer is configured
            if (dkimSigner is not null)
            {
                messageContent = dkimSigner.SignMessage(messageContent);
            }

            // Determine target hosts
            IReadOnlyList<MxRecord> mxHosts;
            
            if (config.SmartHost is not null)
            {
                // Use smarthost relay
                mxHosts = [new MxRecord(config.SmartHost, 0)];
                logger.Log(LogLevel.Debug, $"Using smarthost: {config.SmartHost}");
            }
            else
            {
                // MX lookup
                mxHosts = await ResolveMxAsync(targetDomain, ct);
                if (mxHosts.Count == 0)
                {
                    // Fallback to A/AAAA record
                    mxHosts = [new MxRecord(targetDomain, 0)];
                }
                logger.Log(LogLevel.Debug, $"MX records for {targetDomain}: {string.Join(", ", mxHosts.Select(m => $"{m.Host}:{m.Priority}"))}");
            }

            // Try each MX host in priority order
            Exception? lastException = null;
            string? lastError = null;
            int lastCode = 0;

            foreach (var mx in mxHosts.OrderBy(m => m.Priority))
            {
                try
                {
                    var result = await TrySendToMxAsync(
                        mx.Host,
                        config.SmartHost is not null ? config.SmartHostPort : 25,
                        envelopeFrom,
                        recipients,
                        messageContent,
                        ct
                    );

                    if (result.Status == SendStatus.Success)
                    {
                        var duration = DateTime.UtcNow - startTime;
                        return result with { Duration = duration };
                    }

                    // Permanent failure - don't try other MX hosts
                    if (result.Status == SendStatus.PermFail)
                    {
                        return result;
                    }

                    // Temp failure - try next MX
                    lastError = result.ResponseText;
                    lastCode = result.ResponseCode;
                    logger.Log(LogLevel.Warning, $"MX {mx.Host} temp failed: {result.ResponseCode} {result.ResponseText}");
                }
                catch (Exception ex)
                {
                    lastException = ex;
                    logger.Log(LogLevel.Warning, $"MX {mx.Host} connection failed: {ex.Message}");
                }
            }

            // All MX hosts failed
            return lastError is not null
                ? SendResult.TempFail(lastCode, lastError)
                : SendResult.TempFail($"All MX hosts unreachable: {lastException?.Message}");
        }
        catch (Exception ex)
        {
            logger.Log(LogLevel.Error, $"Send failed to {targetDomain}: {ex.Message}");
            return SendResult.TempFail($"Send error: {ex.Message}");
        }
    }

    private async Task<SendResult> TrySendToMxAsync(
        string              mxHost,
        int                 port,
        string              envelopeFrom,
        string[]            recipients,
        string              messageContent,
        CancellationToken   ct)
    {
        using var client = new TcpClient();
        client.SendTimeout = config.WriteTimeoutMs;
        client.ReceiveTimeout = config.ReadTimeoutMs;

        // Connect with timeout
        using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        connectCts.CancelAfter(config.ConnectTimeoutMs);

        logger.Log(LogLevel.Debug, $"Connecting to {mxHost}:{port}");
        await client.ConnectAsync(mxHost, port, connectCts.Token);

        Stream stream = client.GetStream();
        var reader = new StreamReader(stream, Encoding.ASCII);
        var writer = new StreamWriter(stream, Encoding.ASCII) { AutoFlush = true };

        try
        {
            // Read greeting
            var greeting = await ReadResponseAsync(reader, ct);
            if (!greeting.StartsWith("220"))
            {
                return ParseResponse(greeting, mxHost);
            }

            // EHLO
            await writer.WriteLineAsync($"EHLO {config.LocalHostname}");
            var ehloResponse = await ReadMultilineResponseAsync(reader, ct);
            
            if (!ehloResponse.Code.StartsWith("250"))
            {
                // Try HELO fallback
                await writer.WriteLineAsync($"HELO {config.LocalHostname}");
                ehloResponse = await ReadMultilineResponseAsync(reader, ct);
                
                if (!ehloResponse.Code.StartsWith("250"))
                {
                    return ParseResponse($"{ehloResponse.Code} {ehloResponse.LastLine}", mxHost);
                }
            }

            // STARTTLS if available and desired
            var supportsStartTls = ehloResponse.Lines.Any(l => 
                l.Contains("STARTTLS", StringComparison.OrdinalIgnoreCase));

            if (supportsStartTls && (config.RequireStartTls || config.PreferStartTls))
            {
                await writer.WriteLineAsync("STARTTLS");
                var starttlsResponse = await ReadResponseAsync(reader, ct);

                if (starttlsResponse.StartsWith("220"))
                {
                    // Upgrade to TLS
                    var sslStream = new SslStream(stream, false, ValidateServerCertificate);
                    await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                    {
                        TargetHost = mxHost,
                        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
                    }, ct);

                    stream = sslStream;
                    reader = new StreamReader(sslStream, Encoding.ASCII);
                    writer = new StreamWriter(sslStream, Encoding.ASCII) { AutoFlush = true };

                    logger.Log(LogLevel.Debug, $"TLS established with {mxHost}: {sslStream.SslProtocol}");

                    // Re-send EHLO after TLS
                    await writer.WriteLineAsync($"EHLO {config.LocalHostname}");
                    ehloResponse = await ReadMultilineResponseAsync(reader, ct);
                }
                else if (config.RequireStartTls)
                {
                    return SendResult.TempFail(454, $"STARTTLS required but failed: {starttlsResponse}", mxHost);
                }
            }
            else if (config.RequireStartTls)
            {
                return SendResult.TempFail(454, "STARTTLS required but not supported", mxHost);
            }

            // AUTH if smarthost credentials provided
            if (config.SmartHost is not null && config.SmartHostUsername is not null)
            {
                var authResult = await AuthenticateAsync(reader, writer, ehloResponse, ct);
                if (!authResult.StartsWith("235"))
                {
                    return ParseResponse(authResult, mxHost);
                }
            }

            // MAIL FROM
            await writer.WriteLineAsync($"MAIL FROM:<{envelopeFrom}>");
            var mailResponse = await ReadResponseAsync(reader, ct);
            if (!mailResponse.StartsWith("250"))
            {
                return ParseResponse(mailResponse, mxHost);
            }

            // RCPT TO for each recipient
            var acceptedRecipients = new List<string>();
            foreach (var recipient in recipients)
            {
                await writer.WriteLineAsync($"RCPT TO:<{recipient}>");
                var rcptResponse = await ReadResponseAsync(reader, ct);
                
                if (rcptResponse.StartsWith("250") || rcptResponse.StartsWith("251"))
                {
                    acceptedRecipients.Add(recipient);
                }
                else
                {
                    logger.Log(LogLevel.Warning, $"Recipient {recipient} rejected: {rcptResponse}");
                    // Continue with other recipients
                }
            }

            if (acceptedRecipients.Count == 0)
            {
                return SendResult.PermFail(550, "All recipients rejected", mxHost);
            }

            // DATA
            await writer.WriteLineAsync("DATA");
            var dataResponse = await ReadResponseAsync(reader, ct);
            if (!dataResponse.StartsWith("354"))
            {
                return ParseResponse(dataResponse, mxHost);
            }

            // Send message content with dot-stuffing
            await SendMessageDataAsync(writer, messageContent, ct);

            // End with <CRLF>.<CRLF>
            await writer.WriteLineAsync(".");
            var finalResponse = await ReadResponseAsync(reader, ct);

            // QUIT (best effort)
            try
            {
                await writer.WriteLineAsync("QUIT");
                await ReadResponseAsync(reader, ct);
            }
            catch
            {
                // Ignore QUIT errors
            }

            return ParseResponse(finalResponse, mxHost);
        }
        finally
        {
            client.Close();
        }
    }

    private async Task<string> AuthenticateAsync(
        StreamReader            reader,
        StreamWriter            writer,
        MultilineResponse       ehloResponse,
        CancellationToken       ct)
    {
        // Check supported mechanisms
        var authLine = ehloResponse.Lines.FirstOrDefault(l => 
            l.StartsWith("250", StringComparison.OrdinalIgnoreCase) &&
            l.Contains("AUTH", StringComparison.OrdinalIgnoreCase));

        if (authLine is null)
        {
            return "504 AUTH not supported";
        }

        // Prefer PLAIN for simplicity (already over TLS)
        if (authLine.Contains("PLAIN", StringComparison.OrdinalIgnoreCase))
        {
            var authString = $"\0{config.SmartHostUsername}\0{config.SmartHostPassword}";
            var authBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(authString));
            
            await writer.WriteLineAsync($"AUTH PLAIN {authBase64}");
            return await ReadResponseAsync(reader, ct);
        }

        // Fallback to LOGIN
        if (authLine.Contains("LOGIN", StringComparison.OrdinalIgnoreCase))
        {
            await writer.WriteLineAsync("AUTH LOGIN");
            var response = await ReadResponseAsync(reader, ct);
            if (!response.StartsWith("334"))
                return response;

            await writer.WriteLineAsync(Convert.ToBase64String(Encoding.UTF8.GetBytes(config.SmartHostUsername!)));
            response = await ReadResponseAsync(reader, ct);
            if (!response.StartsWith("334"))
                return response;

            await writer.WriteLineAsync(Convert.ToBase64String(Encoding.UTF8.GetBytes(config.SmartHostPassword!)));
            return await ReadResponseAsync(reader, ct);
        }

        return "504 No supported AUTH mechanism";
    }

    private static async Task SendMessageDataAsync(StreamWriter writer, string content, CancellationToken ct)
    {
        // Split into lines and apply dot-stuffing
        using var contentReader = new StringReader(content);
        string? line;
        
        while ((line = await contentReader.ReadLineAsync(ct)) is not null)
        {
            // Dot-stuffing: lines starting with "." get an extra "."
            if (line.StartsWith('.'))
            {
                await writer.WriteAsync('.');
            }
            await writer.WriteLineAsync(line);
        }
    }

    #region MX Resolution

    private async Task<IReadOnlyList<MxRecord>> ResolveMxAsync(string domain, CancellationToken ct)
    {
        try
        {
            // Use dig/nslookup for MX lookup
            var process = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = OperatingSystem.IsWindows() ? "nslookup" : "dig",
                    Arguments = OperatingSystem.IsWindows()
                        ? $"-type=MX {domain}"
                        : $"+short MX {domain}",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.Start();
            var output = await process.StandardOutput.ReadToEndAsync(ct);
            await process.WaitForExitAsync(ct);

            var records = new List<MxRecord>();

            if (OperatingSystem.IsWindows())
            {
                // Parse nslookup output
                var matches = MxNslookupRegex().Matches(output);
                foreach (Match match in matches)
                {
                    var priority = int.Parse(match.Groups[1].Value);
                    var host = match.Groups[2].Value.TrimEnd('.');
                    records.Add(new MxRecord(host, priority));
                }
            }
            else
            {
                // Parse dig output: "10 mail.example.com."
                foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = line.Trim().Split(' ', 2);
                    if (parts.Length == 2 && int.TryParse(parts[0], out var priority))
                    {
                        var host = parts[1].TrimEnd('.');
                        records.Add(new MxRecord(host, priority));
                    }
                }
            }

            return records;
        }
        catch (Exception ex)
        {
            logger.Log(LogLevel.Warning, $"MX lookup failed for {domain}: {ex.Message}");
            return [];
        }
    }

    [GeneratedRegex(@"MX preference = (\d+), mail exchanger = (.+)")]
    private static partial Regex MxNslookupRegex();

    #endregion

    #region Response Parsing

    private sealed record MultilineResponse(string Code, List<string> Lines, string LastLine);

    private static async Task<string> ReadResponseAsync(StreamReader reader, CancellationToken ct)
    {
        var line = await reader.ReadLineAsync(ct);
        return line ?? "";
    }

    private static async Task<MultilineResponse> ReadMultilineResponseAsync(StreamReader reader, CancellationToken ct)
    {
        var lines = new List<string>();
        string? line;
        string code = "";

        while ((line = await reader.ReadLineAsync(ct)) is not null)
        {
            lines.Add(line);
            
            if (line.Length >= 3)
            {
                code = line[..3];
                
                // Check if this is the last line (space after code, not hyphen)
                if (line.Length == 3 || line[3] != '-')
                    break;
            }
        }

        return new MultilineResponse(code, lines, line ?? "");
    }

    private static SendResult ParseResponse(string response, string? mx)
    {
        if (string.IsNullOrEmpty(response))
            return SendResult.TempFail(0, "Empty response", mx);

        if (!int.TryParse(response.AsSpan(0, Math.Min(3, response.Length)), out var code))
            return SendResult.TempFail(0, response, mx);

        return code switch
        {
            >= 200 and < 300 => SendResult.Success(response, mx ?? "", TimeSpan.Zero),
            >= 400 and < 500 => SendResult.TempFail(code, response, mx),
            >= 500 => SendResult.PermFail(code, response, mx),
            _ => SendResult.TempFail(code, response, mx)
        };
    }

    #endregion

    #region Certificate Validation

    private bool ValidateServerCertificate(
        object sender,
        X509Certificate? certificate,
        X509Chain? chain,
        SslPolicyErrors sslPolicyErrors)
    {
        // In production, implement proper certificate validation
        // For now, log issues but accept (many mail servers have cert issues)
        if (sslPolicyErrors != SslPolicyErrors.None)
        {
            logger.Log(LogLevel.Warning, $"TLS certificate warning: {sslPolicyErrors}");
        }
        return true; // Accept for now - mail delivery is more important than strict TLS
    }

    #endregion
}

#endregion
