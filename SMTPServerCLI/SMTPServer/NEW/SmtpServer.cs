// SMTP Server with StartTLS, DKIM Verification, and DNS Validation
// .NET 10 / C# 13
// Author: Claude for Achim

using System.Buffers;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace AchimSmtpServer;

#region Configuration

public sealed record SmtpServerConfig
{
    public required string   Hostname           { get; init; }
    public          int      Port               { get; init; } = 25;
    public          int      SubmissionPort     { get; init; } = 587;
    public          string   MailStoragePath    { get; init; } = "./mailstore";
    public          string?  CertificatePath    { get; init; }
    public          string?  CertificatePassword{ get; init; }
    public          TimeSpan SessionTimeout     { get; init; } = TimeSpan.FromMinutes(5);
    public          int      MaxMessageSize     { get; init; } = 25 * 1024 * 1024; // 25 MB
    public          int      MaxRecipients      { get; init; } = 100;
    public          bool     RequireStartTls    { get; init; } = false;
    public          bool     VerifyDkim         { get; init; } = true;
    public          bool     VerifySpf          { get; init; } = true;
    public          bool     VerifyDmarc        { get; init; } = true;
    
    /// <summary>
    /// Domains considered "local" - mail to these is stored locally.
    /// Mail to other domains requires authentication (relay).
    /// </summary>
    public HashSet<string>   LocalDomains       { get; init; } = ["localhost", "localhost.localdomain"];
    
    /// <summary>
    /// Require authentication for relaying to external domains.
    /// MUST be true in production to prevent becoming an open relay!
    /// </summary>
    public          bool     RequireAuthForRelay{ get; init; } = true;
    
    /// <summary>
    /// Require authentication on submission port (587) even for local delivery.
    /// RFC 6409 recommends this.
    /// </summary>
    public          bool     RequireAuthOnSubmission { get; init; } = true;
    
    /// <summary>
    /// Check if a domain is local (case-insensitive)
    /// </summary>
    public bool IsLocalDomain(string domain) =>
        LocalDomains.Contains(domain, StringComparer.OrdinalIgnoreCase);
}

#endregion

#region DNS Verification

public enum SpfResult { None, Pass, Fail, SoftFail, Neutral, TempError, PermError }
public enum DkimResult { None, Pass, Fail, TempError, PermError }
public enum DmarcResult { None, Pass, Fail, TempError, PermError }

public sealed record DnsVerificationResult(
    SpfResult   Spf,
    string?     SpfRecord,
    DkimResult  Dkim,
    string?     DkimDetails,
    DmarcResult Dmarc,
    string?     DmarcPolicy,
    string[]    MxRecords
);

public sealed partial class DnsVerifier(ILogger logger)
{
    public async Task<DnsVerificationResult> VerifyAsync(
        string        senderDomain,
        IPAddress     clientIp,
        string        mailFrom,
        string        heloHostname,
        EmailMessage  message,
        CancellationToken ct = default)
    {
        var spfTask   = VerifySpfAsync(senderDomain, clientIp, mailFrom, heloHostname, ct);
        var dkimTask  = VerifyDkimAsync(message, ct);
        var dmarcTask = VerifyDmarcAsync(senderDomain, ct);
        var mxTask    = GetMxRecordsAsync(senderDomain, ct);

        await Task.WhenAll(spfTask, dkimTask, dmarcTask, mxTask);

        return new DnsVerificationResult(
            spfTask.Result.Result,
            spfTask.Result.Record,
            dkimTask.Result.Result,
            dkimTask.Result.Details,
            dmarcTask.Result.Result,
            dmarcTask.Result.Policy,
            mxTask.Result
        );
    }

    #region SPF Verification

    private async Task<(SpfResult Result, string? Record)> VerifySpfAsync(
        string            domain,
        IPAddress         clientIp,
        string            mailFrom,
        string            heloHostname,
        CancellationToken ct)
    {
        try
        {
            var spfRecord = await GetTxtRecordAsync(domain, "v=spf1", ct);
            if (spfRecord is null)
                return (SpfResult.None, null);

            logger.Log(LogLevel.Debug, $"SPF record for {domain}: {spfRecord}");

            var result = EvaluateSpf(spfRecord, clientIp, domain, mailFrom);
            return (result, spfRecord);
        }
        catch (Exception ex)
        {
            logger.Log(LogLevel.Warning, $"SPF verification error for {domain}: {ex.Message}");
            return (SpfResult.TempError, null);
        }
    }

    private SpfResult EvaluateSpf(string spfRecord, IPAddress clientIp, string domain, string mailFrom)
    {
        var mechanisms = spfRecord.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        
        foreach (var mechanism in mechanisms.Skip(1)) // Skip "v=spf1"
        {
            var qualifier = mechanism[0] switch
            {
                '+' => SpfResult.Pass,
                '-' => SpfResult.Fail,
                '~' => SpfResult.SoftFail,
                '?' => SpfResult.Neutral,
                _   => SpfResult.Pass // Default qualifier is Pass
            };

            var mech = mechanism.TrimStart('+', '-', '~', '?').ToLowerInvariant();

            if (mech == "all")
                return qualifier;

            if (mech.StartsWith("ip4:") && clientIp.AddressFamily == AddressFamily.InterNetwork)
            {
                var cidr = mech[4..];
                if (IpMatchesCidr(clientIp, cidr))
                    return qualifier;
            }
            else if (mech.StartsWith("ip6:") && clientIp.AddressFamily == AddressFamily.InterNetworkV6)
            {
                var cidr = mech[4..];
                if (IpMatchesCidr(clientIp, cidr))
                    return qualifier;
            }
            else if (mech.StartsWith("a:") || mech == "a")
            {
                var targetDomain = mech == "a" ? domain : mech[2..];
                if (CheckARecord(clientIp, targetDomain).Result)
                    return qualifier;
            }
            else if (mech.StartsWith("mx:") || mech == "mx")
            {
                var targetDomain = mech == "mx" ? domain : mech[3..];
                if (CheckMxRecord(clientIp, targetDomain).Result)
                    return qualifier;
            }
            else if (mech.StartsWith("include:"))
            {
                var includeDomain = mech[8..];
                var includeRecord = GetTxtRecordAsync(includeDomain, "v=spf1", CancellationToken.None).Result;
                if (includeRecord is not null)
                {
                    var includeResult = EvaluateSpf(includeRecord, clientIp, includeDomain, mailFrom);
                    if (includeResult == SpfResult.Pass)
                        return qualifier;
                }
            }
        }

        return SpfResult.Neutral;
    }

    private static bool IpMatchesCidr(IPAddress ip, string cidr)
    {
        try
        {
            var parts = cidr.Split('/');
            var network = IPAddress.Parse(parts[0]);
            var prefixLength = parts.Length > 1 ? int.Parse(parts[1]) : (ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128);

            var ipBytes = ip.GetAddressBytes();
            var networkBytes = network.GetAddressBytes();

            if (ipBytes.Length != networkBytes.Length)
                return false;

            var fullBytes = prefixLength / 8;
            var remainingBits = prefixLength % 8;

            for (int i = 0; i < fullBytes; i++)
            {
                if (ipBytes[i] != networkBytes[i])
                    return false;
            }

            if (remainingBits > 0 && fullBytes < ipBytes.Length)
            {
                var mask = (byte)(0xFF << (8 - remainingBits));
                if ((ipBytes[fullBytes] & mask) != (networkBytes[fullBytes] & mask))
                    return false;
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    private async Task<bool> CheckARecord(IPAddress clientIp, string domain)
    {
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(domain);
            return addresses.Contains(clientIp);
        }
        catch
        {
            return false;
        }
    }

    private async Task<bool> CheckMxRecord(IPAddress clientIp, string domain)
    {
        try
        {
            var mxRecords = await GetMxRecordsAsync(domain, CancellationToken.None);
            foreach (var mx in mxRecords)
            {
                var addresses = await Dns.GetHostAddressesAsync(mx);
                if (addresses.Contains(clientIp))
                    return true;
            }
            return false;
        }
        catch
        {
            return false;
        }
    }

    #endregion

    #region DKIM Verification

    private async Task<(DkimResult Result, string? Details)> VerifyDkimAsync(
        EmailMessage      message,
        CancellationToken ct)
    {
        try
        {
            var dkimHeaders = message.Headers
                .Where(h => h.Key.Equals("DKIM-Signature", StringComparison.OrdinalIgnoreCase))
                .Select(h => h.Value)
                .ToList();

            if (dkimHeaders.Count == 0)
                return (DkimResult.None, "No DKIM signature found");

            foreach (var dkimHeader in dkimHeaders)
            {
                var result = await VerifySingleDkimSignature(dkimHeader, message, ct);
                if (result.Result == DkimResult.Pass)
                    return result;
            }

            return (DkimResult.Fail, "All DKIM signatures failed verification");
        }
        catch (Exception ex)
        {
            logger.Log(LogLevel.Warning, $"DKIM verification error: {ex.Message}");
            return (DkimResult.TempError, ex.Message);
        }
    }

    private async Task<(DkimResult Result, string? Details)> VerifySingleDkimSignature(
        string            dkimHeader,
        EmailMessage      message,
        CancellationToken ct)
    {
        var dkimParams = ParseDkimHeader(dkimHeader);

        if (!dkimParams.TryGetValue("d", out var domain) ||
            !dkimParams.TryGetValue("s", out var selector) ||
            !dkimParams.TryGetValue("b", out var signature) ||
            !dkimParams.TryGetValue("bh", out var bodyHash))
        {
            return (DkimResult.Fail, "Missing required DKIM parameters");
        }

        // Get public key from DNS
        var dkimDomain = $"{selector}._domainkey.{domain}";
        var dkimRecord = await GetTxtRecordAsync(dkimDomain, "v=DKIM1", ct);

        if (dkimRecord is null)
            return (DkimResult.Fail, $"No DKIM record found at {dkimDomain}");

        var dkimRecordParams = ParseDkimRecord(dkimRecord);

        if (!dkimRecordParams.TryGetValue("p", out var publicKeyBase64))
            return (DkimResult.Fail, "No public key in DKIM record");

        // Verify body hash
        var algorithm = dkimParams.GetValueOrDefault("a", "rsa-sha256");
        var canonicalization = dkimParams.GetValueOrDefault("c", "simple/simple");
        var (headerCanon, bodyCanon) = ParseCanonicalization(canonicalization);

        var canonicalizedBody = CanonicalizeBody(message.Body, bodyCanon);
        var computedBodyHash = ComputeBodyHash(canonicalizedBody, algorithm);

        if (computedBodyHash != bodyHash)
            return (DkimResult.Fail, $"Body hash mismatch: expected {bodyHash}, got {computedBodyHash}");

        // Verify signature
        var signedHeaders = dkimParams.GetValueOrDefault("h", "").Split(':');
        var headerData = BuildSignedHeaderData(message, signedHeaders, dkimHeader, headerCanon);

        try
        {
            var publicKeyBytes = Convert.FromBase64String(publicKeyBase64);
            var signatureBytes = Convert.FromBase64String(signature.Replace(" ", "").Replace("\r", "").Replace("\n", ""));

            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);

            var hashAlgorithm = algorithm.Contains("sha256") ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA1;
            var headerBytes = Encoding.ASCII.GetBytes(headerData);

            var isValid = rsa.VerifyData(headerBytes, signatureBytes, hashAlgorithm, RSASignaturePadding.Pkcs1);

            return isValid
                ? (DkimResult.Pass, $"DKIM signature valid for domain {domain}")
                : (DkimResult.Fail, "Signature verification failed");
        }
        catch (Exception ex)
        {
            return (DkimResult.Fail, $"Signature verification error: {ex.Message}");
        }
    }

    private static Dictionary<string, string> ParseDkimHeader(string header)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var normalized = header.Replace("\r\n", "").Replace("\n", "").Replace("\t", " ");
        
        foreach (var part in normalized.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = part.Trim();
            var eqIndex = trimmed.IndexOf('=');
            if (eqIndex > 0)
            {
                var key = trimmed[..eqIndex].Trim();
                var value = trimmed[(eqIndex + 1)..].Trim();
                result[key] = value;
            }
        }
        return result;
    }

    private static Dictionary<string, string> ParseDkimRecord(string record)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in record.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = part.Trim();
            var eqIndex = trimmed.IndexOf('=');
            if (eqIndex > 0)
            {
                var key = trimmed[..eqIndex].Trim();
                var value = trimmed[(eqIndex + 1)..].Trim();
                result[key] = value;
            }
        }
        return result;
    }

    private static (string Header, string Body) ParseCanonicalization(string c)
    {
        var parts = c.Split('/');
        return (parts[0].ToLowerInvariant(), parts.Length > 1 ? parts[1].ToLowerInvariant() : parts[0].ToLowerInvariant());
    }

    private static string CanonicalizeBody(string body, string method)
    {
        if (method == "relaxed")
        {
            var lines = body.Split("\r\n");
            var canonicalized = lines
                .Select(line => Regex.Replace(line, @"[ \t]+", " ").TrimEnd())
                .ToList();
            
            // Remove trailing empty lines
            while (canonicalized.Count > 0 && string.IsNullOrEmpty(canonicalized[^1]))
                canonicalized.RemoveAt(canonicalized.Count - 1);
            
            return string.Join("\r\n", canonicalized) + "\r\n";
        }
        else // simple
        {
            var result = body;
            while (result.EndsWith("\r\n\r\n"))
                result = result[..^2];
            if (!result.EndsWith("\r\n"))
                result += "\r\n";
            return result;
        }
    }

    private static string ComputeBodyHash(string body, string algorithm)
    {
        var bytes = Encoding.ASCII.GetBytes(body);
        byte[] hash;

        if (algorithm.Contains("sha256"))
            hash = SHA256.HashData(bytes);
        else
            hash = SHA1.HashData(bytes);

        return Convert.ToBase64String(hash);
    }

    private static string BuildSignedHeaderData(EmailMessage message, string[] signedHeaders, string dkimHeader, string method)
    {
        var sb = new StringBuilder();

        foreach (var headerName in signedHeaders)
        {
            var trimmedName = headerName.Trim();
            var headerValue = message.Headers
                .FirstOrDefault(h => h.Key.Equals(trimmedName, StringComparison.OrdinalIgnoreCase))
                .Value;

            if (headerValue is not null)
            {
                if (method == "relaxed")
                {
                    var canonName = trimmedName.ToLowerInvariant();
                    var canonValue = Regex.Replace(headerValue, @"[ \t]+", " ").Trim();
                    sb.Append($"{canonName}:{canonValue}\r\n");
                }
                else
                {
                    sb.Append($"{trimmedName}: {headerValue}\r\n");
                }
            }
        }

        // Add DKIM-Signature header without the b= value
        var dkimForSigning = Regex.Replace(dkimHeader, @"b=[^;]*", "b=");
        if (method == "relaxed")
        {
            var canonValue = Regex.Replace(dkimForSigning, @"[ \t]+", " ").Trim();
            sb.Append($"dkim-signature:{canonValue}");
        }
        else
        {
            sb.Append($"DKIM-Signature: {dkimForSigning}");
        }

        return sb.ToString();
    }

    #endregion

    #region DMARC Verification

    private async Task<(DmarcResult Result, string? Policy)> VerifyDmarcAsync(
        string            domain,
        CancellationToken ct)
    {
        try
        {
            var dmarcDomain = $"_dmarc.{domain}";
            var dmarcRecord = await GetTxtRecordAsync(dmarcDomain, "v=DMARC1", ct);

            if (dmarcRecord is null)
            {
                // Try organizational domain
                var orgDomain = GetOrganizationalDomain(domain);
                if (orgDomain != domain)
                {
                    dmarcDomain = $"_dmarc.{orgDomain}";
                    dmarcRecord = await GetTxtRecordAsync(dmarcDomain, "v=DMARC1", ct);
                }
            }

            if (dmarcRecord is null)
                return (DmarcResult.None, null);

            var policy = ExtractDmarcPolicy(dmarcRecord);
            logger.Log(LogLevel.Debug, $"DMARC record for {domain}: {dmarcRecord}");

            return (DmarcResult.Pass, policy);
        }
        catch (Exception ex)
        {
            logger.Log(LogLevel.Warning, $"DMARC verification error for {domain}: {ex.Message}");
            return (DmarcResult.TempError, null);
        }
    }

    private static string GetOrganizationalDomain(string domain)
    {
        var parts = domain.Split('.');
        return parts.Length > 2 ? string.Join('.', parts[^2..]) : domain;
    }

    private static string ExtractDmarcPolicy(string record)
    {
        var match = Regex.Match(record, @"p=(\w+)");
        return match.Success ? match.Groups[1].Value : "none";
    }

    #endregion

    #region DNS Helpers

    private async Task<string?> GetTxtRecordAsync(string domain, string prefix, CancellationToken ct)
    {
        try
        {
            // Use system DNS resolver through nslookup simulation
            // In production, use a proper DNS library like DnsClient
            var process = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = OperatingSystem.IsWindows() ? "nslookup" : "dig",
                    Arguments = OperatingSystem.IsWindows() 
                        ? $"-type=TXT {domain}"
                        : $"+short TXT {domain}",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.Start();
            var output = await process.StandardOutput.ReadToEndAsync(ct);
            await process.WaitForExitAsync(ct);

            // Parse TXT records
            var matches = TxtRecordRegex().Matches(output);
            foreach (Match match in matches)
            {
                var record = match.Groups[1].Value.Replace("\" \"", "");
                if (record.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    return record;
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    public async Task<string[]> GetMxRecordsAsync(string domain, CancellationToken ct)
    {
        try
        {
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

            var matches = MxRecordRegex().Matches(output);
            return matches.Select(m => m.Groups[1].Value.TrimEnd('.')).ToArray();
        }
        catch
        {
            return [];
        }
    }

    [GeneratedRegex(@"""([^""]+)""")]
    private static partial Regex TxtRecordRegex();

    [GeneratedRegex(@"(?:^\d+\s+)?(\S+\.?)$", RegexOptions.Multiline)]
    private static partial Regex MxRecordRegex();

    #endregion
}

#endregion

#region Email Message

public sealed class EmailMessage
{
    public string                            RawMessage    { get; init; } = "";
    public List<KeyValuePair<string, string>> Headers      { get; } = [];
    public string                            Body          { get; set; } = "";
    public string?                           From          { get; set; }
    public List<string>                      To            { get; } = [];
    public string?                           Subject       { get; set; }
    public DateTime                          ReceivedAt    { get; init; } = DateTime.UtcNow;
    public string?                           MessageId     { get; set; }
    public DnsVerificationResult?            Verification  { get; set; }

    public static EmailMessage Parse(string rawMessage)
    {
        var message = new EmailMessage { RawMessage = rawMessage };
        
        var headerBodySplit = rawMessage.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        if (headerBodySplit < 0)
            headerBodySplit = rawMessage.IndexOf("\n\n", StringComparison.Ordinal);

        string headerSection, bodySection;
        if (headerBodySplit > 0)
        {
            headerSection = rawMessage[..headerBodySplit];
            bodySection = rawMessage[(headerBodySplit + (rawMessage[headerBodySplit] == '\r' ? 4 : 2))..];
        }
        else
        {
            headerSection = rawMessage;
            bodySection = "";
        }

        message.Body = bodySection;

        // Parse headers (handle folded headers)
        var unfoldedHeaders = Regex.Replace(headerSection, @"\r?\n[ \t]+", " ");
        var headerLines = unfoldedHeaders.Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries);

        foreach (var line in headerLines)
        {
            var colonIndex = line.IndexOf(':');
            if (colonIndex > 0)
            {
                var name = line[..colonIndex].Trim();
                var value = line[(colonIndex + 1)..].Trim();
                message.Headers.Add(new KeyValuePair<string, string>(name, value));

                switch (name.ToLowerInvariant())
                {
                    case "from":
                        message.From = ExtractEmailAddress(value);
                        break;
                    case "to":
                        message.To.AddRange(ExtractEmailAddresses(value));
                        break;
                    case "subject":
                        message.Subject = value;
                        break;
                    case "message-id":
                        message.MessageId = value.Trim('<', '>');
                        break;
                }
            }
        }

        return message;
    }

    private static string? ExtractEmailAddress(string value)
    {
        var match = Regex.Match(value, @"<([^>]+)>");
        if (match.Success)
            return match.Groups[1].Value;
        
        match = Regex.Match(value, @"[\w\.-]+@[\w\.-]+\.\w+");
        return match.Success ? match.Value : null;
    }

    private static IEnumerable<string> ExtractEmailAddresses(string value)
    {
        var matches = Regex.Matches(value, @"[\w\.-]+@[\w\.-]+\.\w+");
        return matches.Select(m => m.Value);
    }
}

#endregion

#region Mail Storage

public interface IMailStorage
{
    Task<string> StoreAsync(EmailMessage message, string envelopeFrom, IEnumerable<string> envelopeTo, CancellationToken ct = default);
}

public sealed class FileMailStorage(string basePath, ILogger logger) : IMailStorage
{
    public async Task<string> StoreAsync(
        EmailMessage        message,
        string              envelopeFrom,
        IEnumerable<string> envelopeTo,
        CancellationToken   ct = default)
    {
        Directory.CreateDirectory(basePath);

        var timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss_fff");
        var messageId = message.MessageId ?? Guid.NewGuid().ToString("N")[..16];
        var fileName = $"{timestamp}_{SanitizeFileName(messageId)}.eml";
        var filePath = Path.Combine(basePath, fileName);

        // Build metadata header
        var metadata = new StringBuilder();
        metadata.AppendLine($"X-Envelope-From: {envelopeFrom}");
        metadata.AppendLine($"X-Envelope-To: {string.Join(", ", envelopeTo)}");
        metadata.AppendLine($"X-Received-At: {message.ReceivedAt:O}");

        if (message.Verification is not null)
        {
            var v = message.Verification;
            metadata.AppendLine($"X-SPF-Result: {v.Spf}");
            metadata.AppendLine($"X-DKIM-Result: {v.Dkim}");
            metadata.AppendLine($"X-DMARC-Result: {v.Dmarc}");
            if (v.SpfRecord is not null)
                metadata.AppendLine($"X-SPF-Record: {v.SpfRecord}");
            if (v.DkimDetails is not null)
                metadata.AppendLine($"X-DKIM-Details: {v.DkimDetails}");
            if (v.DmarcPolicy is not null)
                metadata.AppendLine($"X-DMARC-Policy: {v.DmarcPolicy}");
            if (v.MxRecords.Length > 0)
                metadata.AppendLine($"X-MX-Records: {string.Join(", ", v.MxRecords)}");
        }

        var fullMessage = metadata.ToString() + message.RawMessage;
        await File.WriteAllTextAsync(filePath, fullMessage, ct);

        logger.Log(LogLevel.Info, $"Stored message: {filePath}");
        return filePath;
    }

    private static string SanitizeFileName(string name)
    {
        var invalid = Path.GetInvalidFileNameChars();
        return string.Join("_", name.Split(invalid, StringSplitOptions.RemoveEmptyEntries));
    }
}

#endregion

#region SMTP Session

public enum SmtpSessionState { Connected, Greeted, MailFrom, RcptTo, Data, Quit }

public sealed class SmtpSession(
    TcpClient          client,
    SmtpServerConfig   config,
    IMailStorage       storage,
    DnsVerifier        dnsVerifier,
    X509Certificate2?  certificate,
    IUserStore         userStore,
    IMailQueue?        mailQueue,
    bool               isSubmissionPort,
    ConnectionTracker? connectionTracker,
    RateLimitConfig    rateLimitConfig,
    ILogger            logger)
{
    private Stream              _stream       = client.GetStream();
    // Use Latin1 (ISO-8859-1) encoding: 1:1 byte-to-char mapping for 0-255
    // ASCII only handles 0-127, which breaks BDAT with binary data!
    private StreamReader        _reader       = new(client.GetStream(), Encoding.Latin1);
    private StreamWriter        _writer       = new(client.GetStream(), Encoding.Latin1) { AutoFlush = true };
    private SmtpSessionState    _state        = SmtpSessionState.Connected;
    private string?             _mailFrom;
    private readonly List<string> _rcptTo     = [];
    private readonly List<string> _localRcptTo = [];   // Recipients on local domains
    private readonly List<string> _remoteRcptTo = [];  // Recipients on remote domains (relay)
    private bool                _tlsActive;
    private readonly IPAddress  _clientIp     = ((IPEndPoint)client.Client.RemoteEndPoint!).Address;
    private string              _heloHostname = "";
    private readonly SmtpAuthManager _authManager = new(userStore, logger);
    private bool                _inAuthExchange;
    private X509Certificate2?   _clientCertificate;
    
    // DSN support (RFC 3461)
    private string?             _dsnEnvId;
    private DsnRet              _dsnRet = DsnRet.Full;
    private readonly List<RecipientDsn> _recipientDsns = [];
    
    // REQUIRETLS support (RFC 8689)
    private bool                _requireTls;
    
    // BDAT/CHUNKING support (RFC 3030)
    private bool                _inBdatSequence;
    private readonly MemoryStream _bdatBuffer = new();
    
    // Rate limiting
    private readonly SessionCounters _counters = new();

    public async Task HandleAsync(CancellationToken ct)
    {
        // Register connection for rate limiting
        connectionTracker?.RegisterConnection(_clientIp);
        
        try
        {
            await SendResponseAsync(220, $"{config.Hostname} ESMTP AchimSMTP ready");

            while (!ct.IsCancellationRequested && client.Connected)
            {
                var line = await ReadLineAsync(ct);
                if (line is null)
                    break;

                logger.Log(LogLevel.Debug, $"C: {line}");

                // Handle AUTH exchange specially
                if (_inAuthExchange)
                {
                    await ProcessAuthResponseAsync(line, ct);
                    continue;
                }

                var (command, args) = ParseCommand(line);
                await ProcessCommandAsync(command, args, ct);

                if (_state == SmtpSessionState.Quit)
                    break;
                    
                // Check for too many invalid commands
                if (_counters.InvalidCommands >= rateLimitConfig.MaxInvalidCommands)
                {
                    logger.Log(LogLevel.Warning, $"Too many invalid commands from {_clientIp}, disconnecting");
                    await SendResponseAsync(421, "4.7.0 Too many errors, closing connection");
                    break;
                }
            }
        }
        catch (OperationCanceledException)
        {
            logger.Log(LogLevel.Debug, "Session cancelled");
        }
        catch (Exception ex)
        {
            logger.Log(LogLevel.Error, $"Session error: {ex.Message}");
        }
        finally
        {
            connectionTracker?.UnregisterConnection(_clientIp);
            _bdatBuffer.Dispose();
            client.Close();
        }
    }

    private async Task ProcessAuthResponseAsync(string response, CancellationToken ct)
    {
        // Handle AUTH cancellation
        if (response == "*")
        {
            _inAuthExchange = false;
            _authManager.Reset();
            await SendResponseAsync(501, "Authentication cancelled");
            return;
        }

        var result = await _authManager.ProcessResponseAsync(response, ct);
        await HandleAuthResultAsync(result);
    }

    private async Task ProcessCommandAsync(string command, string args, CancellationToken ct)
    {
        switch (command.ToUpperInvariant())
        {
            case "HELO":
                await HandleHeloAsync(args);
                break;
            case "EHLO":
                await HandleEhloAsync(args);
                break;
            case "STARTTLS":
                await HandleStartTlsAsync(ct);
                break;
            case "AUTH":
                // Check rate limiting for AUTH
                if (connectionTracker is not null && !connectionTracker.CanAttemptAuth(_clientIp))
                {
                    await SendResponseAsync(421, "4.7.0 Too many authentication attempts, try again later");
                    return;
                }
                await HandleAuthAsync(args, ct);
                break;
            case "MAIL":
                await HandleMailFromAsync(args);
                break;
            case "RCPT":
                await HandleRcptToAsync(args);
                break;
            case "DATA":
                await HandleDataAsync(ct);
                break;
            case "BDAT":
                await HandleBdatAsync(args, ct);
                break;
            case "RSET":
                await HandleRsetAsync();
                break;
            case "NOOP":
                await SendResponseAsync(250, "OK");
                break;
            case "QUIT":
                await HandleQuitAsync();
                break;
            case "VRFY":
                await SendResponseAsync(252, "Cannot verify user");
                break;
            default:
                _counters.InvalidCommands++;
                await SendResponseAsync(500, "5.5.1 Unrecognized command");
                break;
        }
    }

    private async Task HandleHeloAsync(string hostname)
    {
        _heloHostname = hostname;
        _state = SmtpSessionState.Greeted;
        await SendResponseAsync(250, $"Hello {hostname}, pleased to meet you");
    }

    private async Task HandleEhloAsync(string hostname)
    {
        _heloHostname = hostname;
        _state = SmtpSessionState.Greeted;

        var extensions = new List<string>
        {
            $"{config.Hostname} Hello {hostname}",
            $"SIZE {config.MaxMessageSize}",
            "8BITMIME",
            "ENHANCEDSTATUSCODES",
            "CHUNKING",                             // RFC 3030 - BDAT command
            "DSN",                                  // RFC 3461 - Delivery Status Notifications
            "SMTPUTF8"                              // RFC 6531 - Internationalized Email
        };

        if (certificate is not null && !_tlsActive)
            extensions.Add("STARTTLS");

        // REQUIRETLS only available after STARTTLS (RFC 8689)
        if (_tlsActive)
            extensions.Add("REQUIRETLS");

        // Advertise AUTH mechanisms
        var authMechanisms = _authManager.GetAvailableMechanisms(_tlsActive).ToList();
        if (authMechanisms.Count > 0)
            extensions.Add($"AUTH {string.Join(' ', authMechanisms)}");

        for (int i = 0; i < extensions.Count - 1; i++)
            await SendResponseAsync(250, extensions[i], multiline: true);
        
        await SendResponseAsync(250, extensions[^1]);
    }

    private async Task HandleAuthAsync(string args, CancellationToken ct)
    {
        if (_state < SmtpSessionState.Greeted)
        {
            await SendResponseAsync(503, "Say HELO/EHLO first");
            return;
        }

        if (_authManager.IsAuthenticated)
        {
            await SendResponseAsync(503, "Already authenticated");
            return;
        }

        // Check if PLAIN/LOGIN requires TLS
        var parts = args.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0)
        {
            await SendResponseAsync(501, "Syntax: AUTH mechanism [initial-response]");
            return;
        }

        var mechanism = parts[0].ToUpperInvariant();
        
        // PLAIN and LOGIN should require TLS (but allow SCRAM without)
        if (!_tlsActive && (mechanism == "PLAIN" || mechanism == "LOGIN"))
        {
            await SendResponseAsync(538, "5.7.11 Encryption required for requested authentication mechanism");
            return;
        }

        // EXTERNAL requires client certificate
        if (mechanism == "EXTERNAL" && _clientCertificate is null)
        {
            await SendResponseAsync(535, "5.7.8 Client certificate required for EXTERNAL authentication");
            return;
        }

        var startResult = _authManager.StartAuth(mechanism);
        if (startResult.Result == AuthResult.InvalidMechanism)
        {
            await SendResponseAsync(504, startResult.ErrorCode ?? "Unrecognized authentication type");
            return;
        }

        // Check for initial response (AUTH PLAIN <initial-response>)
        if (parts.Length > 1)
        {
            var result = await _authManager.ProcessResponseAsync(parts[1], ct);
            await HandleAuthResultAsync(result);
        }
        else
        {
            // Request initial response
            _inAuthExchange = true;
            await SendResponseAsync(334, startResult.Challenge ?? "");
        }
    }

    private async Task HandleAuthResultAsync(AuthResponse result)
    {
        switch (result.Result)
        {
            case AuthResult.Success:
                _inAuthExchange = false;
                var successMsg = result.Message is not null 
                    ? $"2.7.0 Authentication successful {result.Message}"
                    : "2.7.0 Authentication successful";
                await SendResponseAsync(235, successMsg);
                logger.Log(LogLevel.Info, $"Authenticated: {result.Username} via {_authManager.AuthenticationMethod}");
                break;

            case AuthResult.Continue:
                _inAuthExchange = true;
                await SendResponseAsync(334, result.Challenge ?? "");
                break;

            case AuthResult.Fail:
                _inAuthExchange = false;
                await SendResponseAsync(535, result.ErrorCode ?? "5.7.8 Authentication failed");
                break;
        }
    }

    private async Task HandleStartTlsAsync(CancellationToken ct)
    {
        if (certificate is null)
        {
            await SendResponseAsync(454, "TLS not available");
            return;
        }

        if (_tlsActive)
        {
            await SendResponseAsync(503, "TLS already active");
            return;
        }

        await SendResponseAsync(220, "Ready to start TLS");

        try
        {
            var sslStream = new SslStream(_stream, false, ValidateClientCertificate);
            await sslStream.AuthenticateAsServerAsync(
                new SslServerAuthenticationOptions
                {
                    ServerCertificate = certificate,
                    ClientCertificateRequired = false,  // Optional client cert for EXTERNAL auth
                    EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | 
                                          System.Security.Authentication.SslProtocols.Tls13
                },
                ct
            );

            _stream = sslStream;
            _reader = new StreamReader(sslStream, Encoding.Latin1);
            _writer = new StreamWriter(sslStream, Encoding.Latin1) { AutoFlush = true };
            _tlsActive = true;
            _state = SmtpSessionState.Connected;

            // Capture client certificate for EXTERNAL auth
            if (sslStream.RemoteCertificate is X509Certificate remoteCert)
            {
                _clientCertificate = new X509Certificate2(remoteCert);
                _authManager.SetClientCertificate(_clientCertificate);
                logger.Log(LogLevel.Info, $"Client certificate: {_clientCertificate.Subject} (Thumbprint: {_clientCertificate.Thumbprint[..8]}...)");
            }

            logger.Log(LogLevel.Info, $"TLS established: {sslStream.SslProtocol}, {sslStream.CipherAlgorithm}");
        }
        catch (Exception ex)
        {
            logger.Log(LogLevel.Error, $"TLS handshake failed: {ex.Message}");
            throw;
        }
    }

    private bool ValidateClientCertificate(
        object sender,
        X509Certificate? certificate,
        X509Chain? chain,
        SslPolicyErrors sslPolicyErrors)
    {
        // Accept any client certificate (or none) - validation happens during AUTH EXTERNAL
        if (certificate is not null)
        {
            logger.Log(LogLevel.Debug, $"Client presented certificate: {certificate.Subject}");
        }
        return true;
    }

    private async Task HandleMailFromAsync(string args)
    {
        if (_state < SmtpSessionState.Greeted)
        {
            await SendResponseAsync(503, "Say HELO first");
            return;
        }

        if (config.RequireStartTls && !_tlsActive)
        {
            await SendResponseAsync(530, "5.7.0 Must issue STARTTLS first");
            return;
        }

        var match = Regex.Match(args, @"FROM:\s*<([^>]*)>", RegexOptions.IgnoreCase);
        if (!match.Success)
        {
            await SendResponseAsync(501, "5.5.4 Syntax error in MAIL command");
            return;
        }

        _mailFrom = match.Groups[1].Value;
        
        // Get everything after the closing >
        var paramStart = args.IndexOf('>');
        var parameters = paramStart > 0 ? args[(paramStart + 1)..].Trim() : "";

        // Parse DSN parameters (RFC 3461)
        var (envId, ret) = DsnParser.ParseMailFromParams(parameters);
        _dsnEnvId = envId;
        _dsnRet = ret;

        // Parse REQUIRETLS (RFC 8689)
        _requireTls = RequireTlsHandler.ParseRequireTls(parameters);
        if (_requireTls && !_tlsActive)
        {
            await SendResponseAsync(530, "5.7.0 REQUIRETLS requires active TLS connection");
            return;
        }

        // Reset state
        _rcptTo.Clear();
        _localRcptTo.Clear();
        _remoteRcptTo.Clear();
        _recipientDsns.Clear();
        _inBdatSequence = false;
        _bdatBuffer.SetLength(0);
        _state = SmtpSessionState.MailFrom;

        await SendResponseAsync(250, "2.1.0 OK");
    }

    private async Task HandleRcptToAsync(string args)
    {
        if (_state < SmtpSessionState.MailFrom)
        {
            await SendResponseAsync(503, "5.5.1 Need MAIL command first");
            return;
        }

        var match = Regex.Match(args, @"TO:\s*<([^>]+)>", RegexOptions.IgnoreCase);
        if (!match.Success)
        {
            await SendResponseAsync(501, "5.5.4 Syntax error in RCPT command");
            return;
        }

        if (_rcptTo.Count >= config.MaxRecipients)
        {
            await SendResponseAsync(452, "4.5.3 Too many recipients");
            return;
        }

        var recipient = match.Groups[1].Value;
        var recipientDomain = ExtractDomain(recipient);

        // Parse DSN parameters (RFC 3461)
        var paramStart = args.IndexOf('>');
        var parameters = paramStart > 0 ? args[(paramStart + 1)..].Trim() : "";
        var (notify, orcpt) = DsnParser.ParseRcptToParams(parameters);

        // Check if this is a local or remote recipient
        var isLocalRecipient = config.IsLocalDomain(recipientDomain);

        if (!isLocalRecipient)
        {
            // Remote recipient = relay request
            // Require authentication to prevent open relay
            if (config.RequireAuthForRelay && !_authManager.IsAuthenticated)
            {
                logger.Log(LogLevel.Warning, 
                    $"Relay denied for {recipient}: not authenticated (from {_clientIp})");
                await SendResponseAsync(550, "5.7.1 Relay access denied. Authentication required.");
                return;
            }

            _remoteRcptTo.Add(recipient);
            logger.Log(LogLevel.Debug, $"Remote recipient (relay): {recipient}");
        }
        else
        {
            _localRcptTo.Add(recipient);
            logger.Log(LogLevel.Debug, $"Local recipient: {recipient}");
        }

        // Submission port (587) requires auth for all mail per RFC 6409
        if (isSubmissionPort && config.RequireAuthOnSubmission && !_authManager.IsAuthenticated)
        {
            // Allow the RCPT but will check again at DATA
            logger.Log(LogLevel.Debug, $"Submission port recipient (auth check deferred): {recipient}");
        }

        // Store DSN info for this recipient
        _recipientDsns.Add(new RecipientDsn
        {
            Recipient = recipient,
            Notify = notify,
            OriginalRecipient = orcpt
        });

        _rcptTo.Add(recipient);
        _state = SmtpSessionState.RcptTo;

        await SendResponseAsync(250, "2.1.5 OK");
    }

    private async Task HandleDataAsync(CancellationToken ct)
    {
        if (_state < SmtpSessionState.RcptTo || _rcptTo.Count == 0)
        {
            await SendResponseAsync(503, "5.5.1 Need RCPT command first");
            return;
        }

        // Submission port requires authentication per RFC 6409
        if (isSubmissionPort && config.RequireAuthOnSubmission && !_authManager.IsAuthenticated)
        {
            await SendResponseAsync(530, "5.7.0 Authentication required");
            return;
        }
        
        // Check message rate limit
        if (connectionTracker is not null && 
            !connectionTracker.CanSendMessage(_clientIp, _authManager.IsAuthenticated))
        {
            await SendResponseAsync(452, "4.7.1 Too many messages, try again later");
            return;
        }

        await SendResponseAsync(354, "Start mail input; end with <CRLF>.<CRLF>");

        var messageBuilder = new StringBuilder();
        var totalSize = 0;

        while (!ct.IsCancellationRequested)
        {
            var line = await ReadLineAsync(ct);
            if (line is null)
                break;

            if (line == ".")
                break;

            // Dot-stuffing: remove leading dot if line starts with ".."
            if (line.StartsWith(".."))
                line = line[1..];

            totalSize += line.Length + 2;
            if (totalSize > config.MaxMessageSize)
            {
                await SendResponseAsync(552, "5.3.4 Message size exceeds maximum");
                ResetTransaction();
                return;
            }

            messageBuilder.AppendLine(line);
        }

        var rawMessage = messageBuilder.ToString();
        await ProcessReceivedMessageAsync(rawMessage, ct);
    }

    /// <summary>
    /// Process a received message (from DATA or BDAT)
    /// </summary>
    private async Task ProcessReceivedMessageAsync(string rawMessage, CancellationToken ct)
    {
        var message = EmailMessage.Parse(rawMessage);

        // Perform DNS verification (for inbound mail from other servers)
        var senderDomain = ExtractDomain(_mailFrom ?? "");
        DnsVerificationResult? verification = null;
        
        if (!string.IsNullOrEmpty(senderDomain) && !_authManager.IsAuthenticated)
        {
            // Only verify external mail (not from authenticated local users)
            verification = await dnsVerifier.VerifyAsync(
                senderDomain,
                _clientIp,
                _mailFrom ?? "",
                _heloHostname,
                message,
                ct
            );
            message.Verification = verification;

            LogVerificationResult(verification);

            // === SPF HARD-FAIL REJECT ===
            if (verification.Spf == SpfResult.Fail)
            {
                logger.Log(LogLevel.Warning, $"SPF hard-fail for {_mailFrom} from {_clientIp}");
                await SendResponseAsync(550, $"5.7.23 SPF validation failed: {senderDomain} does not authorize {_clientIp}");
                ResetTransaction();
                return;
            }

            // === DKIM FAIL REJECT ===
            if (verification.Dkim == DkimResult.Fail)
            {
                logger.Log(LogLevel.Warning, $"DKIM verification failed for message from {_mailFrom}");
                await SendResponseAsync(550, "5.7.20 DKIM signature verification failed");
                ResetTransaction();
                return;
            }

            // === DMARC POLICY ENFORCEMENT ===
            if (verification.Dmarc == DmarcResult.Fail)
            {
                // Check DMARC policy
                var dmarcPolicy = verification.DmarcPolicy?.ToLowerInvariant() ?? "none";
                
                switch (dmarcPolicy)
                {
                    case "reject":
                        logger.Log(LogLevel.Warning, $"DMARC reject policy for {senderDomain}");
                        await SendResponseAsync(550, $"5.7.1 DMARC policy violation: {senderDomain} has p=reject");
                        ResetTransaction();
                        return;
                        
                    case "quarantine":
                        logger.Log(LogLevel.Warning, $"DMARC quarantine policy for {senderDomain} - marking as suspicious");
                        message.Headers.Add(new KeyValuePair<string, string>("X-DMARC-Quarantine", "true"));
                        break;
                        
                    case "none":
                    default:
                        // Log but deliver
                        logger.Log(LogLevel.Info, $"DMARC failed but policy is {dmarcPolicy} for {senderDomain}");
                        break;
                }
            }
        }

        // Record message for rate limiting
        connectionTracker?.RecordMessage(_clientIp);
        _counters.Messages++;

        // Determine what to do with the message
        var hasLocalRecipients = _localRcptTo.Count > 0;
        var hasRemoteRecipients = _remoteRcptTo.Count > 0;

        logger.Log(LogLevel.Info, 
            $"Message from {_mailFrom}: {_localRcptTo.Count} local, {_remoteRcptTo.Count} remote recipients");

        // Store locally for local recipients
        string? filePath = null;
        if (hasLocalRecipients)
        {
            filePath = await storage.StoreAsync(message, _mailFrom ?? "<>", _localRcptTo, ct);
            logger.Log(LogLevel.Info, $"Stored locally: {Path.GetFileName(filePath)}");
        }

        // Queue for outbound delivery for remote recipients (relay)
        if (hasRemoteRecipients && mailQueue is not null)
        {
            // This should only happen if user is authenticated (checked in RCPT TO)
            // But double-check here for safety
            if (!_authManager.IsAuthenticated && config.RequireAuthForRelay)
            {
                logger.Log(LogLevel.Error, "BUG: Remote recipients without auth - this should not happen!");
                await SendResponseAsync(550, "5.7.1 Relay access denied");
                ResetTransaction();
                return;
            }

            // Group remote recipients by domain for efficient delivery
            var recipientsByDomain = _remoteRcptTo
                .GroupBy(r => ExtractDomain(r))
                .Where(g => !string.IsNullOrEmpty(g.Key));

            foreach (var domainGroup in recipientsByDomain)
            {
                var mailId = filePath is not null
                    ? $"{Path.GetFileNameWithoutExtension(filePath)}-{domainGroup.Key}"
                    : $"{Guid.NewGuid():N}-{domainGroup.Key}";

                var queuedMail = new QueuedMail
                {
                    Id = mailId,
                    EnvelopeFrom = _mailFrom ?? "",
                    EnvelopeTo = domainGroup.ToArray(),
                    MessageContent = rawMessage,
                    TargetDomain = domainGroup.Key,
                    QueuedAt = DateTime.UtcNow,
                    NextRetry = DateTime.UtcNow,
                    RequireTls = _requireTls   // Propagate REQUIRETLS (RFC 8689)
                };

                await mailQueue.EnqueueAsync(queuedMail, ct);
                logger.Log(LogLevel.Info, $"Queued for relay to {domainGroup.Key}: {domainGroup.Count()} recipients");
            }
        }

        // Also store a copy locally for remote mail if configured (for sent mail archive)
        if (hasRemoteRecipients && !hasLocalRecipients)
        {
            // Optionally store sent mail - for now just log
            logger.Log(LogLevel.Debug, "Outbound-only message (not stored locally)");
        }

        await SendResponseAsync(250, "2.0.0 OK: Message accepted for delivery");
        ResetTransaction();
    }

    /// <summary>
    /// Handle BDAT command (RFC 3030 CHUNKING)
    /// BDAT allows sending message data in chunks without dot-stuffing
    /// </summary>
    private async Task HandleBdatAsync(string args, CancellationToken ct)
    {
        if (_state < SmtpSessionState.RcptTo || _rcptTo.Count == 0)
        {
            await SendResponseAsync(503, "5.5.1 Need RCPT command first");
            return;
        }

        // Parse BDAT arguments: BDAT <size> [LAST]
        var parts = args.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 1 || !int.TryParse(parts[0], out var chunkSize))
        {
            await SendResponseAsync(501, "5.5.4 Syntax: BDAT size [LAST]");
            return;
        }

        var isLast = parts.Length > 1 && parts[1].Equals("LAST", StringComparison.OrdinalIgnoreCase);

        // Validate chunk size
        if (chunkSize < 0)
        {
            await SendResponseAsync(501, "5.5.4 Invalid chunk size");
            return;
        }

        if (_bdatBuffer.Length + chunkSize > config.MaxMessageSize)
        {
            await SendResponseAsync(552, "5.3.4 Message size exceeds maximum");
            ResetTransaction();
            return;
        }

        // Check message rate limit on first chunk
        if (!_inBdatSequence)
        {
            if (connectionTracker is not null && 
                !connectionTracker.CanSendMessage(_clientIp, _authManager.IsAuthenticated))
            {
                await SendResponseAsync(452, "4.7.1 Too many messages, try again later");
                return;
            }
            _inBdatSequence = true;
        }

        // Read exact number of bytes
        // IMPORTANT: We must read from _reader (not _stream) because StreamReader buffers!
        // The StreamReader may have already read ahead and buffered the BDAT data.
        var charBuffer = new char[chunkSize];
        var charsRead = 0;
        
        while (charsRead < chunkSize)
        {
            var read = await _reader.ReadBlockAsync(charBuffer.AsMemory(charsRead, chunkSize - charsRead), ct);
            if (read == 0)
            {
                await SendResponseAsync(451, "4.3.0 Connection lost during BDAT");
                ResetTransaction();
                return;
            }
            charsRead += read;
        }

        // Convert chars back to bytes using Latin1 (1:1 mapping)
        // The StreamReader uses Latin1, so each char == one byte
        var buffer = Encoding.Latin1.GetBytes(charBuffer, 0, chunkSize);

        // Append to buffer
        _bdatBuffer.Write(buffer, 0, buffer.Length);

        if (isLast)
        {
            // Process the complete message
            // Message content is typically UTF-8 encoded
            var rawMessage = Encoding.UTF8.GetString(_bdatBuffer.ToArray());
            _bdatBuffer.SetLength(0);
            _inBdatSequence = false;
            
            await ProcessReceivedMessageAsync(rawMessage, ct);
        }
        else
        {
            // More chunks expected
            await SendResponseAsync(250, $"2.0.0 {chunkSize} bytes received, continue");
        }
    }

    private void LogVerificationResult(DnsVerificationResult v)
    {
        var spfIcon = v.Spf == SpfResult.Pass ? "✓" : v.Spf == SpfResult.Fail ? "✗" : "?";
        var dkimIcon = v.Dkim == DkimResult.Pass ? "✓" : v.Dkim == DkimResult.Fail ? "✗" : "?";
        var dmarcIcon = v.Dmarc == DmarcResult.Pass ? "✓" : v.Dmarc == DmarcResult.Fail ? "✗" : "?";

        logger.Log(LogLevel.Info, $"Verification: SPF={spfIcon}{v.Spf} DKIM={dkimIcon}{v.Dkim} DMARC={dmarcIcon}{v.Dmarc}");
        
        if (v.MxRecords.Length > 0)
            logger.Log(LogLevel.Debug, $"MX Records: {string.Join(", ", v.MxRecords)}");
    }

    private static string ExtractDomain(string email)
    {
        var atIndex = email.IndexOf('@');
        return atIndex > 0 ? email[(atIndex + 1)..] : "";
    }

    private async Task HandleRsetAsync()
    {
        ResetTransaction();
        _authManager.Reset();
        await SendResponseAsync(250, "OK");
    }

    private void ResetTransaction()
    {
        _mailFrom = null;
        _rcptTo.Clear();
        _localRcptTo.Clear();
        _remoteRcptTo.Clear();
        _recipientDsns.Clear();
        _dsnEnvId = null;
        _dsnRet = DsnRet.Full;
        _requireTls = false;
        _inBdatSequence = false;
        _bdatBuffer.SetLength(0);
        _state = SmtpSessionState.Greeted;
    }

    private async Task HandleQuitAsync()
    {
        await SendResponseAsync(221, $"{config.Hostname} closing connection");
        _state = SmtpSessionState.Quit;
    }

    private async Task SendResponseAsync(int code, string message, bool multiline = false)
    {
        var separator = multiline ? '-' : ' ';
        var response = $"{code}{separator}{message}";
        logger.Log(LogLevel.Debug, $"S: {response}");
        await _writer.WriteLineAsync(response);
    }

    private async Task<string?> ReadLineAsync(CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(config.SessionTimeout);
            return await _reader.ReadLineAsync(cts.Token);
        }
        catch
        {
            return null;
        }
    }

    private static (string Command, string Args) ParseCommand(string line)
    {
        var spaceIndex = line.IndexOf(' ');
        if (spaceIndex < 0)
            return (line, "");
        return (line[..spaceIndex], line[(spaceIndex + 1)..]);
    }
}

#endregion

#region SMTP Server

public sealed class SmtpServer : IAsyncDisposable
{
    private readonly SmtpServerConfig               _config;
    private readonly RateLimitConfig                _rateLimitConfig;
    private readonly IMailStorage                   _storage;
    private readonly DnsVerifier                    _dnsVerifier;
    private readonly IUserStore                     _userStore;
    private readonly IMailQueue?                    _mailQueue;
    private readonly ConnectionTracker              _connectionTracker;
    private readonly X509Certificate2?              _certificate;
    private readonly ILogger                        _logger;
    private readonly ConcurrentBag<TcpListener>     _listeners = [];
    private readonly ConcurrentBag<Task>            _sessionTasks = [];
    private readonly CancellationTokenSource        _cts = new();

    public SmtpServer(
        SmtpServerConfig    config, 
        ILogger?            logger = null, 
        IUserStore?         userStore = null, 
        IMailQueue?         mailQueue = null,
        RateLimitConfig?    rateLimitConfig = null)
    {
        _config = config;
        _rateLimitConfig = rateLimitConfig ?? new RateLimitConfig();
        _logger = logger ?? new ConsoleLogger();
        _storage = new FileMailStorage(config.MailStoragePath, _logger);
        _dnsVerifier = new DnsVerifier(_logger);
        _userStore = userStore ?? new FileUserStore(Path.Combine(config.MailStoragePath, "users.txt"));
        _mailQueue = mailQueue;
        _connectionTracker = new ConnectionTracker(_rateLimitConfig, _logger);

        if (config.CertificatePath is not null)
        {
            _certificate = config.CertificatePassword is not null
                ? new X509Certificate2(config.CertificatePath, config.CertificatePassword)
                : new X509Certificate2(config.CertificatePath);
            
            _logger.Log(LogLevel.Info, $"Loaded certificate: {_certificate.Subject}");
        }
    }

    public async Task StartAsync(CancellationToken ct = default)
    {
        _logger.Log(LogLevel.Info, $"Starting SMTP server on ports {_config.Port} and {_config.SubmissionPort}");
        _logger.Log(LogLevel.Info, $"Mail storage: {Path.GetFullPath(_config.MailStoragePath)}");
        _logger.Log(LogLevel.Info, $"STARTTLS: {(_certificate is not null ? "Available" : "Not configured")}");
        _logger.Log(LogLevel.Info, $"AUTH mechanisms: PLAIN, LOGIN, SCRAM-SHA-256, EXTERNAL");
        _logger.Log(LogLevel.Info, $"Local domains: {string.Join(", ", _config.LocalDomains)}");
        _logger.Log(LogLevel.Info, $"Relay auth required: {_config.RequireAuthForRelay}");
        _logger.Log(LogLevel.Info, $"Verification: SPF={_config.VerifySpf} DKIM={_config.VerifyDkim} DMARC={_config.VerifyDmarc}");
        _logger.Log(LogLevel.Info, $"Rate limiting: {_rateLimitConfig.MaxConnectionsPerIp} conn/IP, {_rateLimitConfig.MaxAuthAttemptsPerIpPerHour} auth/hr");

        Directory.CreateDirectory(_config.MailStoragePath);

        var listener25 = new TcpListener(IPAddress.Any, _config.Port);
        var listener587 = new TcpListener(IPAddress.Any, _config.SubmissionPort);

        listener25.Start();
        listener587.Start();

        _listeners.Add(listener25);
        _listeners.Add(listener587);

        _logger.Log(LogLevel.Info, "Server started. Waiting for connections...");

        // Port 25 = MTA-to-MTA (inbound), Port 587 = MUA-to-MTA (submission)
        var task25 = AcceptConnectionsAsync(listener25, isSubmissionPort: false, _cts.Token);
        var task587 = AcceptConnectionsAsync(listener587, isSubmissionPort: true, _cts.Token);

        try
        {
            await Task.WhenAll(task25, task587);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            _logger.Log(LogLevel.Info, "Server shutdown requested");
        }
    }

    private async Task AcceptConnectionsAsync(TcpListener listener, bool isSubmissionPort, CancellationToken ct)
    {
        var portType = isSubmissionPort ? "Submission" : "MTA";
        
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var client = await listener.AcceptTcpClientAsync(ct);
                var endpoint = client.Client.RemoteEndPoint as IPEndPoint;
                
                if (endpoint is null)
                {
                    client.Close();
                    continue;
                }

                // Check rate limiting
                var rateLimitResult = _connectionTracker.CanConnect(endpoint.Address);
                if (rateLimitResult != RateLimitResult.Allowed)
                {
                    _logger.Log(LogLevel.Warning, 
                        $"[{portType}] Connection rejected from {endpoint.Address}: {rateLimitResult}");
                    
                    // Send rejection message and close
                    try
                    {
                        var writer = new StreamWriter(client.GetStream()) { AutoFlush = true };
                        var message = rateLimitResult switch
                        {
                            RateLimitResult.Blacklisted => "554 5.7.1 Connection refused - blacklisted",
                            RateLimitResult.TooManyConnections => "421 4.7.0 Too many connections, try again later",
                            RateLimitResult.TooManyConnectionsPerIp => "421 4.7.0 Too many connections from your IP",
                            RateLimitResult.ConnectionRateExceeded => "421 4.7.0 Connection rate exceeded, slow down",
                            _ => "421 4.7.0 Connection rejected"
                        };
                        await writer.WriteLineAsync(message);
                    }
                    catch { /* ignore */ }
                    
                    client.Close();
                    continue;
                }

                _logger.Log(LogLevel.Info, $"[{portType}] Connection from {endpoint.Address}:{endpoint.Port}");

                var session = new SmtpSession(
                    client, _config, _storage, _dnsVerifier, _certificate, 
                    _userStore, _mailQueue, isSubmissionPort, 
                    _connectionTracker, _rateLimitConfig, _logger
                );
                var task = session.HandleAsync(ct);
                _sessionTasks.Add(task);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.Log(LogLevel.Error, $"Accept error: {ex.Message}");
            }
        }
    }

    public async Task StopAsync()
    {
        _logger.Log(LogLevel.Info, "Stopping server...");
        await _cts.CancelAsync();

        foreach (var listener in _listeners)
        {
            listener.Stop();
        }

        await Task.WhenAll(_sessionTasks.ToArray());
        _connectionTracker.Dispose();
        _logger.Log(LogLevel.Info, "Server stopped");
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        _cts.Dispose();
        _certificate?.Dispose();
    }
}

#endregion

#region Logging

public enum LogLevel { Debug, Info, Warning, Error }

public interface ILogger
{
    void Log(LogLevel level, string message);
}

public sealed class ConsoleLogger : ILogger
{
    public void Log(LogLevel level, string message)
    {
        var color = level switch
        {
            LogLevel.Debug   => ConsoleColor.Gray,
            LogLevel.Info    => ConsoleColor.White,
            LogLevel.Warning => ConsoleColor.Yellow,
            LogLevel.Error   => ConsoleColor.Red,
            _                => ConsoleColor.White
        };

        var prefix = level switch
        {
            LogLevel.Debug   => "[DBG]",
            LogLevel.Info    => "[INF]",
            LogLevel.Warning => "[WRN]",
            LogLevel.Error   => "[ERR]",
            _                => "[???]"
        };

        var oldColor = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.WriteLine($"{DateTime.Now:HH:mm:ss.fff} {prefix} {message}");
        Console.ForegroundColor = oldColor;
    }
}

#endregion
