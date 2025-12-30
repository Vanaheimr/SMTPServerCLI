// DKIM Signer - Sign outgoing emails
// .NET 10 / C# 13

using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace AchimSmtpServer;

#region DKIM Configuration

public sealed record DkimConfig
{
    public required string  Domain          { get; init; }
    public required string  Selector        { get; init; }
    public required string  PrivateKeyPem   { get; init; }
    public          string  Canonicalization{ get; init; } = "relaxed/relaxed";
    public          string  SignedHeaders   { get; init; } = "from:to:subject:date:message-id:mime-version:content-type";
    public          int     BodyLengthLimit { get; init; } = 0;  // 0 = no limit
}

#endregion

#region DKIM Signer

public sealed partial class DkimSigner
{
    private readonly DkimConfig _config;
    private readonly RSA _privateKey;
    private readonly ILogger _logger;

    public DkimSigner(DkimConfig config, ILogger logger)
    {
        _config = config;
        _logger = logger;
        _privateKey = RSA.Create();
        _privateKey.ImportFromPem(config.PrivateKeyPem);
        
        logger.Log(LogLevel.Info, $"DKIM signer initialized: domain={config.Domain}, selector={config.Selector}");
    }

    public string SignMessage(string message)
    {
        try
        {
            var (headerSection, body) = SplitMessage(message);
            var headers = ParseHeaders(headerSection);

            // Parse canonicalization
            var (headerCanon, bodyCanon) = ParseCanonicalization(_config.Canonicalization);

            // Compute body hash
            var canonicalizedBody = CanonicalizeBody(body, bodyCanon);
            var bodyHash = ComputeHash(canonicalizedBody);
            var bodyHashBase64 = Convert.ToBase64String(bodyHash);

            // Build DKIM-Signature header (without b= value)
            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var dkimHeaderValue = BuildDkimHeaderValue(bodyHashBase64, timestamp);

            // Canonicalize headers and build signing input
            var signedHeaderNames = _config.SignedHeaders.Split(':');
            var headerDataToSign = BuildHeaderSigningData(headers, signedHeaderNames, headerCanon);

            // Add DKIM-Signature header itself (without b= value)
            var dkimHeaderForSigning = $"dkim-signature:{CanonicalizeHeaderValue(dkimHeaderValue, headerCanon)}";
            var fullSigningData = headerDataToSign + dkimHeaderForSigning;

            // Sign
            var signature = _privateKey.SignData(
                Encoding.ASCII.GetBytes(fullSigningData),
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1
            );
            var signatureBase64 = Convert.ToBase64String(signature);

            // Format signature with line folding
            var foldedSignature = FoldBase64(signatureBase64, 76);

            // Build complete DKIM-Signature header
            var completeHeader = $"DKIM-Signature: {dkimHeaderValue}{foldedSignature}";

            _logger.Log(LogLevel.Debug, $"DKIM signature generated for domain {_config.Domain}");

            // Prepend DKIM header to message
            return completeHeader + "\r\n" + message;
        }
        catch (Exception ex)
        {
            _logger.Log(LogLevel.Error, $"DKIM signing failed: {ex.Message}");
            // Return original message if signing fails
            return message;
        }
    }

    private string BuildDkimHeaderValue(string bodyHash, long timestamp)
    {
        var sb = new StringBuilder();
        sb.Append("v=1; ");
        sb.Append("a=rsa-sha256; ");
        sb.Append($"c={_config.Canonicalization}; ");
        sb.Append($"d={_config.Domain}; ");
        sb.Append($"s={_config.Selector}; ");
        sb.Append($"t={timestamp}; ");
        sb.Append($"h={_config.SignedHeaders}; ");
        sb.Append($"bh={bodyHash}; ");
        sb.Append("b=");
        
        return sb.ToString();
    }

    #region Canonicalization

    private static (string Header, string Body) ParseCanonicalization(string c)
    {
        var parts = c.Split('/');
        var header = parts[0].ToLowerInvariant();
        var body = parts.Length > 1 ? parts[1].ToLowerInvariant() : header;
        return (header, body);
    }

    private static string CanonicalizeBody(string body, string method)
    {
        if (string.IsNullOrEmpty(body))
        {
            return "\r\n";
        }

        if (method == "relaxed")
        {
            // 1. Reduce all whitespace sequences to single space
            // 2. Remove trailing whitespace from each line
            // 3. Remove empty lines at end of body
            // 4. Ensure body ends with CRLF

            var lines = body.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
            var canonicalized = new List<string>();

            foreach (var line in lines)
            {
                // Reduce whitespace and trim trailing whitespace
                var canonLine = WhitespaceRegex().Replace(line, " ").TrimEnd();
                canonicalized.Add(canonLine);
            }

            // Remove trailing empty lines
            while (canonicalized.Count > 0 && string.IsNullOrEmpty(canonicalized[^1]))
            {
                canonicalized.RemoveAt(canonicalized.Count - 1);
            }

            // Ensure ends with CRLF
            return string.Join("\r\n", canonicalized) + "\r\n";
        }
        else // simple
        {
            var result = body;
            
            // Normalize line endings to CRLF
            result = result.Replace("\r\n", "\n").Replace("\r", "\n").Replace("\n", "\r\n");

            // Remove trailing empty lines (but keep one final CRLF)
            while (result.EndsWith("\r\n\r\n"))
            {
                result = result[..^2];
            }

            // Ensure ends with CRLF
            if (!result.EndsWith("\r\n"))
            {
                result += "\r\n";
            }

            return result;
        }
    }

    private static string CanonicalizeHeader(string name, string value, string method)
    {
        if (method == "relaxed")
        {
            // 1. Lowercase header name
            // 2. Unfold header (remove CRLF before whitespace)
            // 3. Reduce whitespace sequences to single space
            // 4. Trim leading/trailing whitespace from value

            var canonName = name.ToLowerInvariant();
            var canonValue = CanonicalizeHeaderValue(value, method);

            return $"{canonName}:{canonValue}";
        }
        else // simple
        {
            return $"{name}: {value}";
        }
    }

    private static string CanonicalizeHeaderValue(string value, string method)
    {
        if (method == "relaxed")
        {
            // Unfold (remove CRLF followed by whitespace)
            var unfolded = HeaderFoldingRegex().Replace(value, " ");
            // Reduce whitespace
            var reduced = WhitespaceRegex().Replace(unfolded, " ");
            // Trim
            return reduced.Trim();
        }
        return value;
    }

    [GeneratedRegex(@"[ \t]+")]
    private static partial Regex WhitespaceRegex();

    [GeneratedRegex(@"\r?\n[ \t]+")]
    private static partial Regex HeaderFoldingRegex();

    #endregion

    #region Header Parsing

    private static (string Headers, string Body) SplitMessage(string message)
    {
        // Find header/body separator
        var separatorIndex = message.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        if (separatorIndex < 0)
        {
            separatorIndex = message.IndexOf("\n\n", StringComparison.Ordinal);
            if (separatorIndex < 0)
            {
                return (message, "");
            }
            return (message[..separatorIndex], message[(separatorIndex + 2)..]);
        }
        return (message[..separatorIndex], message[(separatorIndex + 4)..]);
    }

    private static List<KeyValuePair<string, string>> ParseHeaders(string headerSection)
    {
        var headers = new List<KeyValuePair<string, string>>();
        
        // Unfold headers first
        var unfolded = HeaderFoldingRegex().Replace(headerSection, " ");
        var lines = unfolded.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);

        foreach (var line in lines)
        {
            var colonIndex = line.IndexOf(':');
            if (colonIndex > 0)
            {
                var name = line[..colonIndex].Trim();
                var value = line[(colonIndex + 1)..].Trim();
                headers.Add(new KeyValuePair<string, string>(name, value));
            }
        }

        return headers;
    }

    private static string BuildHeaderSigningData(
        List<KeyValuePair<string, string>> headers,
        string[] signedHeaderNames,
        string canonMethod)
    {
        var sb = new StringBuilder();

        foreach (var headerName in signedHeaderNames)
        {
            var trimmedName = headerName.Trim();
            
            // Find header (case-insensitive)
            var header = headers.FirstOrDefault(h => 
                h.Key.Equals(trimmedName, StringComparison.OrdinalIgnoreCase));

            if (header.Key is not null)
            {
                var canonicalized = CanonicalizeHeader(header.Key, header.Value, canonMethod);
                sb.Append(canonicalized);
                sb.Append("\r\n");
            }
        }

        return sb.ToString();
    }

    #endregion

    #region Utility

    private static byte[] ComputeHash(string data)
    {
        return SHA256.HashData(Encoding.ASCII.GetBytes(data));
    }

    private static string FoldBase64(string base64, int lineLength)
    {
        if (base64.Length <= lineLength)
            return base64;

        var sb = new StringBuilder();
        for (int i = 0; i < base64.Length; i += lineLength)
        {
            if (i > 0)
                sb.Append("\r\n\t");
            
            var length = Math.Min(lineLength, base64.Length - i);
            sb.Append(base64.AsSpan(i, length));
        }
        return sb.ToString();
    }

    #endregion
}

#endregion

#region DKIM Key Generator

public static class DkimKeyGenerator
{
    public static (string PrivateKeyPem, string PublicKeyPem, string DnsRecord) GenerateKeyPair(
        string domain,
        string selector,
        int keySize = 2048)
    {
        using var rsa = RSA.Create(keySize);
        
        var privateKeyPem = rsa.ExportRSAPrivateKeyPem();
        var publicKeyPem = rsa.ExportRSAPublicKeyPem();
        
        // Extract public key for DNS record
        var publicKeyBytes = rsa.ExportSubjectPublicKeyInfo();
        var publicKeyBase64 = Convert.ToBase64String(publicKeyBytes);
        
        // DNS TXT record format
        var dnsRecord = $"{selector}._domainkey.{domain}. IN TXT \"v=DKIM1; k=rsa; p={publicKeyBase64}\"";

        return (privateKeyPem, publicKeyPem, dnsRecord);
    }

    public static void SaveKeyPair(string basePath, string domain, string selector)
    {
        var (privateKey, publicKey, dnsRecord) = GenerateKeyPair(domain, selector);

        var privateKeyPath = Path.Combine(basePath, $"dkim_{selector}.private.pem");
        var publicKeyPath = Path.Combine(basePath, $"dkim_{selector}.public.pem");
        var dnsRecordPath = Path.Combine(basePath, $"dkim_{selector}.dns.txt");

        Directory.CreateDirectory(basePath);
        
        File.WriteAllText(privateKeyPath, privateKey);
        File.WriteAllText(publicKeyPath, publicKey);
        File.WriteAllText(dnsRecordPath, dnsRecord);
    }
}

#endregion
