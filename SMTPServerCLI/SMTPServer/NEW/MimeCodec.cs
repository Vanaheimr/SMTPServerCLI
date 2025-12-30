// MIME Encoding/Decoding Utilities (RFC 2045, 2047)
// .NET 10 / C# 13

using System.Text;
using System.Text.RegularExpressions;

namespace AchimSmtpServer;

#region Quoted-Printable Codec (RFC 2045)

public static partial class QuotedPrintable
{
    /// <summary>
    /// Decode Quoted-Printable encoded string
    /// </summary>
    public static string Decode(string input)
    {
        if (string.IsNullOrEmpty(input))
            return input;

        var result = new StringBuilder(input.Length);
        
        for (int i = 0; i < input.Length; i++)
        {
            var c = input[i];
            
            if (c == '=')
            {
                // Soft line break (=\r\n or =\n)
                if (i + 1 < input.Length && (input[i + 1] == '\r' || input[i + 1] == '\n'))
                {
                    i++; // Skip =
                    if (i < input.Length && input[i] == '\r')
                        i++;
                    if (i < input.Length && input[i] == '\n')
                        i++;
                    i--; // Compensate for loop increment
                    continue;
                }
                
                // Hex-encoded byte
                if (i + 2 < input.Length)
                {
                    var hex = input.Substring(i + 1, 2);
                    if (byte.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out var b))
                    {
                        result.Append((char)b);
                        i += 2;
                        continue;
                    }
                }
            }
            
            // Underscore in headers means space (RFC 2047)
            if (c == '_')
            {
                result.Append(' ');
            }
            else
            {
                result.Append(c);
            }
        }

        return result.ToString();
    }

    /// <summary>
    /// Decode Quoted-Printable bytes to string with specified charset
    /// </summary>
    public static string Decode(string input, Encoding encoding)
    {
        if (string.IsNullOrEmpty(input))
            return input;

        var bytes = new List<byte>();
        
        for (int i = 0; i < input.Length; i++)
        {
            var c = input[i];
            
            if (c == '=')
            {
                // Soft line break
                if (i + 1 < input.Length && (input[i + 1] == '\r' || input[i + 1] == '\n'))
                {
                    i++;
                    if (i < input.Length && input[i] == '\r')
                        i++;
                    if (i < input.Length && input[i] == '\n')
                        i++;
                    i--;
                    continue;
                }
                
                // Hex-encoded byte
                if (i + 2 < input.Length)
                {
                    var hex = input.Substring(i + 1, 2);
                    if (byte.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out var b))
                    {
                        bytes.Add(b);
                        i += 2;
                        continue;
                    }
                }
            }
            
            if (c == '_')
            {
                bytes.Add((byte)' ');
            }
            else if (c < 256)
            {
                bytes.Add((byte)c);
            }
        }

        return encoding.GetString(bytes.ToArray());
    }

    /// <summary>
    /// Encode string to Quoted-Printable
    /// </summary>
    public static string Encode(string input, Encoding? encoding = null)
    {
        encoding ??= Encoding.UTF8;
        var bytes = encoding.GetBytes(input);
        var result = new StringBuilder();
        var lineLength = 0;
        const int maxLineLength = 76;

        foreach (var b in bytes)
        {
            string encoded;
            
            // Printable ASCII (33-126) except '=' can be literal
            if (b >= 33 && b <= 126 && b != '=')
            {
                encoded = ((char)b).ToString();
            }
            else if (b == ' ' || b == '\t')
            {
                // Space/tab - literal unless at end of line
                encoded = ((char)b).ToString();
            }
            else if (b == '\r' || b == '\n')
            {
                // Line breaks pass through
                result.Append((char)b);
                lineLength = 0;
                continue;
            }
            else
            {
                // Everything else is hex-encoded
                encoded = $"={b:X2}";
            }

            // Check line length (soft break if needed)
            if (lineLength + encoded.Length > maxLineLength - 1)
            {
                result.Append("=\r\n");
                lineLength = 0;
            }

            result.Append(encoded);
            lineLength += encoded.Length;
        }

        return result.ToString();
    }

    /// <summary>
    /// Encode string for use in MIME header (RFC 2047)
    /// </summary>
    public static string EncodeHeader(string input, string charset = "utf-8")
    {
        if (string.IsNullOrEmpty(input))
            return input;

        // Check if encoding is needed (non-ASCII chars)
        var needsEncoding = false;
        foreach (var c in input)
        {
            if (c > 127 || c < 32)
            {
                needsEncoding = true;
                break;
            }
        }

        if (!needsEncoding)
            return input;

        var encoding = Encoding.GetEncoding(charset);
        var bytes = encoding.GetBytes(input);
        var result = new StringBuilder();
        result.Append($"=?{charset}?Q?");

        foreach (var b in bytes)
        {
            if (b == ' ')
            {
                result.Append('_'); // Space as underscore in Q encoding
            }
            else if ((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9'))
            {
                result.Append((char)b);
            }
            else
            {
                result.Append($"={b:X2}");
            }
        }

        result.Append("?=");
        return result.ToString();
    }
}

#endregion

#region MIME Header Decoder (RFC 2047)

public static partial class MimeDecoder
{
    // Pattern: =?charset?encoding?text?=
    [GeneratedRegex(@"=\?([^?]+)\?([BbQq])\?([^?]*)\?=")]
    private static partial Regex EncodedWordRegex();

    /// <summary>
    /// Decode MIME encoded-word (RFC 2047)
    /// Examples:
    ///   =?utf-8?Q?Gr=C3=BC=C3=9Fe?=  → "Grüße"
    ///   =?utf-8?B?R3LDvMOfZQ==?=     → "Grüße"
    /// </summary>
    public static string DecodeHeader(string input)
    {
        if (string.IsNullOrEmpty(input))
            return input;

        // Replace encoded words
        return EncodedWordRegex().Replace(input, match =>
        {
            var charset = match.Groups[1].Value;
            var encoding = match.Groups[2].Value.ToUpperInvariant();
            var text = match.Groups[3].Value;

            try
            {
                var textEncoding = Encoding.GetEncoding(charset);
                
                if (encoding == "B")
                {
                    // Base64
                    var bytes = Convert.FromBase64String(text);
                    return textEncoding.GetString(bytes);
                }
                else // Q
                {
                    // Quoted-Printable
                    return QuotedPrintable.Decode(text, textEncoding);
                }
            }
            catch
            {
                // If decoding fails, return original
                return match.Value;
            }
        });
    }

    /// <summary>
    /// Decode Content-Transfer-Encoding body
    /// </summary>
    public static string DecodeBody(string body, string? transferEncoding, string charset = "utf-8")
    {
        if (string.IsNullOrEmpty(body))
            return body;

        var encoding = Encoding.GetEncoding(charset);

        return transferEncoding?.ToLowerInvariant() switch
        {
            "base64" => DecodeBase64Body(body, encoding),
            "quoted-printable" => QuotedPrintable.Decode(body, encoding),
            "7bit" or "8bit" or "binary" or null => body,
            _ => body
        };
    }

    private static string DecodeBase64Body(string body, Encoding encoding)
    {
        try
        {
            // Remove whitespace (base64 can be wrapped)
            var cleaned = body.Replace("\r", "").Replace("\n", "").Replace(" ", "");
            var bytes = Convert.FromBase64String(cleaned);
            return encoding.GetString(bytes);
        }
        catch
        {
            return body;
        }
    }
}

#endregion

#region Email Headers Collection

/// <summary>
/// Email headers collection that preserves order and allows duplicates.
/// Provides decoded access to header values.
/// </summary>
public sealed class EmailHeaders
{
    private readonly List<(string Name, string RawValue)> _headers = [];

    public int Count => _headers.Count;

    /// <summary>
    /// Add a header (preserves duplicates)
    /// </summary>
    public void Add(string name, string value)
    {
        _headers.Add((name, value));
    }

    /// <summary>
    /// Get first header value (raw, not decoded)
    /// </summary>
    public string? GetRaw(string name)
    {
        foreach (var (n, v) in _headers)
        {
            if (n.Equals(name, StringComparison.OrdinalIgnoreCase))
                return v;
        }
        return null;
    }

    /// <summary>
    /// Get first header value (MIME decoded)
    /// </summary>
    public string? Get(string name)
    {
        var raw = GetRaw(name);
        return raw is not null ? MimeDecoder.DecodeHeader(raw) : null;
    }

    /// <summary>
    /// Get all values for a header (raw)
    /// </summary>
    public IEnumerable<string> GetAllRaw(string name)
    {
        foreach (var (n, v) in _headers)
        {
            if (n.Equals(name, StringComparison.OrdinalIgnoreCase))
                yield return v;
        }
    }

    /// <summary>
    /// Get all values for a header (decoded)
    /// </summary>
    public IEnumerable<string> GetAll(string name)
    {
        foreach (var raw in GetAllRaw(name))
        {
            yield return MimeDecoder.DecodeHeader(raw);
        }
    }

    /// <summary>
    /// Check if header exists
    /// </summary>
    public bool Contains(string name)
    {
        foreach (var (n, _) in _headers)
        {
            if (n.Equals(name, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    /// <summary>
    /// Remove all headers with given name
    /// </summary>
    public void Remove(string name)
    {
        _headers.RemoveAll(h => h.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Set header (replaces existing, or adds new)
    /// </summary>
    public void Set(string name, string value)
    {
        Remove(name);
        Add(name, value);
    }

    /// <summary>
    /// Get all headers as KeyValuePairs
    /// </summary>
    public IEnumerable<KeyValuePair<string, string>> AsEnumerable()
    {
        foreach (var (name, value) in _headers)
        {
            yield return new KeyValuePair<string, string>(name, value);
        }
    }

    /// <summary>
    /// Get raw header string for serialization
    /// </summary>
    public string ToHeaderString()
    {
        var sb = new StringBuilder();
        foreach (var (name, value) in _headers)
        {
            sb.Append(name);
            sb.Append(": ");
            sb.Append(value);
            sb.Append("\r\n");
        }
        return sb.ToString();
    }

    /// <summary>
    /// Indexer for quick access (returns decoded value)
    /// </summary>
    public string? this[string name] => Get(name);
}

#endregion

#region Improved EmailMessage

/// <summary>
/// Represents a parsed email message with proper MIME decoding
/// </summary>
public sealed class EmailMessageV2
{
    public EmailHeaders Headers { get; } = new();
    public string RawBody { get; set; } = "";
    public DnsVerificationResult? Verification { get; set; }

    // Decoded header accessors
    public string? Subject => Headers.Get("Subject");
    public string? From => Headers.Get("From");
    public string? To => Headers.Get("To");
    public string? Cc => Headers.Get("Cc");
    public string? Bcc => Headers.Get("Bcc");
    public string? ReplyTo => Headers.Get("Reply-To");
    public string? MessageId => Headers.GetRaw("Message-ID"); // Don't decode Message-ID
    public string? Date => Headers.GetRaw("Date");
    public string? ContentType => Headers.GetRaw("Content-Type");
    public string? ContentTransferEncoding => Headers.GetRaw("Content-Transfer-Encoding");

    /// <summary>
    /// Get decoded body content
    /// </summary>
    public string DecodedBody
    {
        get
        {
            var charset = ParseCharset(ContentType) ?? "utf-8";
            return MimeDecoder.DecodeBody(RawBody, ContentTransferEncoding, charset);
        }
    }

    /// <summary>
    /// Get all Received headers (in order, for mail routing trace)
    /// </summary>
    public IEnumerable<string> ReceivedHeaders => Headers.GetAllRaw("Received");

    /// <summary>
    /// Parse email from raw message
    /// </summary>
    public static EmailMessageV2 Parse(string rawMessage)
    {
        var message = new EmailMessageV2();

        // Split headers from body
        var headerEnd = rawMessage.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        if (headerEnd < 0)
            headerEnd = rawMessage.IndexOf("\n\n", StringComparison.Ordinal);

        string headerSection, bodySection;
        if (headerEnd > 0)
        {
            headerSection = rawMessage[..headerEnd];
            bodySection = rawMessage[(headerEnd + (rawMessage[headerEnd] == '\r' ? 4 : 2))..];
        }
        else
        {
            headerSection = rawMessage;
            bodySection = "";
        }

        // Parse headers (unfold continuation lines first)
        var unfoldedHeaders = Regex.Replace(headerSection, @"\r?\n[ \t]+", " ");
        var headerLines = unfoldedHeaders.Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries);

        foreach (var line in headerLines)
        {
            var colonIndex = line.IndexOf(':');
            if (colonIndex > 0)
            {
                var name = line[..colonIndex].Trim();
                var value = line[(colonIndex + 1)..].Trim();
                message.Headers.Add(name, value);
            }
        }

        message.RawBody = bodySection;

        return message;
    }

    /// <summary>
    /// Serialize message back to raw format
    /// </summary>
    public string ToRawMessage()
    {
        var sb = new StringBuilder();
        sb.Append(Headers.ToHeaderString());
        sb.Append("\r\n");
        sb.Append(RawBody);
        return sb.ToString();
    }

    /// <summary>
    /// Parse charset from Content-Type header
    /// </summary>
    private static string? ParseCharset(string? contentType)
    {
        if (string.IsNullOrEmpty(contentType))
            return null;

        var match = Regex.Match(contentType, @"charset\s*=\s*""?([^""\s;]+)""?", RegexOptions.IgnoreCase);
        return match.Success ? match.Groups[1].Value : null;
    }
}

#endregion
