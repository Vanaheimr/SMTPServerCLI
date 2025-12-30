// MTA-STS - SMTP Strict Transport Security (RFC 8461)
// .NET 10 / C# 13

using System.Collections.Concurrent;
using System.Net.Http;
using System.Text.RegularExpressions;

namespace AchimSmtpServer;

#region MTA-STS Policy

public enum MtaStsMode
{
    None,       // No policy or failed to fetch
    Testing,    // Report failures but don't enforce
    Enforce     // Require valid TLS
}

public sealed partial record MtaStsPolicy
{
    public MtaStsMode   Mode        { get; init; } = MtaStsMode.None;
    public List<string> MxPatterns  { get; init; } = [];
    public TimeSpan     MaxAge      { get; init; } = TimeSpan.Zero;
    public DateTime     FetchedAt   { get; init; } = DateTime.UtcNow;
    public string?      PolicyId    { get; init; }
    public bool         IsValid     => Mode != MtaStsMode.None && DateTime.UtcNow - FetchedAt < MaxAge;

    /// <summary>
    /// Check if an MX host matches the policy
    /// </summary>
    public bool MatchesMx(string mxHost)
    {
        foreach (var pattern in MxPatterns)
        {
            if (pattern.StartsWith("*."))
            {
                // Wildcard match: *.example.com matches mail.example.com
                var suffix = pattern[1..]; // .example.com
                if (mxHost.EndsWith(suffix, StringComparison.OrdinalIgnoreCase) ||
                    mxHost.Equals(pattern[2..], StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            else
            {
                // Exact match
                if (mxHost.Equals(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }
        return false;
    }

    public static MtaStsPolicy None => new() { Mode = MtaStsMode.None };
}

#endregion

#region MTA-STS Resolver

/// <summary>
/// Resolves and caches MTA-STS policies for domains.
/// MTA-STS requires:
/// 1. DNS TXT record at _mta-sts.domain.com
/// 2. HTTPS fetch of policy from https://mta-sts.domain.com/.well-known/mta-sts.txt
/// </summary>
public sealed partial class MtaStsResolver : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly ILogger _logger;
    private readonly ConcurrentDictionary<string, MtaStsPolicy> _cache = new();
    private readonly SemaphoreSlim _fetchLock = new(5); // Max 5 concurrent fetches

    public MtaStsResolver(ILogger logger)
    {
        _logger = logger;
        _httpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(10)
        };
        _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("AchimSMTP/1.0 MTA-STS");
    }

    /// <summary>
    /// Get MTA-STS policy for a domain
    /// </summary>
    public async Task<MtaStsPolicy> GetPolicyAsync(string domain, CancellationToken ct = default)
    {
        domain = domain.ToLowerInvariant();

        // Check cache first
        if (_cache.TryGetValue(domain, out var cached) && cached.IsValid)
        {
            return cached;
        }

        await _fetchLock.WaitAsync(ct);
        try
        {
            // Double-check after acquiring lock
            if (_cache.TryGetValue(domain, out cached) && cached.IsValid)
            {
                return cached;
            }

            var policy = await FetchPolicyAsync(domain, ct);
            _cache[domain] = policy;
            return policy;
        }
        finally
        {
            _fetchLock.Release();
        }
    }

    private async Task<MtaStsPolicy> FetchPolicyAsync(string domain, CancellationToken ct)
    {
        try
        {
            // Step 1: Check for _mta-sts DNS TXT record
            var txtRecord = await LookupMtaStsTxtAsync(domain, ct);
            if (txtRecord is null)
            {
                _logger.Log(LogLevel.Debug, $"No MTA-STS TXT record for {domain}");
                return MtaStsPolicy.None;
            }

            // Parse TXT record for policy ID
            var policyId = ParsePolicyId(txtRecord);
            
            // Step 2: Fetch policy via HTTPS
            var policyUrl = $"https://mta-sts.{domain}/.well-known/mta-sts.txt";
            
            _logger.Log(LogLevel.Debug, $"Fetching MTA-STS policy from {policyUrl}");
            
            var response = await _httpClient.GetAsync(policyUrl, ct);
            if (!response.IsSuccessStatusCode)
            {
                _logger.Log(LogLevel.Debug, $"MTA-STS policy fetch failed: {response.StatusCode}");
                return MtaStsPolicy.None;
            }

            var policyText = await response.Content.ReadAsStringAsync(ct);
            var policy = ParsePolicy(policyText, policyId);
            
            if (policy.Mode != MtaStsMode.None)
            {
                _logger.Log(LogLevel.Info, $"MTA-STS policy for {domain}: mode={policy.Mode}, mx={string.Join(",", policy.MxPatterns)}");
            }

            return policy;
        }
        catch (Exception ex)
        {
            _logger.Log(LogLevel.Debug, $"MTA-STS lookup failed for {domain}: {ex.Message}");
            return MtaStsPolicy.None;
        }
    }

    private async Task<string?> LookupMtaStsTxtAsync(string domain, CancellationToken ct)
    {
        try
        {
            var process = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = OperatingSystem.IsWindows() ? "nslookup" : "dig",
                    Arguments = OperatingSystem.IsWindows()
                        ? $"-type=TXT _mta-sts.{domain}"
                        : $"+short TXT _mta-sts.{domain}",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.Start();
            var output = await process.StandardOutput.ReadToEndAsync(ct);
            await process.WaitForExitAsync(ct);

            // Look for v=STSv1
            if (output.Contains("v=STSv1", StringComparison.OrdinalIgnoreCase))
            {
                return output;
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    private static string? ParsePolicyId(string txtRecord)
    {
        var match = PolicyIdRegex().Match(txtRecord);
        return match.Success ? match.Groups[1].Value : null;
    }

    private static MtaStsPolicy ParsePolicy(string policyText, string? policyId)
    {
        var lines = policyText.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        
        var mode = MtaStsMode.None;
        var mxPatterns = new List<string>();
        var maxAge = TimeSpan.FromDays(1); // Default

        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("version:", StringComparison.OrdinalIgnoreCase))
            {
                // Must be STSv1
                if (!trimmed.Contains("STSv1", StringComparison.OrdinalIgnoreCase))
                    return MtaStsPolicy.None;
            }
            else if (trimmed.StartsWith("mode:", StringComparison.OrdinalIgnoreCase))
            {
                var modeValue = trimmed[5..].Trim().ToLowerInvariant();
                mode = modeValue switch
                {
                    "enforce" => MtaStsMode.Enforce,
                    "testing" => MtaStsMode.Testing,
                    "none" => MtaStsMode.None,
                    _ => MtaStsMode.None
                };
            }
            else if (trimmed.StartsWith("mx:", StringComparison.OrdinalIgnoreCase))
            {
                var mx = trimmed[3..].Trim();
                if (!string.IsNullOrEmpty(mx))
                    mxPatterns.Add(mx);
            }
            else if (trimmed.StartsWith("max_age:", StringComparison.OrdinalIgnoreCase))
            {
                if (long.TryParse(trimmed[8..].Trim(), out var seconds))
                    maxAge = TimeSpan.FromSeconds(seconds);
            }
        }

        return new MtaStsPolicy
        {
            Mode = mode,
            MxPatterns = mxPatterns,
            MaxAge = maxAge,
            PolicyId = policyId,
            FetchedAt = DateTime.UtcNow
        };
    }

    [GeneratedRegex(@"id=([a-zA-Z0-9]+)")]
    private static partial Regex PolicyIdRegex();

    public void Dispose()
    {
        _httpClient.Dispose();
        _fetchLock.Dispose();
    }
}

#endregion

#region TLSRPT - TLS Reporting (RFC 8460)

/// <summary>
/// TLS-RPT report for MTA-STS failures
/// </summary>
public sealed record TlsRptReport
{
    public required string      Domain          { get; init; }
    public required DateTime    StartTime       { get; init; }
    public required DateTime    EndTime         { get; init; }
    public required string      PolicyMode      { get; init; }
    public required string[]    MxHost          { get; init; }
    public          int         SuccessCount    { get; set; }
    public          int         FailureCount    { get; set; }
    public          List<TlsRptFailure> Failures { get; init; } = [];
}

public sealed record TlsRptFailure
{
    public required string  ResultType      { get; init; }  // e.g., "certificate-expired"
    public required string  SendingMta      { get; init; }
    public required string  ReceivingMx     { get; init; }
    public          int     FailureCount    { get; init; } = 1;
}

#endregion
