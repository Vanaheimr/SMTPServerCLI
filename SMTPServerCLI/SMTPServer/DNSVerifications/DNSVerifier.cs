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

using System.Text;
using System.Text.RegularExpressions;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Buffers;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SMTP.New
{

    public sealed partial class DNSVerifier(DNSClient  DNSClient,
                                            ILogger    Logger)
    {

        public async Task<DnsVerificationResult> VerifyAsync(String                senderDomain,
                                                             System.Net.IPAddress  clientIp,
                                                             String                mailFrom,
                                                             String                heloHostname,
                                                             EMailMessage          message,
                                                             CancellationToken     ct = default)
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

        private async Task<(SPFResult Result, string? Record)> VerifySpfAsync(
            string            domain,
            System.Net.IPAddress         clientIp,
            string            mailFrom,
            string            heloHostname,
            CancellationToken ct)
        {
            try
            {
                var spfRecord = await GetTxtRecordAsync(domain, "v=spf1", ct);
                if (spfRecord is null)
                    return (SPFResult.None, null);

                Logger.Log(LogLevel.Debug, $"SPF record for {domain}: {spfRecord}");

                var result = EvaluateSpf(spfRecord, clientIp, domain, mailFrom);
                return (result, spfRecord);
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Warning, $"SPF verification error for {domain}: {ex.Message}");
                return (SPFResult.TempError, null);
            }
        }

        private SPFResult EvaluateSpf(string spfRecord, System.Net.IPAddress clientIp, string domain, string mailFrom)
        {
            var mechanisms = spfRecord.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        
            foreach (var mechanism in mechanisms.Skip(1)) // Skip "v=spf1"
            {
                var qualifier = mechanism[0] switch
                {
                    '+' => SPFResult.Pass,
                    '-' => SPFResult.Fail,
                    '~' => SPFResult.SoftFail,
                    '?' => SPFResult.Neutral,
                    _   => SPFResult.Pass // Default qualifier is Pass
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
                        if (includeResult == SPFResult.Pass)
                            return qualifier;
                    }
                }
            }

            return SPFResult.Neutral;
        }

        private static bool IpMatchesCidr(System.Net.IPAddress ip, string cidr)
        {
            try
            {
                var parts = cidr.Split('/');
                var network = System.Net.IPAddress.Parse(parts[0]);
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

        private async Task<bool> CheckARecord(System.Net.IPAddress clientIp, string domain)
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

        private async Task<bool> CheckMxRecord(System.Net.IPAddress clientIp, string domain)
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
            EMailMessage      message,
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
                Logger.Log(LogLevel.Warning, $"DKIM verification error: {ex.Message}");
                return (DkimResult.TempError, ex.Message);
            }
        }

        private async Task<(DkimResult Result, string? Details)> VerifySingleDkimSignature(
            string            dkimHeader,
            EMailMessage      message,
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

        private static string BuildSignedHeaderData(EMailMessage message, string[] signedHeaders, string dkimHeader, string method)
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
                Logger.Log(LogLevel.Debug, $"DMARC record for {domain}: {dmarcRecord}");

                return (DmarcResult.Pass, policy);
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Warning, $"DMARC verification error for {domain}: {ex.Message}");
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

        private async Task<String?> GetTxtRecordAsync(String domain, String prefix, CancellationToken ct)
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

        public async Task<String[]> GetMxRecordsAsync(String domain, CancellationToken ct)
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

}
