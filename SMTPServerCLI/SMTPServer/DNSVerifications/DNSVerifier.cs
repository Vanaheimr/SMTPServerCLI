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
                mxTask.Result,
                dkimTask.Result.Domain
            );

        }

        #region SPF Verification

        // RFC 7208 §4.6.4: the total number of DNS-querying terms
        // (a, mx, ptr, exists, include, redirect) MUST NOT exceed 10.
        private const int MaxSpfDnsLookups = 10;

        // Mutable lookup budget shared across the whole (recursive) evaluation.
        private sealed class SpfLookupState { public int Lookups; }

        private async Task<(SPFResult Result, string? Record)> VerifySpfAsync(
            string               domain,
            System.Net.IPAddress clientIp,
            string               mailFrom,
            string               heloHostname,
            CancellationToken    ct)
        {
            try
            {
                var spfRecord = await GetTxtRecordAsync(domain, "v=spf1", ct);
                if (spfRecord is null)
                    return (SPFResult.None, null);

                Logger.Log(LogLevel.Debug, $"SPF record for {domain}: {spfRecord}");

                // Macro context (RFC 7208 §7). An empty MAIL FROM uses "postmaster@<helo>".
                string local, senderDom, sender;
                if (string.IsNullOrEmpty(mailFrom))
                {
                    local = "postmaster"; senderDom = heloHostname; sender = $"postmaster@{heloHostname}";
                }
                else
                {
                    var at    = mailFrom.IndexOf('@');
                    local     = at > 0 ? mailFrom[..at]       : "postmaster";
                    senderDom = at > 0 ? mailFrom[(at + 1)..] : mailFrom;
                    sender    = mailFrom;
                }
                var ctx = new SpfMacroContext(sender, local, senderDom, heloHostname);

                var result = await EvaluateSpfAsync(spfRecord, clientIp, domain, ctx, new SpfLookupState(), ct);
                return (result, spfRecord);
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Warning, $"SPF verification error for {domain}: {ex.Message}");
                return (SPFResult.TempError, null);
            }
        }

        /// <summary>
        /// Evaluate an SPF record against the client IP (RFC 7208).
        /// Handles the a/mx/ip4/ip6/include/exists/all mechanisms, the redirect modifier,
        /// dual-CIDR lengths, and the shared 10-DNS-lookup limit across recursion.
        /// </summary>
        private async Task<SPFResult> EvaluateSpfAsync(
            string                spfRecord,
            System.Net.IPAddress  clientIp,
            string                domain,
            SpfMacroContext       ctx,
            SpfLookupState        state,
            CancellationToken     ct)
        {

            var terms = spfRecord.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            string? redirectDomain = null;

            foreach (var term in terms)
            {

                if (term.Equals("v=spf1", StringComparison.OrdinalIgnoreCase))
                    continue;

                // Modifiers are "name=value" (redirect=, exp=, unknown). Mechanisms never contain '='.
                if (term.Contains('='))
                {
                    var eq = term.IndexOf('=');
                    if (term[..eq].Equals("redirect", StringComparison.OrdinalIgnoreCase))
                        redirectDomain = term[(eq + 1)..];
                    // exp= and unknown modifiers are ignored (RFC 7208 §6)
                    continue;
                }

                var qualifier = term[0] switch
                {
                    '+' => SPFResult.Pass,
                    '-' => SPFResult.Fail,
                    '~' => SPFResult.SoftFail,
                    '?' => SPFResult.Neutral,
                    _   => SPFResult.Pass   // default qualifier
                };

                var mech = (term[0] is '+' or '-' or '~' or '?' ? term[1..] : term).ToLowerInvariant();

                if (mech == "all")
                    return qualifier;

                else if (mech.StartsWith("ip4:"))
                {
                    if (clientIp.AddressFamily == AddressFamily.InterNetwork && IpMatchesCidr(clientIp, mech[4..]))
                        return qualifier;
                }

                else if (mech.StartsWith("ip6:"))
                {
                    if (clientIp.AddressFamily == AddressFamily.InterNetworkV6 && IpMatchesCidr(clientIp, mech[4..]))
                        return qualifier;
                }

                else if (mech == "a" || mech.StartsWith("a:") || mech.StartsWith("a/"))
                {
                    if (!CountLookup(state))
                        return SPFResult.PermError;

                    var (rawTarget, ip4Cidr, ip6Cidr) = ParseTarget(StripName(mech, 1), domain);
                    var target = SpfMacros.Expand(rawTarget, domain, clientIp, ctx);
                    if (await MatchAAsync(clientIp, target, ip4Cidr, ip6Cidr, ct))
                        return qualifier;
                }

                else if (mech == "mx" || mech.StartsWith("mx:") || mech.StartsWith("mx/"))
                {
                    if (!CountLookup(state))
                        return SPFResult.PermError;

                    var (rawTarget, ip4Cidr, ip6Cidr) = ParseTarget(StripName(mech, 2), domain);
                    var target = SpfMacros.Expand(rawTarget, domain, clientIp, ctx);
                    if (await MatchMxAsync(clientIp, target, ip4Cidr, ip6Cidr, ct))
                        return qualifier;
                }

                else if (mech.StartsWith("include:"))
                {
                    if (!CountLookup(state))
                        return SPFResult.PermError;

                    var includeDomain = SpfMacros.Expand(mech[8..], domain, clientIp, ctx);

                    var includeRecord = await GetTxtRecordAsync(includeDomain, "v=spf1", ct);
                    if (includeRecord is null)
                        return SPFResult.PermError;    // include target without SPF record (RFC 7208 §5.2)

                    var includeResult = await EvaluateSpfAsync(includeRecord, clientIp, includeDomain, ctx, state, ct);
                    switch (includeResult)
                    {
                        case SPFResult.Pass:                          return qualifier;      // include matched
                        case SPFResult.Fail or SPFResult.SoftFail
                                             or SPFResult.Neutral:    break;                 // no match, keep going
                        case SPFResult.TempError:                     return SPFResult.TempError;
                        default:                                      return SPFResult.PermError;  // None/PermError
                    }
                }

                else if (mech == "exists" || mech.StartsWith("exists:"))
                {
                    if (!CountLookup(state))
                        return SPFResult.PermError;

                    var existsDomain = SpfMacros.Expand(mech.StartsWith("exists:") ? mech[7..] : domain, domain, clientIp, ctx);

                    var ips = await ResolveIpsAsync(existsDomain, ct);
                    // 'exists' matches if the name has any A record (RFC 7208 §5.7)
                    if (ips.Any(ip => ip.AddressFamily == AddressFamily.InterNetwork))
                        return qualifier;
                }

                else if (mech == "ptr" || mech.StartsWith("ptr:"))
                {
                    if (!CountLookup(state))
                        return SPFResult.PermError;

                    // 'ptr' is deprecated (RFC 7208 §5.5) and intentionally not evaluated; counts against the limit.
                    Logger.Log(LogLevel.Debug, "SPF 'ptr' mechanism is deprecated and skipped");
                }

                else
                {
                    // Unknown mechanism => PermError (RFC 7208 §4.6.1)
                    Logger.Log(LogLevel.Debug, $"SPF unknown mechanism '{mech}' => PermError");
                    return SPFResult.PermError;
                }

            }

            // No mechanism matched: apply redirect (if no 'all' was present), else default Neutral.
            if (redirectDomain is not null)
            {
                if (!CountLookup(state))
                    return SPFResult.PermError;

                var redirectTarget = SpfMacros.Expand(redirectDomain, domain, clientIp, ctx);

                var redirectRecord = await GetTxtRecordAsync(redirectTarget, "v=spf1", ct);
                if (redirectRecord is null)
                    return SPFResult.PermError;    // RFC 7208 §6.1

                return await EvaluateSpfAsync(redirectRecord, clientIp, redirectTarget, ctx, state, ct);
            }

            return SPFResult.Neutral;

        }

        private static bool CountLookup(SpfLookupState state)
            => ++state.Lookups <= MaxSpfDnsLookups;

        // Strip the leading mechanism keyword (and an optional ':') from a mechanism term.
        private static string StripName(string mech, int keywordLength)
        {
            var rest = mech[keywordLength..];
            return rest.StartsWith(':') ? rest[1..] : rest;
        }

        // Parse "domain/ip4cidr//ip6cidr" (any part optional) into a target domain (still
        // possibly containing macros) + CIDR lengths.
        private static (string Domain, int Ip4Cidr, int Ip6Cidr) ParseTarget(string spec, string defaultDomain)
        {
            var ip4Cidr = 32;
            var ip6Cidr = 128;

            var domainPart = spec;
            var slash      = spec.IndexOf('/');
            if (slash >= 0)
            {
                domainPart = spec[..slash];
                var m = Regex.Match(spec[slash..], @"^(?:/(\d+))?(?://(\d+))?$");
                if (m.Groups[1].Success) ip4Cidr = int.Parse(m.Groups[1].Value);
                if (m.Groups[2].Success) ip6Cidr = int.Parse(m.Groups[2].Value);
            }

            return (string.IsNullOrEmpty(domainPart) ? defaultDomain : domainPart, ip4Cidr, ip6Cidr);
        }

        private async Task<bool> MatchAAsync(System.Net.IPAddress clientIp, string domain, int ip4Cidr, int ip6Cidr, CancellationToken ct)
        {
            foreach (var ip in await ResolveIpsAsync(domain, ct))
            {
                if (ip.AddressFamily != clientIp.AddressFamily)
                    continue;

                var cidr = clientIp.AddressFamily == AddressFamily.InterNetwork ? ip4Cidr : ip6Cidr;
                if (IpMatchesCidr(clientIp, $"{ip}/{cidr}"))
                    return true;
            }
            return false;
        }

        private async Task<bool> MatchMxAsync(System.Net.IPAddress clientIp, string domain, int ip4Cidr, int ip6Cidr, CancellationToken ct)
        {
            var mxHosts = await GetMxRecordsAsync(domain, ct);

            // RFC 7208 §4.6.4: at most 10 MX names are processed.
            foreach (var mx in mxHosts.Take(10))
            {
                if (await MatchAAsync(clientIp, mx, ip4Cidr, ip6Cidr, ct))
                    return true;
            }
            return false;
        }

        private async Task<System.Net.IPAddress[]> ResolveIpsAsync(string domain, CancellationToken ct)
        {
            try
            {
                var response = await DNSClient.Query(
                                         DNSServiceName.Parse(domain),
                                         [ DNSResourceRecordTypes.A, DNSResourceRecordTypes.AAAA ],
                                         CancellationToken: ct
                                     );

                var addresses = new List<System.Net.IPAddress>();
                foreach (var a in response.Answers.OfType<A>())
                    addresses.Add(new System.Net.IPAddress(a.IPv4Address.GetBytes()));
                foreach (var aaaa in response.Answers.OfType<AAAA>())
                    addresses.Add(new System.Net.IPAddress(aaaa.IPv6Address.GetBytes()));

                return [.. addresses];
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Debug, $"A/AAAA lookup failed for {domain}: {ex.Message}");
                return [];
            }
        }

        /// <summary>
        /// Reverse (PTR) lookup for an IP address via the Hermod DNS client.
        /// Returns the first PTR target hostname (without trailing dot), or null.
        /// </summary>
        public async Task<String?> ReverseLookupAsync(System.Net.IPAddress ip, CancellationToken ct = default)
        {
            try
            {
                var response = await DNSClient.Query(
                                         DNSServiceName.Parse(BuildReverseName(ip)),
                                         [ DNSResourceRecordTypes.PTR ],
                                         CancellationToken: ct
                                     );

                var ptr = response.Answers.OfType<PTR>().FirstOrDefault();
                return ptr?.Target.FullName.TrimEnd('.');
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Debug, $"PTR lookup failed for {ip}: {ex.Message}");
                return null;
            }
        }

        // Build the reverse-DNS query name: "4.3.2.1.in-addr.arpa" / nibble-reversed "...ip6.arpa".
        private static String BuildReverseName(System.Net.IPAddress ip)
        {
            var bytes = ip.GetAddressBytes();

            if (ip.AddressFamily == AddressFamily.InterNetwork)
                return String.Join('.', bytes.Reverse()) + ".in-addr.arpa";

            var sb = new StringBuilder();
            for (var i = bytes.Length - 1; i >= 0; i--)
            {
                sb.Append((bytes[i] & 0x0F).ToString("x")).Append('.');
                sb.Append((bytes[i] >> 4)  .ToString("x")).Append('.');
            }
            sb.Append("ip6.arpa");
            return sb.ToString();
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

        #endregion

        #region DKIM Verification

        private async Task<(DkimResult Result, string? Details, string? Domain)> VerifyDkimAsync(
            EMailMessage      message,
            CancellationToken ct)
        {
            try
            {
                // Parse the raw message so canonicalization sees the original bytes
                // (message.Headers are already unfolded/trimmed and unusable for DKIM).
                var (headerBlock, body) = DkimCanonicalization.Split(message.RawMessage);
                var fields              = DkimCanonicalization.ParseFields(headerBlock);
                var dkimFields          = fields.Where(f => f.Name.Equals("DKIM-Signature", StringComparison.OrdinalIgnoreCase)).ToList();

                if (dkimFields.Count == 0)
                    return (DkimResult.None, "No DKIM signature found", null);

                (DkimResult Result, string? Details) last = (DkimResult.Fail, "All DKIM signatures failed verification");
                string? lastDomain = null;

                foreach (var dkimField in dkimFields)
                {
                    // d= of the signature being evaluated (for Authentication-Results header.d).
                    lastDomain = ParseDkimHeader(dkimField.RawValue).GetValueOrDefault("d");
                    last = await VerifySingleDkimSignature(dkimField, fields, body, ct);
                    if (last.Result == DkimResult.Pass)
                        return (last.Result, last.Details, lastDomain);
                }

                return (last.Result, last.Details, lastDomain);
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Warning, $"DKIM verification error: {ex.Message}");
                return (DkimResult.TempError, ex.Message, null);
            }
        }

        private async Task<(DkimResult Result, string? Details)> VerifySingleDkimSignature(
            DkimHeaderField        dkimField,
            List<DkimHeaderField>  fields,
            string                 body,
            CancellationToken      ct)
        {
            var dkimParams = ParseDkimHeader(dkimField.RawValue);

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

            var algorithm = dkimParams.GetValueOrDefault("a", "rsa-sha256");
            var (headerCanon, bodyCanon) = ParseCanonicalization(dkimParams.GetValueOrDefault("c", "simple/simple"));

            // Body hash over the wire octets (UTF-8), via the shared canonicalizer.
            var canonicalizedBody = DkimCanonicalization.CanonicalizeBody(body, bodyCanon);
            var bodyBytes         = Encoding.UTF8.GetBytes(canonicalizedBody);
            var computedBodyHash  = Convert.ToBase64String(
                                        algorithm.Contains("sha256")
                                            ? SHA256.HashData(bodyBytes)
                                            : SHA1.HashData(bodyBytes)
                                    );

            if (computedBodyHash != bodyHash)
                return (DkimResult.Fail, $"Body hash mismatch: expected {bodyHash}, got {computedBodyHash}");

            try
            {
                var publicKeyBytes = Convert.FromBase64String(publicKeyBase64);
                var signatureBytes = Convert.FromBase64String(signature.Replace(" ", "").Replace("\r", "").Replace("\n", ""));

                using var rsa = RSA.Create();
                rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);

                var signedHeaders = dkimParams.GetValueOrDefault("h", "").Split(':');
                var signingInput  = DkimCanonicalization.BuildHeaderHashInput(fields, signedHeaders, dkimField, headerCanon);

                var hashAlgorithm = algorithm.Contains("sha256") ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA1;
                var isValid       = rsa.VerifyData(Encoding.UTF8.GetBytes(signingInput), signatureBytes, hashAlgorithm, RSASignaturePadding.Pkcs1);

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
                // DNSServiceName (not DomainName) so underscore labels like
                // _dmarc.* and *._domainkey.* validate (DMARC/DKIM lookups).
                var response = await DNSClient.Query(
                                         DNSServiceName.Parse(domain),
                                         [ DNSResourceRecordTypes.TXT ],
                                         CancellationToken: ct
                                     );

                foreach (var txt in response.Answers.OfType<TXT>())
                {
                    if (txt.Text.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                        return txt.Text;
                }

                return null;
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Debug, $"TXT lookup failed for {domain}: {ex.Message}");
                return null;
            }
        }

        public async Task<String[]> GetMxRecordsAsync(String domain, CancellationToken ct)
        {
            try
            {
                var response = await DNSClient.Query(
                                         DomainName.Parse(domain),
                                         [ DNSResourceRecordTypes.MX ],
                                         CancellationToken: ct
                                     );

                // Ordered by preference (lowest = highest priority), returned as bare hostnames.
                return response.Answers.
                           OfType<MX>().
                           OrderBy(mx => mx.Preference).
                           Select(mx => mx.Exchange.FullName.TrimEnd('.')).
                           ToArray();
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.Debug, $"MX lookup failed for {domain}: {ex.Message}");
                return [];
            }
        }

        #endregion

    }

}
