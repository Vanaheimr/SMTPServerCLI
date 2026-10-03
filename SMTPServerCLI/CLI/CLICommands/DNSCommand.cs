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

using System.Security.Cryptography;

using org.GraphDefined.Vanaheimr.CLI;
using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SMTP.CLI
{

    /// <summary>
    /// The DNS records this server needs, written for this server - and,
    /// with 'check', whether the world can see them yet.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The DKIM record is computed from the private key the server signs with
    /// rather than read from dkim_&lt;selector&gt;.dns.txt, which says the domain
    /// it was generated for and goes stale the day the domain changes; the
    /// TLSA record from the certificate it presents. Both are in the form a
    /// zone file takes: a key longer than one character-string is split into
    /// several, as RFC 1035 wants and many a web form does not do by itself.
    /// </para>
    /// <para>
    /// 'check' asks the name servers the server itself asks, so what it says
    /// is what SPF, DKIM and DMARC checks of other servers will find - give or
    /// take their caches.
    /// </para>
    /// </remarks>
    /// <param name="CLI">The command line.</param>
    public class DNSCommand(SMTPCLI CLI) : ACLICommand<SMTPCLI>(CLI),
                                           ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public static readonly String CommandName = nameof(DNSCommand)[..^7].ToLowerInvariant();

        private static readonly String[] subcommands = [ "records", "check" ];

        #endregion

        #region Suggest(Arguments)

        public override IEnumerable<SuggestionResponse> Suggest(String[] Arguments)
        {

            if (Arguments.Length == 1)
                return SMTPCLI.Is(CommandName, Arguments[0])
                           ? SMTPCLI.CompleteNext   (CommandName, subcommands)
                           : SMTPCLI.CompleteCommand(CommandName, Arguments[0]);

            if (Arguments.Length == 2 && SMTPCLI.Is(CommandName, Arguments[0]))
                return SMTPCLI.CompleteWord(CommandName, Arguments[1], subcommands);

            return [];

        }

        #endregion

        #region Execute(Arguments, CancellationToken)

        public override async Task<String[]> Execute(String[]           Arguments,
                                                     CancellationToken  CancellationToken)
        {

            var what = Arguments.Length > 1 ? Arguments[1].ToLowerInvariant() : "records";

            if (Arguments.Length > 2 || !subcommands.Contains(what))
                return [ $"Usage: {Help()}" ];

            var settings = cli.Server.Settings;

            if (IsLocal(settings.Hostname))
                return [
                    $"The hostname is '{settings.Hostname}', which nobody else can resolve: there is nothing to publish yet.",
                     "Start with --hostname mail.example.com --local-domain example.com - or set both in Configuration.cs."
                ];

            return what == "check"
                       ? await Check(CancellationToken)
                       : Records();

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} [records | check] - the DNS records to publish for this server, or whether they are published";

        #endregion


        #region (private) Records()

        private String[] Records()
        {

            var settings  = cli.Server.Settings;
            var host      = settings.Hostname;
            var domains   = MailDomains();
            var receiving = MailDomains(Receiving: true);
            var lines     = new List<String> {
                                "; Where mail for each domain goes, and the server's own address -",
                                "; A and AAAA with the server's public addresses:",
                            };

            foreach (var domain in receiving)
                lines.Add($"{domain}.  IN MX   10 {host}.");

            lines.Add($"{host}.  IN A     <the server's IPv4 address>");
            lines.Add($"{host}.  IN AAAA  <the server's IPv6 address, if it has one>");
            lines.Add("");

            lines.Add("; PTR - at whoever gives you the IP address: it must name the host, and the host the IP:");
            lines.Add($"<reversed IPv4>.in-addr.arpa.  IN PTR  {host}.");
            lines.Add("");

            lines.Add("; SPF - who may send for each domain mail is sent from. ~all while testing, -all once it works:");
            foreach (var domain in domains)
                lines.Add($"{domain}.  IN TXT  \"v=spf1 mx " +
                          (settings.SmartHost is not null ? $"include:<what {settings.SmartHost}'s provider says> " : "") +
                          "~all\"");
            lines.Add("");

            lines.Add($"; DKIM - the key outgoing mail is signed with ({cli.Server.DkimPrivateKeyPath}):");
            lines.Add($"{settings.DkimSelector}._domainkey.{settings.DkimDomain}.  IN TXT  ( {DkimRecord()} )");
            lines.Add("");

            lines.Add("; DMARC - begin with p=none and the reports, tighten once SPF and DKIM pass:");
            foreach (var domain in domains)
                lines.Add($"_dmarc.{domain}.  IN TXT  \"v=DMARC1; p=none; rua=mailto:{Configuration.DmarcReportEmail ?? $"dmarc-reports@{host}"}; adkim=r; aspf=r\"");
            lines.Add("");

            lines.Add("; TLS-RPT - optional: other servers report how TLS to this one went:");
            foreach (var domain in receiving)
                lines.Add($"_smtp._tls.{domain}.  IN TXT  \"v=TLSRPTv1; rua=mailto:{Configuration.TlsRptReportEmail ?? $"tls-reports@{host}"}\"");

            if (cli.Server.Certificate is { } certificate && !cli.Server.CertificateSelfSigned)
            {
                lines.Add("");
                lines.Add("; DANE - optional, and only in a DNSSEC-signed zone: the key of this certificate.");
                lines.Add("; Renew the certificate with a new key and this has to change first.");
                lines.Add($"_25._tcp.{host}.  IN TLSA  3 1 1 {Convert.ToHexString(SHA256.HashData(certificate.PublicKey.ExportSubjectPublicKeyInfo()))}");
            }

            return [.. lines];

        }

        #endregion

        #region (private) Check(CancellationToken)

        private async Task<String[]> Check(CancellationToken CancellationToken)
        {

            var settings  = cli.Server.Settings;
            var host      = settings.Hostname;
            var lines     = new List<String>();

            async Task<IDNSResourceRecord[]> Ask(String Name, DNSResourceRecordTypes Type)
            {
                try
                {
                    var answer = await cli.Server.DNSClient.Query(DNSServiceName.Parse(Name), [ Type ], CancellationToken: CancellationToken);
                    return [.. answer.Answers];
                }
                catch
                {
                    return [];
                }
            }

            void Say(Boolean Good, String Text)
                => lines.Add($"  {(Good ? "ok     " : "MISSING")}  {Text}");

            var addresses = (await Ask(host, DNSResourceRecordTypes.A)).OfType<A>().Select(a => a.IPv4Address.ToString()).
                     Concat((await Ask(host, DNSResourceRecordTypes.AAAA)).OfType<AAAA>().Select(aaaa => aaaa.IPv6Address.ToString())).
                     ToArray();

            Say(addresses.Length > 0, $"{host} has the address(es) {(addresses.Length > 0 ? String.Join(", ", addresses) : "-")}");

            foreach (var domain in MailDomains())
            {

                if (MailDomains(Receiving: true).Contains(domain))
                {
                    var mx = (await Ask(domain, DNSResourceRecordTypes.MX)).OfType<MX>().ToArray();
                    Say(mx.Any(record => record.Exchange.FullName.TrimEnd('.').Equals(host, StringComparison.OrdinalIgnoreCase)),
                        $"MX of {domain}: {(mx.Length > 0 ? String.Join(", ", mx.Select(record => $"{record.Preference} {Exchange(record)}")) : "none")}");
                }

                var spf = (await Ask(domain, DNSResourceRecordTypes.TXT)).OfType<TXT>().Select(txt => txt.Text).
                                                                          Where(text => text.StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase)).
                                                                          ToArray();
                Say(spf.Length == 1, $"SPF of {domain}: {(spf.Length > 0 ? String.Join(" | ", spf) : "none")}" +
                                     (spf.Length > 1 ? " - more than one is a permerror" : ""));

                var dmarc = (await Ask($"_dmarc.{domain}", DNSResourceRecordTypes.TXT)).OfType<TXT>().Select(txt => txt.Text).
                                                                                         FirstOrDefault(text => text.StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase));
                Say(dmarc is not null, $"DMARC of {domain}: {dmarc ?? "none"}");

            }

            var dkimName  = $"{settings.DkimSelector}._domainkey.{settings.DkimDomain}";
            var dkim      = (await Ask(dkimName, DNSResourceRecordTypes.TXT)).OfType<TXT>().Select(txt => txt.Text.Replace(" ", "")).ToArray();
            var ourKey    = $"p={PublicKey()}";

            Say(dkim.Any(text => text.Contains(ourKey, StringComparison.Ordinal)),
                $"DKIM at {dkimName}: " + (dkim.Length == 0                        ? "none"
                                         : dkim.Any(text => text.Contains(ourKey)) ? "the key this server signs with"
                                         :                                           "a key, but not the one this server signs with"));

            lines.Add("");
            lines.Add("  The PTR of the server's address is not checked: which address the world sees is not known here.");

            return [.. lines];

        }

        #endregion


        #region (private) MailDomains(Receiving = false)

        /// <summary>
        /// The domains mail is received for - the local domains - and, unless
        /// only those are asked for, the DKIM domain mail is sent from; without
        /// the ones nobody else can resolve.
        /// </summary>
        private String[] MailDomains(Boolean Receiving = false)

            => [.. SMTPServerInstance.LocalDomains(cli.Server.Settings.LocalDomains).
                                      Concat(Receiving ? [] : [ cli.Server.Settings.DkimDomain ]).
                                      Where(domain => !IsLocal(domain)).
                                      Distinct(StringComparer.OrdinalIgnoreCase).
                                      Order()];

        #endregion

        #region (private) PublicKey() / DkimRecord()

        /// <summary>
        /// The public half of the DKIM key, as the p= tag has it.
        /// </summary>
        private String PublicKey()
        {

            using var rsa = RSA.Create();

            rsa.ImportFromPem(File.ReadAllText(cli.Server.DkimPrivateKeyPath));

            return Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo());

        }

        /// <summary>
        /// The DKIM record's text, in character-strings of at most 255 characters.
        /// </summary>
        private String DkimRecord()
        {

            var text    = $"v=DKIM1; k=rsa; p={PublicKey()}";
            var strings = new List<String>();

            for (var i = 0; i < text.Length; i += 255)
                strings.Add($"\"{text.Substring(i, Math.Min(255, text.Length - i))}\"");

            return String.Join(" ", strings);

        }

        #endregion

        #region (private static) Exchange(MX)

        /// <summary>
        /// Where an MX points; "." for the null MX of a domain that receives
        /// no mail at all (RFC 7505).
        /// </summary>
        private static String Exchange(MX Record)
        {

            var exchange = Record.Exchange.FullName.TrimEnd('.');

            return exchange.Length > 0 ? exchange : ". (null MX: no mail at all)";

        }

        #endregion

        #region (private static) IsLocal(Name)

        private static Boolean IsLocal(String Name)

            => Name.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
               Name.EndsWith(".localhost",   StringComparison.OrdinalIgnoreCase) ||
               Name.EndsWith(".localdomain", StringComparison.OrdinalIgnoreCase) ||
               !Name.Contains('.');

        #endregion

    }

}
