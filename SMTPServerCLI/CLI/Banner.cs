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

namespace org.GraphDefined.Vanaheimr.Hermod.SMTP.CLI
{

    /// <summary>
    /// What somebody who just started the server needs to know: where it
    /// answers, what it was built from, where its files are, who it is and how
    /// it treats mail - and, in a box, what has to be done before it is let
    /// near the Internet.
    /// </summary>
    /// <remarks>
    /// The same lines 'config' prints at the prompt, so that what scrolled away
    /// can be had back without a restart.
    /// </remarks>
    public static class Banner
    {

        #region Data

        /// <summary>
        /// Where the values begin.
        /// </summary>
        public const Int32 Column = 19;

        #endregion


        #region Lines(Server)

        /// <summary>
        /// The banner, line by line, beginning and ending with an empty one.
        /// </summary>
        /// <param name="Server">The started server.</param>
        /// <param name="AtStart">Whether this is the banner at the start, which alone says what the first start generated - the password of its account among it, which is shown once.</param>
        public static IReadOnlyList<String> Lines(SMTPServerInstance  Server,
                                                  Boolean             AtStart   = true)
        {

            var settings  = Server.Settings;
            var accounts  = Server.Users.Read();

            var lines     = new List<String> { "" };

            void Add(String Label, String Value)
            {

                var said = Value.Split('\n');

                lines.Add($"  {Label}".PadRight(Column) + said[0]);

                foreach (var more in said.Skip(1))
                    lines.Add(new String(' ', Column) + more);

            }

            foreach (var (label, value) in Server.Listeners())
                Add(label, value);

            Add("built from",      String.Join("\n", SMTPServerInstance.BuiltFrom()));

            Add("hostname",        settings.Hostname);
            Add("local domains",   String.Join(", ", SMTPServerInstance.LocalDomains(settings.LocalDomains)) +
                                   " - stored here; anything else is relayed, for accounts only");
            Add("configuration",   settings.ConfigDirectory);
            Add("mail store",      settings.MailStoragePath);
            Add("accounts",        $"{accounts.Count} in {settings.UsersFilePath}");

            Add("TLS certificate", Server.Certificate is { } certificate
                                       ? $"{certificate.GetNameInfo(System.Security.Cryptography.X509Certificates.X509NameType.SimpleName, false)}" +
                                         $"{(Server.CertificateSelfSigned ? ", self-signed" : "")}, " +
                                         $"valid until {certificate.NotAfter:yyyy-MM-dd}"
                                       : "none");

            Add("DKIM signing",    $"{settings.DkimSelector}._domainkey.{settings.DkimDomain} - 'dns' prints the record to publish");
            Add("inbound checks",  "SPF, DKIM, DMARC, ARC - recorded in every stored message");
            Add("outbound",        settings.SmartHost is not null
                                       ? $"via smarthost {settings.SmartHost}:{settings.SmartHostPort}" +
                                         (settings.SmartHostUsername is not null ? $" as {settings.SmartHostUsername}" : "")
                                       : "directly to each domain's MX" +
                                         (Configuration.OutboundRequireStartTls ? ", STARTTLS required" : ", STARTTLS when offered") +
                                         (Configuration.EnableDane              ? ", DANE"               : ""));
            Add("reports",         $"DMARC {OnOff(Configuration.EnableDmarcReporting)}, " +
                                   $"TLS-RPT out {OnOff(Configuration.EnableTlsRptReporting)}, " +
                                   $"TLS-RPT in {OnOff(Configuration.EnableTlsRptIngestion)}, " +
                                   $"read receipts {OnOff(Configuration.EnableAutoMdn)}");
            Add("console log",     $"from {CLILogger.Name(Server.Logger.MinimumLevel)} up - 'log' changes it");

            lines.AddRange(Box(Server, accounts, AtStart));

            lines.Add("");

            return lines;

        }

        #endregion

        #region (private static) Box(Server, Accounts)

        /// <summary>
        /// What has to be done before the server is let near the Internet, in a
        /// box; nothing where there is nothing to do.
        /// </summary>
        private static IEnumerable<String> Box(SMTPServerInstance          Server,
                                               IReadOnlyList<UserAccount>  Accounts,
                                               Boolean                     AtStart)
        {

            var said = new List<String>();

            if (AtStart && Server.Generated.Count > 0)
            {
                said.Add("First start - generated:");
                said.AddRange(Server.Generated.Select(what => $"  {what}"));
            }

            if (AtStart && Server.FirstAccountPassword is String password)
            {
                said.Add($"There were no accounts, so one was made up for you, shown this once:");
                said.Add($"  user '{SMTPServerInstance.FirstAccountName}', password '{password}'");
                said.Add($"  'user passwd {SMTPServerInstance.FirstAccountName}' changes it, 'user add <name>' adds another.");
            }

            var wellKnown = Accounts.Where(account => account.WellKnownPassword is not null).ToArray();

            if (wellKnown.Length > 0)
                said.Add($"Accounts with a password everybody knows: " +
                         String.Join(", ", wellKnown.Select(account => $"{account.Name} ('{account.WellKnownPassword}')")) +
                         " - 'user passwd <name>' or 'user remove <name>'.");

            var anyCertificate = Accounts.Where(account => account.CertificateThumbprints.Contains("*")).ToArray();

            if (anyCertificate.Length > 0)
                said.Add($"users.txt lets any client certificate at all authenticate as " +
                         String.Join(", ", anyCertificate.Select(account => $"'{account.Name}'")) +
                         " - Hermod's demo file does. This server ignores that: only a certificate whose thumbprint " +
                         "is written down for an account authenticates it. 'user remove <name>' tidies it away.");

            if (Server.CertificateSelfSigned && Server.Settings.Hostname != "localhost")
                said.Add($"The TLS certificate is self-signed: replace {Server.CertificatePath} with a real one " +
                         $"for {Server.Settings.Hostname}, or give --certificate <file.pfx>.");

            if (Server.Certificate is { } certificate && !certificate.MatchesHostname(Server.Settings.Hostname))
                said.Add($"The TLS certificate is not for '{Server.Settings.Hostname}': " +
                         $"{certificate.GetNameInfo(System.Security.Cryptography.X509Certificates.X509NameType.SimpleName, false)}.");

            if (said.Count == 0)
                yield break;

            yield return "";
            yield return "  ┌─ Read this " + new String('─', 65);

            // A line that begins indented is part of the one before it, and
            // stays as far in when it is broken.
            foreach (var line in said)
            {

                var indent = new String(' ', line.Length - line.TrimStart(' ').Length);

                foreach (var wrapped in Usage.Wrap(line, $"  │ {indent}", $"  │   {indent}"))
                    yield return wrapped;

            }

            yield return "  └" + new String('─', 77);

        }

        #endregion

        #region (private static) OnOff(Value)

        private static String OnOff(Boolean Value)

            => Value ? "on" : "off";

        #endregion

    }

}
