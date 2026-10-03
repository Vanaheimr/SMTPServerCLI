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
    /// What -h says, and the 80 columns everything the program says before
    /// its prompt is kept to.
    /// </summary>
    public static class Usage
    {

        #region Data

        /// <summary>
        /// How wide a line may be.
        /// </summary>
        public const Int32 Width       = 80;

        /// <summary>
        /// Where the explanation of a switch begins.
        /// </summary>
        public const Int32 TextColumn  = 22;

        private static readonly String[] synopsis = [
            "[--hostname <name>]", "[--local-domain <domain>]...",
            "[--port <number>]", "[--submission-port <number>]", "[--implicit-tls-port <number>]",
            "[--certificate <file.pfx>]", "[--certificate-password <pw>]", "[--require-starttls]",
            "[--dkim-domain <domain>]", "[--dkim-selector <selector>]",
            "[--smarthost <host[:port]>]", "[--smarthost-user <name>]", "[--smarthost-password <pw>]",
            "[--config <dir>]", "[--mailstore <dir>]",
            "[--verbose | --quiet | --log-level <level>]", "[--version]"
        ];

        #endregion


        #region Lines()

        /// <summary>
        /// Everything -h prints, line by line.
        /// </summary>
        public static IEnumerable<String> Lines()
        {

            foreach (var line in WrapItems(synopsis, "Usage: SMTPServerCLI ", new String(' ', 21)))
                yield return line;

            yield return "";
            yield return "A self-contained SMTP server: MTA, submission and SMTPS on one set of";
            yield return "ports, with an outbound queue, DKIM signing and a command line. Every";
            yield return "default is in Configuration.cs; a switch changes one for this start only.";
            yield return "";

            yield return "Who it is:";
            foreach (var line in Switch("--hostname <name>",              $"the public hostname - banner, EHLO, Received headers, and the DKIM " +
                                                                           $"and report domain unless they are given (default: {Configuration.Hostname})")) yield return line;
            foreach (var line in Switch("--local-domain <domain>",         "a domain whose mail is stored here; everything else is relayed, for " +
                                                                           "accounts only. May be given several times and replaces the configured " +
                                                                          $"ones (default: {String.Join(", ", Configuration.LocalDomains)}); localhost is always local")) yield return line;
            yield return "";

            yield return "Where it listens:";
            foreach (var line in Switch("--port <number>",                $"mail from other servers (default: {Configuration.Port}; on the Internet: 25)")) yield return line;
            foreach (var line in Switch("--submission-port <number>",     $"clients, STARTTLS and authentication (default: {Configuration.SubmissionPort}; usually 587)")) yield return line;
            foreach (var line in Switch("--implicit-tls-port <number>",   $"clients, TLS from the first byte (default: {Configuration.ImplicitTlsPort}; usually 465)")) yield return line;
            yield return "";

            yield return "TLS:";
            foreach (var line in Switch("--certificate <file.pfx>",        "the server's certificate and key as PKCS#12, instead of the self-signed " +
                                                                           "one generated into the configuration folder on the first start")) yield return line;
            foreach (var line in Switch("--certificate-password <pw>",     "the password of that file (default: Configuration.CertificatePassword)")) yield return line;
            foreach (var line in Switch("--require-starttls",              "refuse MAIL FROM on the MTA port before STARTTLS. Off by default, so " +
                                                                           "that plaintext peers still get their mail delivered")) yield return line;
            yield return "";

            yield return "DKIM signing of outgoing mail:";
            foreach (var line in Switch("--dkim-domain <domain>",          "the d= domain (default: the hostname)")) yield return line;
            foreach (var line in Switch("--dkim-selector <selector>",     $"the s= selector; a new one gets a new key pair (default: {Configuration.DkimSelector})")) yield return line;
            yield return "";

            yield return "Outgoing mail:";
            foreach (var line in Switch("--smarthost <host[:port]>",       "relay everything through this server instead of delivering to each " +
                                                                           "domain's MX - where port 25 outbound is blocked, as it is on most " +
                                                                           "home and cloud connections. Port 25 unless given")) yield return line;
            foreach (var line in Switch("--smarthost-user <name>",         "authenticate at the smarthost as this account")) yield return line;
            foreach (var line in Switch("--smarthost-password <pw>",       "with this password")) yield return line;
            yield return "";

            yield return "Files:";
            foreach (var line in Switch("--config <dir>",                  "the TLS certificate and the DKIM keys, generated on the first start " +
                                                                          $"(default: {Shorter(ServerSettings.DefaultFolder("config"))})")) yield return line;
            foreach (var line in Switch("--mailstore <dir>",               "received mail, the outbound queue, users.txt and the reporting state " +
                                                                          $"(default: {Shorter(ServerSettings.DefaultFolder("mailstore"))})")) yield return line;
            yield return "";

            yield return "The console:";
            foreach (var line in Switch("--verbose",                       "show the log from debug up")) yield return line;
            foreach (var line in Switch("--quiet",                         "show warnings and errors only")) yield return line;
            foreach (var line in Switch("--log-level <level>",            $"one of {String.Join(", ", CLILogger.Levels)} (default: info); 'log' at the " +
                                                                           "prompt changes it while the server runs")) yield return line;
            foreach (var line in Switch("--version",                       "what this was built from, and nothing else")) yield return line;
            foreach (var line in Switch("-h, --help",                      "this")) yield return line;
            yield return "";

            yield return "Once it runs, 'help' at its prompt lists what it can be asked; Tab completes";
            yield return "commands, accounts, queue entries and messages.";

        }

        #endregion

        #region Switch(Name, Text)

        /// <summary>
        /// One switch with its explanation: beside it where there is room, and
        /// on the lines below where there is none.
        /// </summary>
        public static IEnumerable<String> Switch(String Name, String Text)
        {

            var indent = new String(' ', TextColumn);
            var first  = $"  {Name}";

            if (first.Length + 2 <= TextColumn)
                return Wrap(Text, first.PadRight(TextColumn), indent);

            return [ first, .. Wrap(Text, indent, indent) ];

        }

        #endregion

        #region Wrap(Text, First, Rest) / WrapItems(Items, First, Rest)

        /// <summary>
        /// A text broken between its words into lines of at most <see cref="Width"/>
        /// columns, the first beginning with the one prefix and the rest with the other.
        /// </summary>
        public static IEnumerable<String> Wrap(String Text, String First, String Rest)

            => WrapItems(Text.Split(' ', StringSplitOptions.RemoveEmptyEntries), First, Rest);

        /// <summary>
        /// Items broken into lines of at most <see cref="Width"/> columns,
        /// never inside one - an item too long for a line has one to itself.
        /// </summary>
        public static IEnumerable<String> WrapItems(IEnumerable<String> Items, String First, String Rest)
        {

            var line   = First;
            var empty  = true;

            foreach (var item in Items)
            {

                if (!empty && line.Length + 1 + item.Length > Width)
                {
                    yield return line;
                    line   = Rest;
                    empty  = true;
                }

                line   += empty ? item : " " + item;
                empty   = false;

            }

            yield return line;

        }

        #endregion

        #region Say(Writer, Text)

        /// <summary>
        /// A sentence on the console, kept to 80 columns.
        /// </summary>
        public static void Say(TextWriter Writer, String Text)
        {
            foreach (var line in Wrap(Text, "", ""))
                Writer.WriteLine(line);
        }

        #endregion


        #region (private static) Shorter(Path)

        /// <summary>
        /// A default folder as -h shows it: relative to where the program was
        /// started from, where it is below that.
        /// </summary>
        private static String Shorter(String Path)
        {

            var relative = System.IO.Path.GetRelativePath(Environment.CurrentDirectory, Path);

            return relative.StartsWith("..") || System.IO.Path.IsPathRooted(relative)
                       ? Path
                       : relative;

        }

        #endregion

    }

}
