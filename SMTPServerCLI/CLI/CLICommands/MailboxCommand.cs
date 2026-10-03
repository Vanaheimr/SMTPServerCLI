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

using System.Globalization;

using org.GraphDefined.Vanaheimr.CLI;
using org.GraphDefined.Vanaheimr.Illias;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SMTP.CLI
{

    /// <summary>
    /// The mail that arrived for the local domains: the newest of it in one
    /// line each, one message as it was stored, or one message gone.
    /// </summary>
    /// <remarks>
    /// Hermod stores every message as an .eml in the mail store, named by the
    /// time it arrived, with the envelope and what SPF, DKIM and DMARC said of
    /// it in X- headers in front of the message itself - which is what a line
    /// of the listing is made of. There are no mailboxes: whatever is local is
    /// in one folder, whoever it was for.
    /// </remarks>
    /// <param name="CLI">The command line.</param>
    public class MailboxCommand(SMTPCLI CLI) : ACLICommand<SMTPCLI>(CLI),
                                               ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public static readonly String CommandName = nameof(MailboxCommand)[..^7].ToLowerFirstChar();

        /// <summary>
        /// How many lines of a message 'show' prints at most.
        /// </summary>
        public const Int32 MaxLines = 200;

        private static readonly String[] subcommands = [ "list", "show", "delete" ];

        #endregion

        #region Suggest(Arguments)

        public override IEnumerable<SuggestionResponse> Suggest(String[] Arguments)
        {

            if (Arguments.Length == 1)
                return SMTPCLI.Is(CommandName, Arguments[0])
                           ? SMTPCLI.CompleteNext   (CommandName, subcommands)
                           : SMTPCLI.CompleteCommand(CommandName, Arguments[0]);

            if (!SMTPCLI.Is(CommandName, Arguments[0]))
                return [];

            var needsMessage = Arguments[1].Equals("show",   StringComparison.OrdinalIgnoreCase) ||
                               Arguments[1].Equals("delete", StringComparison.OrdinalIgnoreCase);

            if (Arguments.Length == 2)
                return needsMessage
                           ? SMTPCLI.CompleteNext($"{CommandName} {Arguments[1].ToLowerInvariant()}", Names(20))
                           : SMTPCLI.CompleteWord(CommandName, Arguments[1], subcommands);

            if (Arguments.Length == 3 && needsMessage)
                return SMTPCLI.CompleteWord($"{CommandName} {Arguments[1].ToLowerInvariant()}", Arguments[2], Names(500));

            return [];

        }

        #endregion

        #region Execute(Arguments, CancellationToken)

        public override async Task<String[]> Execute(String[]           Arguments,
                                                     CancellationToken  CancellationToken)
        {

            var server  = cli.Server;
            var what    = Arguments.Length > 1 ? Arguments[1].ToLowerInvariant() : "list";

            switch (what)
            {

                case "list" when Arguments.Length <= 3:
                {

                    var count = 20;

                    if (Arguments.Length == 3 &&
                        (!Int32.TryParse(Arguments[2], NumberStyles.None, CultureInfo.InvariantCulture, out count) || count < 1))
                        return [ $"'{Arguments[2]}' is no number of messages." ];

                    var all = Messages(server).ToArray();

                    if (all.Length == 0)
                        return [ $"No mail has arrived in {server.Settings.MailStoragePath}." ];

                    var lines = new List<String> { $"{Math.Min(count, all.Length)} newest of {all.Length} message(s):" };

                    foreach (var file in all.Take(count))
                        lines.Add($"  {Summary(await Headers(file, CancellationToken), Path.GetFileNameWithoutExtension(file))}");

                    return [.. lines];

                }

                case "show" when Arguments.Length == 3:
                {

                    if (Find(server, Arguments[2]) is not String file)
                        return [ $"No message '{Arguments[2]}' - 'mailbox list' lists them, Tab completes them." ];

                    var lines = await File.ReadAllLinesAsync(file, CancellationToken);

                    return lines.Length > MaxLines
                               ? [ .. lines.Take(MaxLines), $"... {lines.Length - MaxLines} more line(s) in {file}" ]
                               : lines;

                }

                case "delete" when Arguments.Length == 3:
                {

                    if (Find(server, Arguments[2]) is not String file)
                        return [ $"No message '{Arguments[2]}' - 'mailbox list' lists them, Tab completes them." ];

                    File.Delete(file);

                    server.Logger.Log(LogLevel.Info, $"{cli.Who} deleted the message {Path.GetFileName(file)}.");

                    return [ $"Deleted {Path.GetFileName(file)}." ];

                }

                default:
                    return [ $"Usage: {Help()}" ];

            }

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} [list [<count>] | show <message> | delete <message>] - the mail stored for the local domains, newest first";

        #endregion


        #region (static) Messages(Server)

        /// <summary>
        /// The stored messages, newest first - their names begin with the time
        /// they arrived.
        /// </summary>
        public static IEnumerable<String> Messages(SMTPServerInstance Server)

            => Directory.Exists(Server.Settings.MailStoragePath)
                   ? Directory.EnumerateFiles(Server.Settings.MailStoragePath, "*.eml").
                               OrderByDescending(file => Path.GetFileName(file), StringComparer.Ordinal)
                   : [];

        #endregion

        #region (private) Names(Count)

        private IEnumerable<String> Names(Int32 Count)

            => Messages(cli.Server).Take(Count).Select(file => Path.GetFileNameWithoutExtension(file));

        #endregion

        #region (private static) Find(Server, Typed)

        /// <summary>
        /// The one stored message whose name begins with what was typed.
        /// </summary>
        private static String? Find(SMTPServerInstance Server, String Typed)
        {

            var name     = Typed.EndsWith(".eml", StringComparison.OrdinalIgnoreCase) ? Typed[..^4] : Typed;
            var matches  = Messages(Server).Where(file => Path.GetFileNameWithoutExtension(file).StartsWith(name, StringComparison.OrdinalIgnoreCase)).
                                            Take (2).
                                            ToArray();

            return matches.Length == 1 ? matches[0] : null;

        }

        #endregion

        #region (private static) Headers(File, CancellationToken)

        /// <summary>
        /// The header fields of a stored message, unfolded, the first of each name.
        /// </summary>
        private static async Task<Dictionary<String, String>> Headers(String File, CancellationToken CancellationToken)
        {

            var headers  = new Dictionary<String, String>(StringComparer.OrdinalIgnoreCase);
            var last     = (String?) null;

            using var reader = new StreamReader(File);

            while (await reader.ReadLineAsync(CancellationToken) is String line && line.Length > 0)
            {

                if ((line[0] == ' ' || line[0] == '\t') && last is not null)
                {
                    headers[last] += " " + line.Trim();
                    continue;
                }

                var colon = line.IndexOf(':');

                if (colon <= 0)
                    continue;

                last = line[..colon].Trim();

                if (!headers.TryAdd(last, line[(colon + 1)..].Trim()))
                    last = null;

            }

            return headers;

        }

        #endregion

        #region (private static) Summary(Headers, Name)

        private static String Summary(Dictionary<String, String> Headers, String Name)
        {

            String Get(String Field)
                => Headers.TryGetValue(Field, out var value) ? value : "?";

            var checks = Headers.ContainsKey("X-SPF-Result")
                             ? $" [SPF {Get("X-SPF-Result")}, DKIM {Get("X-DKIM-Result")}, DMARC {Get("X-DMARC-Result")}]"
                             : "";

            return $"{Name}  {Get("X-Envelope-From")} -> {Get("X-Envelope-To")}: {Get("Subject")}{checks}";

        }

        #endregion

    }

}
