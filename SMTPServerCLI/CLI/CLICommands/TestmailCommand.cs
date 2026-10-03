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

using org.GraphDefined.Vanaheimr.CLI;
using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.Mail;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SMTP.CLI
{

    /// <summary>
    /// Send a short test message to somebody elsewhere: through the outbound
    /// queue, DKIM-signed, to the recipient's MX or the smarthost - the way
    /// every message this server relays goes.
    /// </summary>
    /// <remarks>
    /// The quickest answer to "does mail from here arrive, and does it pass?":
    /// send one to a mailbox at a large provider and read SPF, DKIM and DMARC
    /// off its "show original". Mail for a local domain is refused here, since
    /// the queue only knows the way out.
    /// </remarks>
    /// <param name="CLI">The command line.</param>
    public class TestmailCommand(SMTPCLI CLI) : ACLICommand<SMTPCLI>(CLI),
                                                ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public static readonly String CommandName = nameof(TestmailCommand)[..^7].ToLowerFirstChar();

        #endregion

        #region Suggest(Arguments)

        public override IEnumerable<SuggestionResponse> Suggest(String[] Arguments)
        {

            if (Arguments.Length == 1)
                return SMTPCLI.Is(CommandName, Arguments[0])
                           ? [ SuggestionResponse.CommandHelp(Help()) ]
                           : SMTPCLI.CompleteCommand(CommandName, Arguments[0]);

            return [];

        }

        #endregion

        #region Execute(Arguments, CancellationToken)

        public override async Task<String[]> Execute(String[]           Arguments,
                                                     CancellationToken  CancellationToken)
        {

            if (Arguments.Length is < 2 or > 3)
                return [ $"Usage: {Help()}" ];

            var server    = cli.Server;
            var settings  = server.Settings;
            var fromText  = Arguments.Length == 3 ? Arguments[2] : $"postmaster@{settings.DkimDomain}";

            if (SimpleEMailAddress.TryParse(Arguments[1]) is not SimpleEMailAddress to)
                return [ $"'{Arguments[1]}' is no e-mail address." ];

            if (SimpleEMailAddress.TryParse(fromText) is not SimpleEMailAddress from)
                return [ $"'{fromText}' is no e-mail address." ];

            if (SMTPServerInstance.LocalDomains(settings.LocalDomains).Contains(to.Domain.TrimEnd('.').ToLowerInvariant()))
                return [ $"{to.Domain} is a local domain: mail for it is stored here, and the queue only knows the way out. " +
                          "Send to a mailbox elsewhere." ];

            var mail = new TextEMailBuilder {
                           Text = String.Join("\r\n",
                                      $"This is a test message from the SMTP server {settings.Hostname},",
                                      $"sent at its command line at {Timestamp.Now:yyyy-MM-dd HH:mm:ss} UTC.",
                                       "",
                                      $"It was signed with DKIM as {settings.DkimSelector}._domainkey.{settings.DkimDomain}.",
                                       "Look at the authentication results in the message's headers -",
                                       "SPF, DKIM and DMARC should all say 'pass'.")
                       };

            mail.From     = (EMailAddress) from;
            mail.To       = (EMailAddress) to;
            mail.Subject  = $"Test from {settings.Hostname}";

            var ids = await server.MailSender.SendAsync((EMail) mail, CancellationToken);

            server.Logger.Log(LogLevel.Info, $"{cli.Who} queued a test message from {from} to {to}.");

            return [ $"Queued as {String.Join(", ", ids)}: from {from} to {to}" +
                     (settings.SmartHost is not null ? $" via {settings.SmartHost}." : $", to the MX of {to.Domain}.") +
                      " The log says how the delivery goes; 'queue' shows it while it waits." ];

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} <to> [<from>] - send a DKIM-signed test message to an address elsewhere (from: postmaster@<DKIM domain>)";

        #endregion

    }

}
