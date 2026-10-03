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

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SMTP.CLI
{

    /// <summary>
    /// How the server is doing, in a few lines: since when it runs, what is
    /// waiting to go out, what has arrived, and who can authenticate.
    /// </summary>
    /// <param name="CLI">The command line.</param>
    public class StatusCommand(SMTPCLI CLI) : ACLICommand<SMTPCLI>(CLI),
                                              ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public static readonly String CommandName = nameof(StatusCommand)[..^7].ToLowerFirstChar();

        #endregion

        #region Suggest(Arguments)

        public override IEnumerable<SuggestionResponse> Suggest(String[] Arguments)

            => Arguments.Length == 1
                   ? SMTPCLI.CompleteCommand(CommandName, Arguments[0])
                   : [];

        #endregion

        #region Execute(Arguments, CancellationToken)

        public override Task<String[]> Execute(String[]           Arguments,
                                               CancellationToken  CancellationToken)
        {

            var server    = cli.Server;
            var queue     = QueueCommand.Entries(server, QueueCommand.Pending).ToArray();
            var accounts  = server.Users.Read();
            var uptime    = Timestamp.Now - server.StartedAt;

            return Task.FromResult<String[]>([
                $"  server         {(server.IsRunning ? "accepting" : "stopped")}, up {Describe(uptime)} (since {server.StartedAt.ToLocalTime():yyyy-MM-dd HH:mm:ss})",
                $"  outbound       {queue.Count(mail => mail.Status == QueueItemStatus.Pending)} pending, " +
                                 $"{queue.Count(mail => mail.Status == QueueItemStatus.Deferred)} deferred, " +
                                 $"{server.QueueProcessor.ActiveDeliveries} being delivered now, " +
                                 $"{QueueCommand.Count(server, QueueCommand.Failed)} failed, " +
                                 $"{QueueCommand.Count(server, QueueCommand.Delivered)} delivered",
                $"  mailbox        {MailboxCommand.Messages(server).Count()} message(s) in {server.Settings.MailStoragePath}",
                $"  accounts       {(accounts.Count > 0 ? String.Join(", ", accounts.Select(account => account.Name)) : "none - nobody can relay")}",
                $"  SSH            {(server.SSH is SSHService ssh ? $"{ssh.Sessions.Count} session(s) on {ssh.URL} - 'who' lists them" : "off")}",
                $"  console log    from {CLILogger.Name(server.Logger.MinimumLevel)} up"
            ]);

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} - uptime, the outbound queue, the mailbox and the accounts at a glance";

        #endregion


        #region (static) Describe(Duration)

        /// <summary>
        /// A duration as somebody says it: 3d 4h, 2h 5m, 42s.
        /// </summary>
        public static String Describe(TimeSpan Duration)

            => Duration.TotalDays    >= 1 ? $"{(Int32) Duration.TotalDays}d {Duration.Hours}h"
             : Duration.TotalHours   >= 1 ? $"{(Int32) Duration.TotalHours}h {Duration.Minutes}m"
             : Duration.TotalMinutes >= 1 ? $"{(Int32) Duration.TotalMinutes}m {Duration.Seconds}s"
             :                              $"{Math.Max(0, (Int32) Duration.TotalSeconds)}s";

        #endregion

    }

}
