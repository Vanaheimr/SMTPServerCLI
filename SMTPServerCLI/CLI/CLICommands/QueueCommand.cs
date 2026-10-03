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

using System.Text.Json;
using System.Text.Json.Serialization;

using org.GraphDefined.Vanaheimr.CLI;
using org.GraphDefined.Vanaheimr.Illias;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SMTP.CLI
{

    /// <summary>
    /// The outbound queue: what is waiting to go out and why, what gave up,
    /// and a nudge for what waits for its next retry.
    /// </summary>
    /// <remarks>
    /// The queue is a folder of JSON files - queue/pending, queue/failed and
    /// queue/delivered in the mail store - and the listing reads them as they
    /// are, because Hermod's queue only hands out what is due right now, and
    /// a mail that waits for its retry in an hour is precisely the one somebody
    /// asks about. Changes go through the queue itself.
    /// </remarks>
    /// <param name="CLI">The command line.</param>
    public class QueueCommand(SMTPCLI CLI) : ACLICommand<SMTPCLI>(CLI),
                                             ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public static readonly String CommandName = nameof(QueueCommand)[..^7].ToLowerFirstChar();

        /// <summary>
        /// The folders of the queue, below queue/ in the mail store.
        /// </summary>
        public const String Pending    = "pending";
        public const String Failed     = "failed";
        public const String Delivered  = "delivered";

        private static readonly String[] subcommands = [ "list", "failed", "show", "flush", "remove" ];

        private static readonly JsonSerializerOptions jsonOptions = new() {
            Converters = { new JsonStringEnumConverter() }
        };

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

            if (Arguments.Length == 2)
            {

                // "queue show" is whole: on to the entries it could be.
                if (Arguments[1].Equals("show",   StringComparison.OrdinalIgnoreCase) ||
                    Arguments[1].Equals("remove", StringComparison.OrdinalIgnoreCase))
                    return SMTPCLI.CompleteNext($"{CommandName} {Arguments[1].ToLowerInvariant()}", Ids(Arguments[1]));

                return SMTPCLI.CompleteWord(CommandName, Arguments[1], subcommands);

            }

            if (Arguments.Length == 3 &&
               (Arguments[1].Equals("show",   StringComparison.OrdinalIgnoreCase) ||
                Arguments[1].Equals("remove", StringComparison.OrdinalIgnoreCase)))
                return SMTPCLI.CompleteWord($"{CommandName} {Arguments[1].ToLowerInvariant()}", Arguments[2], Ids(Arguments[1]));

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

                #region list

                case "list" when Arguments.Length <= 2:
                {

                    var entries = Entries(server, Pending).OrderBy(mail => mail.NextRetry).ToArray();

                    if (entries.Length == 0)
                        return [ $"Nothing waits to go out. {Count(server, Failed)} failed, {Count(server, Delivered)} delivered - 'queue failed' lists what failed." ];

                    return [
                        $"{entries.Length} waiting to go out:",
                        .. entries.Select(Line)
                    ];

                }

                #endregion

                #region failed

                case "failed" when Arguments.Length <= 2:
                {

                    var entries = await server.MailQueue.GetFailedAsync(50, CancellationToken);

                    if (entries.Count == 0)
                        return [ "Nothing failed." ];

                    return [
                        $"{entries.Count} gave up (newest first, at most 50):",
                        .. entries.Select(Line)
                    ];

                }

                #endregion

                #region show <id>

                case "show" when Arguments.Length == 3:
                {

                    if (Find(server, Arguments[2]) is not { } id)
                        return [ $"No entry '{Arguments[2]}' in the queue - 'queue list' and 'queue failed' list them." ];

                    if (await server.MailQueue.GetByIdAsync(id, CancellationToken) is not { } mail)
                        return [ $"'{id}' left the queue just now." ];

                    var subject = mail.MessageContent.Split("\r\n").
                                                      TakeWhile(line => line.Length > 0).
                                                      FirstOrDefault(line => line.StartsWith("Subject:", StringComparison.OrdinalIgnoreCase));

                    return [
                        $"  id             {mail.Id}",
                        $"  status         {mail.Status}",
                        $"  from           {Sender(mail)}",
                        $"  to             {String.Join(", ", mail.EnvelopeTo)}",
                        $"  domain         {mail.TargetDomain}",
                        $"  subject        {subject?["Subject:".Length..].Trim() ?? "(none)"}",
                        $"  size           {mail.MessageContent.Length:N0} characters",
                        $"  queued         {mail.QueuedAt.ToLocalTime():yyyy-MM-dd HH:mm:ss}",
                        $"  attempts       {mail.RetryCount}",
                        $"  next attempt   {(mail.Status is QueueItemStatus.Pending or QueueItemStatus.Deferred ? $"{mail.NextRetry.ToLocalTime():yyyy-MM-dd HH:mm:ss}" : "none")}",
                        $"  last error     {mail.LastError ?? "none"}",
                        $"  remote MX      {mail.RemoteMx ?? "-"}",
                        $"  remote said    {mail.RemoteResponse ?? "-"}",
                        $"  REQUIRETLS     {(mail.RequireTls ? "yes" : "no")}, priority {mail.Priority}, DSN {mail.Notify}"
                    ];

                }

                #endregion

                #region flush

                case "flush" when Arguments.Length == 2:
                {

                    var deferred = Entries(server, Pending).Where(mail => mail.Status == QueueItemStatus.Deferred && mail.NextRetry > Timestamp.Now).ToArray();

                    foreach (var mail in deferred)
                    {
                        mail.NextRetry = Timestamp.Now;
                        await server.MailQueue.UpdateAsync(mail, CancellationToken);
                    }

                    server.MailQueue.SignalRetryCheck();

                    return [ deferred.Length > 0
                                 ? $"{deferred.Length} deferred mail(s) will be tried again now - the log says how it goes."
                                 : "Nothing waited for a retry; the queue was asked to look anyway." ];

                }

                #endregion

                #region remove <id>

                case "remove" when Arguments.Length == 3:
                {

                    if (Find(server, Arguments[2]) is not { } id ||
                        !File.Exists(Path.Combine(Folder(server, Pending), $"{id}.json")))
                        return [ $"No entry '{Arguments[2]}' waits to go out - 'queue list' lists them." ];

                    await server.MailQueue.RemoveAsync(id, CancellationToken);

                    server.Logger.Log(LogLevel.Info, $"Removed {id} from the outbound queue at the command line.");

                    return [ $"Removed {id}. Nobody is told: no bounce goes back to the sender." ];

                }

                #endregion

                default:
                    return [ $"Usage: {Help()}" ];

            }

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} [list | failed | show <id> | flush | remove <id>] - the outbound queue; " +
                "flush retries what is deferred now, an id may be shortened";

        #endregion


        #region (static) Entries(Server, Folder) / Count(Server, Folder)

        /// <summary>
        /// The entries in one folder of the queue, as they are on disk; those
        /// that cannot be read are left out.
        /// </summary>
        public static IEnumerable<QueuedMail> Entries(SMTPServerInstance Server, String Folder)
        {

            var folder = QueueCommand.Folder(Server, Folder);

            if (!Directory.Exists(folder))
                yield break;

            foreach (var file in Directory.EnumerateFiles(folder, "*.json"))
            {

                QueuedMail? mail = null;

                try
                {
                    mail = JsonSerializer.Deserialize<QueuedMail>(File.ReadAllText(file), jsonOptions);
                }
                catch
                {
                    // Being written right now, or not one of ours.
                }

                if (mail is not null)
                    yield return mail;

            }

        }

        /// <summary>
        /// How many entries one folder of the queue has.
        /// </summary>
        public static Int32 Count(SMTPServerInstance Server, String Folder)
        {

            var folder = QueueCommand.Folder(Server, Folder);

            return Directory.Exists(folder)
                       ? Directory.EnumerateFiles(folder, "*.json").Count()
                       : 0;

        }

        #endregion

        #region (private static) Folder(Server, Name) / Find(Server, Typed) / Ids(Subcommand)

        private static String Folder(SMTPServerInstance Server, String Name)

            => Path.Combine(Server.Settings.MailStoragePath, "queue", Name);

        /// <summary>
        /// The id of the one entry that begins with what was typed - pending or failed.
        /// </summary>
        private static String? Find(SMTPServerInstance Server, String Typed)
        {

            var matches = new[] { Pending, Failed }.
                              Select       (name => Folder(Server, name)).
                              Where        (Directory.Exists).
                              SelectMany   (folder => Directory.EnumerateFiles(folder, "*.json")).
                              Select       (file => Path.GetFileNameWithoutExtension(file)).
                              Where        (id => id.StartsWith(Typed, StringComparison.OrdinalIgnoreCase)).
                              Distinct     ().
                              ToArray      ();

            return matches.Length == 1 ? matches[0] : null;

        }

        private IEnumerable<String> Ids(String Subcommand)
        {

            var folders = Subcommand.Equals("remove", StringComparison.OrdinalIgnoreCase)
                              ? new[] { Pending }
                              : new[] { Pending, Failed };

            return folders.Select    (name => Folder(cli.Server, name)).
                           Where     (Directory.Exists).
                           SelectMany(folder => Directory.EnumerateFiles(folder, "*.json")).
                           Select    (file => Path.GetFileNameWithoutExtension(file)).
                           Take      (50);

        }

        #endregion

        #region (private static) Sender(Mail)

        /// <summary>
        /// The envelope sender as SMTP writes it - "<>" for the null sender of
        /// a bounce, rather than nothing at all.
        /// </summary>
        private static String Sender(QueuedMail Mail)

            => Mail.EnvelopeFrom.Length > 0 ? Mail.EnvelopeFrom : "<>";

        #endregion

        #region (private static) Line(Mail)

        /// <summary>
        /// One entry in one line: the first twenty characters of its id - a UUIDv7,
        /// whose first twelve are only the millisecond it was queued in.
        /// </summary>
        private static String Line(QueuedMail Mail)

            => $"  {Mail.Id[..Math.Min(20, Mail.Id.Length)]}  {Mail.Status,-9} {Sender(Mail)} -> {String.Join(", ", Mail.EnvelopeTo)}" +
               (Mail.Status is QueueItemStatus.Pending or QueueItemStatus.Deferred
                    ? $", attempt {Mail.RetryCount + 1} at {Mail.NextRetry.ToLocalTime():HH:mm:ss}"
                    : "") +
               (Mail.LastError is not null ? $" - {Mail.LastError}" : "");

        #endregion

    }

}
