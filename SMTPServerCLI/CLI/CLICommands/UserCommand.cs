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
    /// The accounts that may submit and relay mail: list them, add one, give
    /// one a new password, remove one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Written to users.txt, which the server reads again as soon as it
    /// changes: an account added here can authenticate at the next AUTH,
    /// without a restart.
    /// </para>
    /// <para>
    /// Without a password one is made up and shown once. That is the way to
    /// prefer: a password typed here stays in the history of this command
    /// line, and 'history' shows it to whoever comes to the console next.
    /// </para>
    /// </remarks>
    /// <param name="CLI">The command line.</param>
    public class UserCommand(SMTPCLI CLI) : ACLICommand<SMTPCLI>(CLI),
                                            ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public static readonly String CommandName = nameof(UserCommand)[..^7].ToLowerFirstChar();

        private static readonly String[] subcommands = [ "list", "add", "passwd", "remove" ];

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

            var needsAccount = Arguments[1].Equals("passwd", StringComparison.OrdinalIgnoreCase) ||
                               Arguments[1].Equals("remove", StringComparison.OrdinalIgnoreCase);

            if (Arguments.Length == 2)
                return needsAccount
                           ? SMTPCLI.CompleteNext($"{CommandName} {Arguments[1].ToLowerInvariant()}", Names())
                           : SMTPCLI.CompleteWord(CommandName, Arguments[1], subcommands);

            if (Arguments.Length == 3 && needsAccount)
                return SMTPCLI.CompleteWord($"{CommandName} {Arguments[1].ToLowerInvariant()}", Arguments[2], Names());

            return [];

        }

        #endregion

        #region Execute(Arguments, CancellationToken)

        public override Task<String[]> Execute(String[]           Arguments,
                                               CancellationToken  CancellationToken)

            => Task.FromResult(Run(Arguments));

        private String[] Run(String[] Arguments)
        {

            var users  = cli.Server.Users;
            var what   = Arguments.Length > 1 ? Arguments[1].ToLowerInvariant() : "list";

            switch (what)
            {

                case "list" when Arguments.Length <= 2:
                {

                    var accounts = users.Read();

                    if (accounts.Count == 0)
                        return [ $"No accounts in {users.Path}: nobody can submit or relay. 'user add <name>' adds one." ];

                    return [
                        $"{accounts.Count} account(s) in {users.Path}:",
                        .. accounts.Select(account => $"  {account.Name,-20} " + String.Join(", ", Mechanisms(account)) +
                                                      (account.WellKnownPassword is not null ? $"  <- password '{account.WellKnownPassword}', known to everybody" : "") +
                                                      (account.CertificateThumbprints.Contains("*") ? "  <- '*' for any certificate, which this server ignores" : ""))
                    ];

                }

                case "add"    when Arguments.Length is 3 or 4:
                case "passwd" when Arguments.Length is 3 or 4:
                {

                    var name      = Arguments[2];
                    var madeUp    = Arguments.Length == 3;
                    var password  = madeUp ? UsersFile.MakeUpPassword() : Arguments[3];

                    if (users.SetPassword(name, password, MustExist: what == "passwd") is String refused)
                        return [ refused ];

                    cli.Server.Logger.Log(LogLevel.Info, what == "add"
                                                             ? $"Added the account '{name}' at the command line."
                                                             : $"Gave the account '{name}' a new password at the command line.");

                    return madeUp
                               ? [ $"'{name}' has the password '{password}' now - shown this once." ]
                               : [ $"'{name}' has the password you gave it now. It is in this command line's history as well." ];

                }

                case "remove" when Arguments.Length == 3:
                {

                    if (!users.Remove(Arguments[2]))
                        return [ $"There is no account '{Arguments[2]}'." ];

                    cli.Server.Logger.Log(LogLevel.Info, $"Removed the account '{Arguments[2]}' at the command line.");

                    return [ $"Removed '{Arguments[2]}'. A session it is signed in to right now stays signed in until it ends." ];

                }

                default:
                    return [ $"Usage: {Help()}" ];

            }

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} [list | add <name> [<password>] | passwd <name> [<password>] | remove <name>] - " +
                "the accounts that may submit and relay; without a password one is made up";

        #endregion


        #region (private) Names()

        private IEnumerable<String> Names()

            => cli.Server.Users.Read().Select(account => account.Name);

        #endregion

        #region (private static) Mechanisms(Account)

        /// <summary>
        /// The SASL mechanisms an account can authenticate with.
        /// </summary>
        private static IEnumerable<String> Mechanisms(UserAccount Account)
        {

            if (Account.HasPassword)
                yield return "PLAIN/LOGIN";

            if (Account.HasScram)
                yield return "SCRAM-SHA-256";

            var pinned = Account.CertificateThumbprints.Count(thumbprint => thumbprint != "*");

            if (pinned > 0)
                yield return $"EXTERNAL ({pinned} certificate(s))";

        }

        #endregion

    }

}
