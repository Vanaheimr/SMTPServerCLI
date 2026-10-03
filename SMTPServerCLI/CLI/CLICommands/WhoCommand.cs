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
    /// Who is at the command line now: the sessions over SSH - account, where
    /// from, which key, since when - and which of them is the one asking.
    /// </summary>
    /// <param name="CLI">The command line.</param>
    public class WhoCommand(SMTPCLI CLI) : ACLICommand<SMTPCLI>(CLI),
                                           ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public static readonly String CommandName = nameof(WhoCommand)[..^7].ToLowerFirstChar();

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

            if (cli.Server.SSH is not SSHService ssh)
                return Task.FromResult<String[]>([ "The command line is not served over SSH (--no-ssh): there is only the console." ]);

            var sessions = ssh.Sessions;

            if (sessions.Count == 0)
                return Task.FromResult<String[]>([ $"Nobody is signed in over SSH ({ssh.URL})." ]);

            return Task.FromResult<String[]>([
                $"{sessions.Count} session(s) over SSH:",
                .. sessions.Select(session => $"  {session.Account,-16} from {session.From}, since {session.Since.ToLocalTime():HH:mm:ss} " +
                                              $"({StatusCommand.Describe(DateTimeOffset.UtcNow - session.Since)})" +
                                              (session.Key is not null ? $", key {session.Key}" : "") +
                                              (cli.Account == session.Account && cli.From == session.From ? "  <- you" : ""))
            ]);

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} - who is signed in to the command line over SSH";

        #endregion

    }

}
