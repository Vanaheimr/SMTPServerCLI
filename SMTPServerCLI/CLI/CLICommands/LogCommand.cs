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
    /// How much of the log the console shows: from which level up, or none.
    /// </summary>
    /// <remarks>
    /// --verbose and --quiet say it at the start; this changes it while the
    /// server runs - debug while chasing a delivery, off to type in peace.
    /// </remarks>
    /// <param name="CLI">The command line.</param>
    public class LogCommand(SMTPCLI CLI) : ACLICommand<SMTPCLI>(CLI),
                                           ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public static readonly String CommandName = nameof(LogCommand)[..^7].ToLowerFirstChar();

        #endregion

        #region Suggest(Arguments)

        public override IEnumerable<SuggestionResponse> Suggest(String[] Arguments)
        {

            if (Arguments.Length == 1)
                return SMTPCLI.Is(CommandName, Arguments[0])
                           ? SMTPCLI.CompleteNext   (CommandName, CLILogger.Levels)
                           : SMTPCLI.CompleteCommand(CommandName, Arguments[0]);

            if (Arguments.Length == 2 && SMTPCLI.Is(CommandName, Arguments[0]))
                return SMTPCLI.CompleteWord(CommandName, Arguments[1], CLILogger.Levels);

            return [];

        }

        #endregion

        #region Execute(Arguments, CancellationToken)

        public override Task<String[]> Execute(String[]           Arguments,
                                               CancellationToken  CancellationToken)
        {

            var logger = cli.Server.Logger;

            if (Arguments.Length > 2)
                return Task.FromResult<String[]>([ $"Usage: {Help()}" ]);

            if (Arguments.Length == 1)
                return Task.FromResult<String[]>([ Shows(logger.MinimumLevel, "") ]);

            if (!CLILogger.TryParse(Arguments[1], out var level))
                return Task.FromResult<String[]>([ $"'{Arguments[1]}' is no level. Use one of {String.Join(", ", CLILogger.Levels)}." ]);

            logger.MinimumLevel = level;

            return Task.FromResult<String[]>([ Shows(level, " now") ]);

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} [{String.Join("|", CLILogger.Levels)}] - how much of the log the console shows";

        #endregion


        #region (private static) Shows(Level, Now)

        private static String Shows(LogLevel? Level, String Now)

            => Level is LogLevel shown
                   ? $"The console shows the log from {CLILogger.Name(shown)} up{Now}."
                   : $"The console shows no log{Now}.";

        #endregion

    }

}
