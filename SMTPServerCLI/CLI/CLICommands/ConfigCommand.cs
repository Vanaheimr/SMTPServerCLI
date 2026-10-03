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
    /// The banner again: what the server was started with, long after it
    /// scrolled away under the log.
    /// </summary>
    /// <param name="CLI">The command line.</param>
    public class ConfigCommand(SMTPCLI CLI) : ACLICommand<SMTPCLI>(CLI),
                                              ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public static readonly String CommandName = nameof(ConfigCommand)[..^7].ToLowerFirstChar();

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

            => Task.FromResult<String[]>([.. Banner.Lines(cli.Server, AtStart: false)]);

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} - what the server was started with: ports, folders, certificate, DKIM, outbound";

        #endregion

    }

}
