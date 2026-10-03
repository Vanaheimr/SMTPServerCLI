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

using System.Reflection;
using System.Runtime.InteropServices;

using org.GraphDefined.Vanaheimr.CLI;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SMTP.CLI
{

    /// <summary>
    /// The command line of a running SMTP server: Styx's line editor - Tab,
    /// the history, a log that scrolls past above the line being typed - with
    /// the server's commands, from the first prompt until 'quit', Ctrl+C or a
    /// service manager's SIGTERM.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Commands are not listed anywhere: anything in this assembly that
    /// implements ICLICommand and can be built from an SMTPCLI is one, found
    /// as Styx finds its own help, history and quit. A new command is a new
    /// file in CLI/CLICommands and nothing else.
    /// </para>
    /// <para>
    /// The base class is named with its namespace, because this one ends in
    /// CLI as well and a bare "CLI" here would be that namespace.
    /// </para>
    /// </remarks>
    public class SMTPCLI : org.GraphDefined.Vanaheimr.CLI.CLI
    {

        #region Properties

        /// <summary>
        /// The server these commands are about.
        /// </summary>
        public SMTPServerInstance  Server        { get; }

        /// <summary>
        /// The account signed in over SSH; null at the console.
        /// </summary>
        public String?             Account       { get; }

        /// <summary>
        /// Where the account signed in from; null at the console.
        /// </summary>
        public String?             From          { get; }

        /// <summary>
        /// The log as this command line shows it, where it is a session over SSH;
        /// null at the console, whose log is the server's console log.
        /// </summary>
        public LogListener?        SessionLog    { get; set; }

        /// <summary>
        /// Who is typing here, as the log names it: "the console", or the
        /// account and where it signed in from.
        /// </summary>
        public String              Who
            => Account is null
                   ? "the console"
                   : $"'{Account}' over SSH from {From}";

        #endregion

        #region Constructor(s)

        /// <summary>
        /// The command line of the given server, on the console of this process.
        /// </summary>
        /// <param name="Server">The running server.</param>
        /// <param name="AssembliesWithCLICommands">Further assemblies to search for commands.</param>
        public SMTPCLI(SMTPServerInstance  Server,
                       params Assembly[]   AssembliesWithCLICommands)

            : base(AssembliesWithCLICommands)

        {

            this.Server = Server;

            RegisterCLIType(typeof(SMTPCLI));

        }

        /// <summary>
        /// The command line of the given server on the given terminal, for an
        /// account signed in over SSH. 'quit' leaves the session; the server
        /// keeps running.
        /// </summary>
        /// <param name="Server">The running server.</param>
        /// <param name="Terminal">What the command line is typed at and written on.</param>
        /// <param name="Account">The account signed in.</param>
        /// <param name="From">Where it signed in from.</param>
        /// <param name="AssembliesWithCLICommands">Further assemblies to search for commands.</param>
        public SMTPCLI(SMTPServerInstance  Server,
                       ICLITerminal        Terminal,
                       String              Account,
                       String              From,
                       params Assembly[]   AssembliesWithCLICommands)

            : base(Terminal, AssembliesWithCLICommands)

        {

            this.Server   = Server;
            this.Account  = Account;
            this.From     = From;

            RegisterCLIType(typeof(SMTPCLI));

        }

        #endregion


        #region (protected override) GetPrompt()

        /// <summary>
        /// The server's hostname, because the consoles of a test server and the
        /// real one look alike otherwise.
        /// </summary>
        protected override String GetPrompt()

            => $"smtp@{Server.Settings.Hostname}> ";

        #endregion


        #region RunUntilStopped()

        /// <summary>
        /// The console, until 'quit', Ctrl+C or SIGTERM: a prompt where somebody
        /// can type, and nothing but waiting where nobody can.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Started by systemd, from a script or with its output going into a
        /// file, there is no terminal to type at and no cursor to move, and
        /// drawing a prompt throws rather than waits. Then the server simply
        /// runs, and the log is all there is on the console.
        /// </para>
        /// <para>
        /// Ctrl+C means stop; the line editor has a handler of its own for it,
        /// which cancels the command that is running, and both fire. 'quit' is
        /// the same thing said politely. SIGTERM, what a service manager sends,
        /// means stop as well.
        /// </para>
        /// </remarks>
        public async Task RunUntilStopped()
        {

            var canBeTypedAt = !Console.IsInputRedirected &&
                               !Console.IsOutputRedirected;

            Console.WriteLine(canBeTypedAt
                                  ? "Type 'help' for what can be typed here, Tab to complete, 'quit' or Ctrl+C to stop."
                                  : "Press Ctrl+C to stop. (No terminal here, so nothing to type at.)");
            Console.WriteLine();

            var stopped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

            void OnCancelKeyPress(Object? Sender, ConsoleCancelEventArgs Event)
            {
                Event.Cancel = true;
                stopped.TrySetResult();
            }

            Console.CancelKeyPress += OnCancelKeyPress;

            PosixSignalRegistration? terminated = null;

            try
            {
                terminated = PosixSignalRegistration.Create(PosixSignal.SIGTERM, context => {
                                 context.Cancel = true;
                                 stopped.TrySetResult();
                             });
            }
            catch (PlatformNotSupportedException)
            {
                // Where there is no SIGTERM there is nothing that sends one.
            }

            var promptLeft = false;

            try
            {

                if (canBeTypedAt)
                    promptLeft = await Prompt(stopped.Task);

                else
                    await stopped.Task;

            }
            finally
            {

                // The console back to the log alone, or the prompt would be put
                // back under every entry the shutdown writes. Its line is ended
                // first, or the first of those entries would start right behind
                // what was being typed.
                Server.Logger.ShareConsoleWith(null);

                if (promptLeft)
                    Console.WriteLine();

                Console.CancelKeyPress -= OnCancelKeyPress;
                terminated?.Dispose();

            }

        }

        #endregion

        #region (private) Prompt(Stopped)

        /// <summary>
        /// The prompt, until it is quit or the server is to stop - and a new one
        /// where one broke. Says whether a prompt is still standing.
        /// </summary>
        private async Task<Boolean> Prompt(Task Stopped)
        {

            var brokeAtOnce = false;

            while (true)
            {

                // From here two things write on one screen: this command line,
                // and the server's log from whichever session did the thing it
                // reports. So the log asks the command line for the screen.
                Server.Logger.ShareConsoleWith(WriteBlock);

                // On a thread of its own, because Console.ReadKey blocks the one
                // it is called on, and Ctrl+C would have nobody left to wake.
                var since   = System.Diagnostics.Stopwatch.GetTimestamp();
                var typing  = Task.Run(Run);

                await Task.WhenAny(Stopped, typing);

                // Quit - or stopped, and then the prompt is still reading keys.
                if (!typing.IsFaulted)
                    return !typing.IsCompleted;

                // A command line that broke is not somebody asking the server to
                // stop: a new one, unless the last one was already a new one and
                // broke again the moment it started - a console a prompt cannot
                // be drawn on at all.
                Server.Logger.ShareConsoleWith(null);

                var atOnce  = System.Diagnostics.Stopwatch.GetElapsedTime(since) < TimeSpan.FromSeconds(1);
                var giveUp  = atOnce && brokeAtOnce;

                brokeAtOnce = atOnce;

                Server.Logger.Log(
                    LogLevel.Warning,
                    $"The command line stopped working: {typing.Exception?.GetBaseException().Message} " +
                    (giveUp
                         ? "A new one broke again as soon as it started, so there is none; the server keeps running, and Ctrl+C stops it."
                         : "A new one is started.")
                );

                if (giveUp)
                {
                    await Stopped;
                    return false;
                }

            }

        }

        #endregion


        #region (static) Is(Command, Typed) / CompleteCommand(...) / CompleteWord(...) / CompleteNext(...)

        // What every command of the server's needs for Tab, said once.

        /// <summary>
        /// Whether the first word is the given command, as typed in any case.
        /// </summary>
        public static Boolean Is(String Command, String Typed)

            => Command.Equals(Typed, StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// Tab on the first word: the command once it is whole, and before.
        /// </summary>
        public static IEnumerable<SuggestionResponse> CompleteCommand(String Command, String Typed)

            => Command.StartsWith(Typed, StringComparison.OrdinalIgnoreCase)
                   ? [ SuggestionResponse.CommandCompleted(Command) ]
                   : [];

        /// <summary>
        /// Tab on a word after the command: every candidate that begins with
        /// what was typed, completed where it is the only one that is whole.
        /// </summary>
        /// <param name="Before">The words before this one, the command among them.</param>
        /// <param name="Typed">What was typed of this one.</param>
        /// <param name="Candidates">What it could be.</param>
        public static IEnumerable<SuggestionResponse> CompleteWord(String               Before,
                                                                   String               Typed,
                                                                   IEnumerable<String>  Candidates)

            => Candidates.Where (candidate => candidate.StartsWith(Typed, StringComparison.OrdinalIgnoreCase)).
                          Select(candidate => candidate.Equals(Typed, StringComparison.OrdinalIgnoreCase)
                                                  ? SuggestionResponse.ParameterCompleted($"{Before} {candidate}")
                                                  : SuggestionResponse.ParameterPrefix   ($"{Before} {candidate}"));

        /// <summary>
        /// Tab right after a whole command: what can come next. The command line
        /// keeps no empty word at its end, so "queue " arrives as "queue", and a
        /// Tab that answered with the command it already was would never show
        /// the list it is there for.
        /// </summary>
        /// <param name="Command">The command.</param>
        /// <param name="Next">What can come after it.</param>
        public static IEnumerable<SuggestionResponse> CompleteNext(String               Command,
                                                                   IEnumerable<String>  Next)
        {

            var next = Next.Select(word => SuggestionResponse.ParameterPrefix($"{Command} {word}")).ToArray();

            return next.Length > 0
                       ? next
                       : [ SuggestionResponse.CommandCompleted(Command) ];

        }

        #endregion

    }

}
