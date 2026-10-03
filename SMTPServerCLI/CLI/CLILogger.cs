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

using System.Collections.Concurrent;

using org.GraphDefined.Vanaheimr.Illias;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SMTP.CLI
{

    /// <summary>
    /// The server's log on the console, from a level up, and sharing the
    /// screen with the command line.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Hermod's own ConsoleLogger writes straight to the console. With a
    /// prompt on it that is half an entry in the middle of a half-typed
    /// command, and every session the server accepts writes several. So this
    /// one asks whoever owns the screen to write for it - the command line,
    /// once it is up, which takes the command off the screen, writes the entry
    /// whole and puts the command back where it was.
    /// </para>
    /// <para>
    /// One entry is one line: a message with line breaks of its own would
    /// otherwise continue on lines with no time and no level.
    /// </para>
    /// <para>
    /// Every command line over SSH gets the log as well, as a listener with a
    /// level of its own - see <see cref="Listen"/>.
    /// </para>
    /// </remarks>
    /// <param name="MinimumLevel">From which level up to write; null for nothing.</param>
    public sealed class CLILogger(LogLevel? MinimumLevel) : ILogger
    {

        #region Data

        private readonly  Lock                                     padlock    = new();
        private           Action<Action>?                          shareConsole;
        private readonly  ConcurrentDictionary<LogListener, Byte>  listeners  = new();

        #endregion

        #region Properties

        /// <summary>
        /// From which level up the log is written; null for nothing.
        /// </summary>
        public LogLevel?  MinimumLevel    { get; set; } = MinimumLevel;

        #endregion


        #region ShareConsoleWith(Write)

        /// <summary>
        /// Write every entry through the given writer from now on - the command
        /// line's WriteBlock while there is one - or by itself again, with a
        /// lock of its own, given null.
        /// </summary>
        /// <param name="Write">What writes a block on the console for the log.</param>
        public void ShareConsoleWith(Action<Action>? Write)

            => shareConsole = Write;

        #endregion

        #region Listen(MinimumLevel, Write)

        /// <summary>
        /// Hand every entry from the given level up to the given writer as well,
        /// until the listener that comes back is disposed of.
        /// </summary>
        /// <param name="MinimumLevel">From which level up; null for nothing, until it is changed.</param>
        /// <param name="Write">What writes an entry: its level, its line and the colour it is shown in. It must not block.</param>
        public LogListener Listen(LogLevel?                               MinimumLevel,
                                  Action<LogLevel, String, ConsoleColor?>  Write)
        {

            var listener = new LogListener(MinimumLevel, Write, this);

            listeners.TryAdd(listener, 0);

            return listener;

        }

        internal void Forget(LogListener Listener)

            => listeners.TryRemove(Listener, out _);

        #endregion

        #region Log(Level, Message)

        public void Log(LogLevel  Level,
                        String    Message)
        {

            var toConsole  = MinimumLevel is LogLevel minimum && Level >= minimum;
            var toAnybody  = toConsole || listeners.Keys.Any(listener => listener.MinimumLevel is LogLevel level && Level >= level);

            if (!toAnybody)
                return;

            var line   = $"{Timestamp.Now.ToLocalTime():HH:mm:ss.fff} {Prefix(Level)} {Message.ReplaceLineEndings(" ")}";
            var color  = Color(Level);

            if (toConsole)
                (shareConsole ?? WriteLocked)(() => {

                    var previous = Console.ForegroundColor;

                    if (color is ConsoleColor shown)
                        Console.ForegroundColor = shown;

                    Console.WriteLine(line);

                    Console.ForegroundColor = previous;

                });

            foreach (var listener in listeners.Keys)
            {

                if (listener.MinimumLevel is not LogLevel level || Level < level)
                    continue;

                try
                {
                    listener.Write(Level, line, color);
                }
                catch
                {
                    // A session that is going away; the log goes on without it.
                }

            }

        }

        #endregion


        #region (static) Name(Level) / Prefix(Level)

        /// <summary>
        /// A level as it is typed: debug, info, warning, error - or off.
        /// </summary>
        public static String Name(LogLevel? Level)

            => Level?.ToString().ToLowerInvariant() ?? "off";

        private static ConsoleColor? Color(LogLevel Level)

            => Level switch {
                   LogLevel.Debug    => ConsoleColor.DarkGray,
                   LogLevel.Warning  => ConsoleColor.Yellow,
                   LogLevel.Error    => ConsoleColor.Red,
                   _                 => null
               };

        private static String Prefix(LogLevel Level)

            => Level switch {
                   LogLevel.Debug    => "[DBG]",
                   LogLevel.Info     => "[INF]",
                   LogLevel.Warning  => "[WRN]",
                   LogLevel.Error    => "[ERR]",
                   _                 => "[???]"
               };

        #endregion

        #region (static) TryParse(Text, out Level)

        /// <summary>
        /// A level from what was typed: debug, info, warning, error or off.
        /// </summary>
        public static Boolean TryParse(String Text, out LogLevel? Level)
        {

            Level = null;

            switch (Text.ToLowerInvariant())
            {
                case "debug":    Level = LogLevel.Debug;    return true;
                case "info":     Level = LogLevel.Info;     return true;
                case "warning":  Level = LogLevel.Warning;  return true;
                case "error":    Level = LogLevel.Error;    return true;
                case "off":                                 return true;
                default:                                    return false;
            }

        }

        /// <summary>
        /// Every level that can be typed, from the most to the least.
        /// </summary>
        public static readonly String[] Levels = [ "debug", "info", "warning", "error", "off" ];

        #endregion

        #region (private) WriteLocked(Write)

        private void WriteLocked(Action Write)
        {
            lock (padlock)
            {
                Write();
            }
        }

        #endregion

    }

}


namespace org.GraphDefined.Vanaheimr.Hermod.SMTP.CLI
{

    /// <summary>
    /// One more place the log is written to - a command line over SSH - with
    /// a level of its own, until it is disposed of.
    /// </summary>
    public sealed class LogListener : IDisposable
    {

        private readonly CLILogger logger;

        /// <summary>
        /// From which level up the log is written here; null for nothing.
        /// </summary>
        public LogLevel?                                MinimumLevel    { get; set; }

        /// <summary>
        /// What writes an entry.
        /// </summary>
        public Action<LogLevel, String, ConsoleColor?>  Write           { get; }

        internal LogListener(LogLevel?                                MinimumLevel,
                             Action<LogLevel, String, ConsoleColor?>  Write,
                             CLILogger                                Logger)
        {
            this.MinimumLevel  = MinimumLevel;
            this.Write         = Write;
            this.logger        = Logger;
        }

        /// <summary>
        /// Stop writing the log here.
        /// </summary>
        public void Dispose()

            => logger.Forget(this);

    }

}
