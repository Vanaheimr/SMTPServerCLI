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
using System.Net.Sockets;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SMTP.CLI
{

    /// <summary>
    /// One SMTP server, with a prompt, until 'quit', Ctrl+C or SIGTERM.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every default lives in <see cref="Configuration"/>; a switch changes one
    /// for this start and is written nowhere. The crypto material - the TLS
    /// certificate and the DKIM key pair - is generated on the first start into
    /// the repository's config/ folder, so a fresh clone runs with a single
    /// "dotnet run".
    /// </para>
    /// <para>
    /// What the server is and does lives in Hermod. What is here is the
    /// wiring (<see cref="SMTPServerInstance"/>), the words for it - the
    /// switches, the banner - and the commands the prompt understands, one
    /// file each in CLI/CLICommands.
    /// </para>
    /// <para>
    /// Exit codes: 0 after a stop that was asked for, 1 when the server could
    /// not start, 2 when the switches made no sense.
    /// </para>
    /// </remarks>
    public static class Program
    {

        #region Main(Arguments)

        public static async Task<Int32> Main(String[] Arguments)
        {

            Console.OutputEncoding = System.Text.Encoding.UTF8;

            #region Switches

            var settings = new ServerSettings();

            if (Parse(Arguments, settings) is Int32 exitCode)
                return exitCode;

            #endregion

            #region The server

            var logger = new CLILogger(settings.ConsoleLogLevel);

            await using var server = new SMTPServerInstance(settings, logger);

            try
            {
                await server.Start();
            }
            catch (Exception e)
            {

                Console.Error.WriteLine();

                Usage.Say(Console.Error, e switch {

                    SocketException { SocketErrorCode: SocketError.AddressAlreadyInUse }
                        => $"The SMTP server could not start: one of its ports - {settings.Port}, {settings.SubmissionPort}, " +
                           $"{settings.ImplicitTlsPort} - is in use already. Another instance? --port, --submission-port " +
                            "and --implicit-tls-port choose others.",

                    SocketException { SocketErrorCode: SocketError.AccessDenied }
                        => $"The SMTP server could not start: it may not bind one of its ports - {settings.Port}, " +
                           $"{settings.SubmissionPort}, {settings.ImplicitTlsPort}. Ports below 1024 need privileges: " +
                            "CAP_NET_BIND_SERVICE on Linux, or a port-forward.",

                    System.Security.Cryptography.CryptographicException
                        => $"The SMTP server could not start: its certificate could not be read - {e.Message} " +
                            "Is --certificate-password (or Configuration.CertificatePassword) the file's?",

                    _   => $"The SMTP server could not start: {e.Message}"

                });

                if (settings.ConsoleLogLevel == LogLevel.Debug)
                    Console.Error.WriteLine(e);

                return 1;

            }

            #endregion

            #region What somebody who just started this needs to know

            foreach (var line in Banner.Lines(server))
                Console.WriteLine(line);

            #endregion

            #region The command line, until 'quit', Ctrl+C or SIGTERM

            await new SMTPCLI(server).RunUntilStopped();

            logger.Log(LogLevel.Info, "Shutdown requested...");

            #endregion

            return 0;

        }

        #endregion


        #region (private static) Parse(Arguments, Settings)

        /// <summary>
        /// What the switches said, into the given settings. Null to go on, or the
        /// exit code to end with - after -h or --version, or a switch that made
        /// no sense.
        /// </summary>
        private static Int32? Parse(String[]        Arguments,
                                    ServerSettings  Settings)
        {

            List<String>? localDomains = null;

            for (var i = 0; i < Arguments.Length; i++)
            {

                var flag = Arguments[i];

                switch (flag)
                {

                    case "-h":
                    case "--help":
                    case "-?":
                    case "/?":
                        foreach (var line in Usage.Lines())
                            Console.WriteLine(line);
                        return 0;

                    case "--version":
                        foreach (var line in SMTPServerInstance.BuiltFrom())
                            Console.WriteLine(line);
                        return 0;

                    #region Who it is

                    case "--hostname":
                        if (Value(Arguments, ref i, flag, "a hostname") is not String hostname)
                            return 2;
                        Settings.Hostname = hostname.TrimEnd('.').ToLowerInvariant();
                        break;

                    case "--local-domain":
                        if (Value(Arguments, ref i, flag, "a domain") is not String domain)
                            return 2;
                        (localDomains ??= []).Add(domain);
                        break;

                    #endregion

                    #region Where it listens

                    case "--port":
                        if (Port(Arguments, ref i, flag) is not UInt16 port)
                            return 2;
                        Settings.Port = port;
                        break;

                    case "--submission-port":
                        if (Port(Arguments, ref i, flag) is not UInt16 submissionPort)
                            return 2;
                        Settings.SubmissionPort = submissionPort;
                        break;

                    case "--implicit-tls-port":
                        if (Port(Arguments, ref i, flag) is not UInt16 implicitTlsPort)
                            return 2;
                        Settings.ImplicitTlsPort = implicitTlsPort;
                        break;

                    #endregion

                    #region TLS

                    case "--certificate":
                        if (Value(Arguments, ref i, flag, "a PKCS#12 file") is not String certificate)
                            return 2;
                        if (!File.Exists(certificate))
                        {
                            Usage.Say(Console.Error, $"{flag}: there is no file '{certificate}'.");
                            return 2;
                        }
                        Settings.CertificatePath = certificate;
                        break;

                    case "--certificate-password":
                        if (Value(Arguments, ref i, flag, "a password") is not String certificatePassword)
                            return 2;
                        Settings.CertificatePassword = certificatePassword;
                        break;

                    case "--require-starttls":
                        Settings.RequireStartTls = true;
                        break;

                    #endregion

                    #region DKIM

                    case "--dkim-domain":
                        if (Value(Arguments, ref i, flag, "a domain") is not String dkimDomain)
                            return 2;
                        Settings.DkimDomain = dkimDomain.TrimEnd('.').ToLowerInvariant();
                        break;

                    case "--dkim-selector":
                        if (Value(Arguments, ref i, flag, "a selector") is not String dkimSelector)
                            return 2;
                        if (dkimSelector.Any(c => !Char.IsAsciiLetterOrDigit(c) && c != '-' && c != '.'))
                        {
                            Usage.Say(Console.Error, $"{flag}: '{dkimSelector}' cannot be a selector - letters, digits, '-' and '.' only.");
                            return 2;
                        }
                        Settings.DkimSelector = dkimSelector;
                        break;

                    #endregion

                    #region Outgoing mail

                    case "--smarthost":
                        if (Value(Arguments, ref i, flag, "host[:port]") is not String smarthost)
                            return 2;
                        var colon = smarthost.LastIndexOf(':');
                        if (colon > 0 && !smarthost.EndsWith(']'))
                        {
                            if (!UInt16.TryParse(smarthost[(colon + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out var smarthostPort) ||
                                smarthostPort == 0)
                            {
                                Usage.Say(Console.Error, $"{flag}: '{smarthost[(colon + 1)..]}' is no port.");
                                return 2;
                            }
                            Settings.SmartHostPort = smarthostPort;
                            smarthost = smarthost[..colon];
                        }
                        Settings.SmartHost = smarthost.Trim('[', ']');
                        break;

                    case "--smarthost-user":
                        if (Value(Arguments, ref i, flag, "an account") is not String smarthostUser)
                            return 2;
                        Settings.SmartHostUsername = smarthostUser;
                        break;

                    case "--smarthost-password":
                        if (Value(Arguments, ref i, flag, "a password") is not String smarthostPassword)
                            return 2;
                        Settings.SmartHostPassword = smarthostPassword;
                        break;

                    #endregion

                    #region Files

                    case "--config":
                        if (Value(Arguments, ref i, flag, "a directory") is not String configDirectory)
                            return 2;
                        Settings.ConfigDirectory = Path.GetFullPath(configDirectory);
                        break;

                    case "--mailstore":
                        if (Value(Arguments, ref i, flag, "a directory") is not String mailStore)
                            return 2;
                        Settings.MailStoragePath = Path.GetFullPath(mailStore);
                        break;

                    #endregion

                    #region The console

                    case "--verbose":
                        Settings.ConsoleLogLevel = LogLevel.Debug;
                        break;

                    case "--quiet":
                        Settings.ConsoleLogLevel = LogLevel.Warning;
                        break;

                    case "--log-level":
                        if (Value(Arguments, ref i, flag, String.Join(", ", CLILogger.Levels)) is not String levelText)
                            return 2;
                        if (!CLILogger.TryParse(levelText, out var level))
                        {
                            Usage.Say(Console.Error, $"{flag}: '{levelText}' is no level. One of {String.Join(", ", CLILogger.Levels)}.");
                            return 2;
                        }
                        Settings.ConsoleLogLevel = level;
                        break;

                    #endregion

                    default:
                        Usage.Say(Console.Error, $"Unknown switch '{flag}'. -h lists them.");
                        return 2;

                }

            }

            if (localDomains is not null)
                Settings.LocalDomains = [.. localDomains];

            if (Settings.SmartHostUsername is not null ^ Settings.SmartHostPassword is not null)
            {
                Usage.Say(Console.Error, "--smarthost-user and --smarthost-password go together: an account without a password, " +
                                         "or a password without an account, authenticates nobody.");
                return 2;
            }

            var ports = new[] { Settings.Port, Settings.SubmissionPort, Settings.ImplicitTlsPort };

            if (ports.Distinct().Count() < ports.Length)
            {
                Usage.Say(Console.Error, $"The MTA, submission and implicit-TLS ports have to differ: {String.Join(", ", ports)}.");
                return 2;
            }

            return null;

        }

        #endregion

        #region (private static) Value(Arguments, ref Index, Flag, What)

        /// <summary>
        /// The word after a switch, or null after saying that there is none.
        /// </summary>
        private static String? Value(String[]   Arguments,
                                     ref Int32  Index,
                                     String     Flag,
                                     String     What)
        {

            if (Index + 1 < Arguments.Length && !Arguments[Index + 1].StartsWith("--"))
                return Arguments[++Index];

            Usage.Say(Console.Error, $"{Flag} needs {What} after it.");
            return null;

        }

        #endregion

        #region (private static) Port(Arguments, ref Index, Flag)

        /// <summary>
        /// A TCP port after a switch, or null after saying why there is none.
        /// </summary>
        private static UInt16? Port(String[]   Arguments,
                                    ref Int32  Index,
                                    String     Flag)
        {

            if (Value(Arguments, ref Index, Flag, "a port") is not String text)
                return null;

            if (UInt16.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var port) && port > 0)
                return port;

            Usage.Say(Console.Error, $"{Flag}: '{text}' is no TCP port - 1 to 65535.");
            return null;

        }

        #endregion

    }

}
