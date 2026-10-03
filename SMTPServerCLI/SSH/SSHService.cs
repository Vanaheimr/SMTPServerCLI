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

using org.GraphDefined.Vanaheimr.CLI;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Server;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SMTP.CLI
{

    /// <summary>
    /// The server's command line over SSH: what somebody signed in with PuTTY
    /// or ssh gets, and nothing else - no shell of the machine, no files, no
    /// tunnels.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Hermod's SSH server, on the loopback unless --ssh-any says every
    /// address. A server under systemd has no console to type at, and this is
    /// how its command line is reached anyway: ssh -p 22525 admin@localhost on
    /// the machine, or through a tunnel from anywhere else.
    /// </para>
    /// <para>
    /// Whoever signs in is an account of <see cref="SSHAccounts"/>, with one of
    /// the keys in its file. With no keys anywhere, the server listens and lets
    /// nobody in.
    /// </para>
    /// <para>
    /// The host key is made at the first start that serves SSH and kept in the
    /// configuration folder beside the TLS certificate and the DKIM keys. One
    /// that is there and cannot be read stops the start: a server with a new
    /// key is, to every client that knew the old one, another machine.
    /// </para>
    /// </remarks>
    public sealed class SSHService : IAsyncDisposable
    {

        #region Data

        /// <summary>
        /// What the host key's file is called, in the ssh folder of the configuration.
        /// </summary>
        public const String HostKeyFileName = "ssh_host_ed25519_key";

        private readonly  SMTPServerInstance                     smtp;
        private readonly  ConcurrentDictionary<String, Session>  sessions  = new();
        private           SshServer?                             sshServer;

        #endregion

        #region Properties

        /// <summary>The accounts and their keys.</summary>
        public SSHAccounts  Accounts       { get; }

        /// <summary>Where the host key is kept.</summary>
        public String       HostKeyPath    { get; }

        /// <summary>The host key's type and SHA-256 fingerprint, as PuTTY shows them the first time; null until started.</summary>
        public String?      HostKey        { get; private set; }

        /// <summary>Where the command line is reached: ssh://127.0.0.1:22525.</summary>
        public String       URL
            => $"ssh://{(smtp.Settings.SSHAnyAddress ? "0.0.0.0" : "127.0.0.1")}:{smtp.Settings.SSHPort}";

        /// <summary>The sessions open now, the oldest first.</summary>
        public IReadOnlyList<Session> Sessions
            => [.. sessions.Values.OrderBy(session => session.Since)];

        #endregion

        #region (record) Session

        /// <summary>
        /// One session: who, from where, with which key, since when.
        /// </summary>
        public sealed record Session(String          Id,
                                     String          Account,
                                     String          From,
                                     String?         Key,
                                     DateTimeOffset  Since);

        #endregion

        #region Constructor(s)

        /// <summary>
        /// The command line over SSH of the given server, not yet started.
        /// </summary>
        public SSHService(SMTPServerInstance SMTP)
        {

            this.smtp         = SMTP;
            this.Accounts     = new SSHAccounts(Path.Combine(SMTP.Settings.ConfigDirectory, "ssh", "authorized"));
            this.HostKeyPath  = Path.Combine(SMTP.Settings.ConfigDirectory, "ssh", HostKeyFileName);

        }

        #endregion


        #region Start()

        /// <summary>
        /// Start the SSH server, with the host key made now where there is none yet.
        /// </summary>
        public async Task Start()
        {

            var hostKey  = await LoadOrCreateHostKey();

            HostKey      = $"{hostKey.AlgorithmNames[0]} {SshFingerprint.Sha256(hostKey.PublicKeyBlob)}";

            var server   = new SshServer(new SshServerOptions {
                               HostKeys             = [ hostKey ],
                               Authenticator        = new Authenticator(Accounts),
                               ShellHandler         = ServeShellAsync,
                               AuditSink            = new DelegateAuditSink(Audited),
                               ShutdownGracePeriod  = TimeSpan.FromSeconds(3),
                               Limits               = new SshServerLimits {
                                                          LoginGraceTime       = TimeSpan.FromSeconds(30),
                                                          MaxSessions          = 4,
                                                          ClientAliveInterval  = TimeSpan.FromSeconds(60),
                                                          ClientAliveCountMax  = 3
                                                      }
                           });

            var port     = IPPort.Parse(smtp.Settings.SSHPort);

            try
            {
                await server.StartAsync(smtp.Settings.SSHAnyAddress
                                            ? IPSocket.AnyV4(port)
                                            : IPSocket.LocalhostV4(port));
            }
            catch
            {
                await server.DisposeAsync();
                throw;
            }

            sshServer = server;

            var accounts = Accounts.AccountsWithKeys();

            smtp.Logger.Log(LogLevel.Info,
                            $"The command line is served over SSH on {URL}, host key {HostKey}; " +
                            (accounts.Count == 0
                                 ? "no account has a key yet, so nobody can sign in."
                                 : $"{accounts.Count} account(s) can sign in with a key: {String.Join(", ", accounts)}."));

        }

        #endregion

        #region (private) LoadOrCreateHostKey()

        private async Task<ISshHostKey> LoadOrCreateHostKey()
        {

            if (File.Exists(HostKeyPath))
            {
                try
                {
                    return SshKeyGenerator.LoadPrivateKey(await File.ReadAllTextAsync(HostKeyPath)).Key;
                }
                catch (Exception problem)
                {
                    throw new InvalidOperationException(
                              $"The SSH host key in '{HostKeyPath}' could not be read: {problem.Message} " +
                               "Repair it, or remove it for a new one - which every client that knows this server will take for another machine.",
                              problem
                          );
                }
            }

            Directory.CreateDirectory(Path.GetDirectoryName(HostKeyPath)!);

            var key = SshHostKey.GenerateEd25519();

            await SshKeyGenerator.WriteKeyPairAsync(key, HostKeyPath, Comment: $"smtp@{Environment.MachineName}");

            smtp.Generated.Add($"an SSH host key, {key.AlgorithmNames[0]} {SshFingerprint.Sha256(key.PublicKeyBlob)}: {HostKeyPath}");

            return key;

        }

        #endregion

        #region (private) ServeShellAsync(Context, CancellationToken)

        /// <summary>
        /// What somebody signed in over SSH gets: the server's command line, on
        /// their terminal, until they leave, close their window, or the server
        /// stops. 'quit', 'exit' and Ctrl+D leave the session, and the server
        /// keeps running.
        /// </summary>
        private async ValueTask<Int32> ServeShellAsync(SshShellContext    Context,
                                                       CancellationToken  CancellationToken)
        {

            var session  = Context.Session;
            var from     = session.Peer?.ToString() ?? "somewhere";
            var since    = DateTimeOffset.UtcNow;

            if (Context.Size is not SshWindowSize size)
            {
                await Context.WriteAsync("This is the command line of an SMTP server, and it wants a terminal to be typed at: " +
                                         "connect with ssh -t, or with PuTTY.\r\n",
                                         CancellationToken);
                return 1;
            }

            await using var terminal = new VT100Terminal((bytes, ct) => Context.WriteAsync(bytes, ct), Width: Columns(size));

            Context.WindowChanged += changed => terminal.Width = Columns(changed);
            Context.Signalled     += signal  => { if (signal is "INT" or "TERM") terminal.Interrupt(); };

            using var cli = new SMTPCLI(smtp, terminal, session.Username, from);

            // The log, from where the console shows it, written around the line being typed.
            cli.SessionLog = smtp.Logger.Listen(smtp.Logger.MinimumLevel ?? LogLevel.Info,
                                                (level, line, color) => cli.WriteBlock(t => t.WriteLine(line, color)));

            sessions[session.ConnectionId] = new Session(session.ConnectionId,
                                                         session.Username,
                                                         from,
                                                         session.PublicKeyFingerprint,
                                                         since);

            var reading = terminal.ReadFromAsync(Context.Input, CancellationToken);

            try
            {

                terminal.WriteLine($"SMTP server {smtp.Settings.Hostname}: signed in as '{session.Username}' from {from}.");
                terminal.WriteLine("Type 'help' for what can be typed here, Tab to complete; 'quit' or Ctrl+D leaves, and the server keeps running.");
                terminal.WriteLine();

                await cli.Run(CancellationToken);

                if (Context.Stopping.IsCancellationRequested && !Context.Closed.IsCancellationRequested)
                {
                    terminal.WriteLine();
                    terminal.WriteLine("The SMTP server is shutting down.");
                }

                if (!Context.Closed.IsCancellationRequested)
                    await terminal.FlushAsync().WaitAsync(TimeSpan.FromSeconds(2));

            }
            catch (Exception) when (Context.Closed.IsCancellationRequested || CancellationToken.IsCancellationRequested)
            {
                // The window was closed in the middle of something.
            }
            catch (IOException)
            {
                // The far end stopped taking what it was sent.
            }
            catch (TimeoutException)
            {
                // The goodbye did not get through in time; the session ends regardless.
            }
            finally
            {

                cli.SessionLog.Dispose();
                sessions.TryRemove(session.ConnectionId, out _);

                smtp.Logger.Log(LogLevel.Info,
                                $"'{session.Username}' left the command line over SSH after {StatusCommand.Describe(DateTimeOffset.UtcNow - since)}" +
                                (Context.Stopping.IsCancellationRequested ? ", as the server stopped." : "."));

            }

            _ = reading.ContinueWith(task => _ = task.Exception, TaskContinuationOptions.OnlyOnFaulted);

            return 0;

        }

        #endregion

        #region (private static) Columns(Size)

        /// <summary>
        /// How wide the terminal is: what the client said, and 80 where it said
        /// 0 - which OpenSSH does when its own output is not a terminal.
        /// </summary>
        private static Int32 Columns(SshWindowSize Size)

            => Size.Columns == 0
                   ? 80
                   : (Int32) Math.Min(Size.Columns, 1000);

        #endregion

        #region (private) Audited(Event)

        /// <summary>
        /// What the SSH server says happened, in the server's log: who signed in
        /// and from where, who could not, which limit was reached, what was
        /// refused - and the rest for the debug log.
        /// </summary>
        private void Audited(SshAuditEvent Event)
        {

            var from = Event.PeerEndpoint is not null ? $" from {Event.PeerEndpoint}" : "";

            switch (Event)
            {

                case AuthenticationSucceededEvent signedIn:
                    smtp.Logger.Log(LogLevel.Info, $"'{signedIn.Username}' signed in to the command line over SSH{from} with {String.Join(" and ", signedIn.Methods)}.");
                    break;

                case AuthMethodFailedEvent failed:
                    smtp.Logger.Log(LogLevel.Info, $"Somebody{from} could not sign in over SSH as '{failed.Username}' with {failed.Method}.");
                    break;

                case AuthenticationFailedEvent gaveUp:
                    smtp.Logger.Log(LogLevel.Warning, $"Somebody{from} failed to sign in over SSH as '{gaveUp.Username}' {gaveUp.FailedAttempts} time(s), and was disconnected.");
                    break;

                case LimitExceededEvent limit:
                    smtp.Logger.Log(LogLevel.Warning, $"The SSH server refused{from}: {limit.Limit} - {limit.Detail}.");
                    break;

                case PolicyDeniedEvent denied:
                    smtp.Logger.Log(LogLevel.Info, $"Refused over SSH{from}: {denied.PolicyType}{(denied.Target.Length > 0 ? $" '{denied.Target}'" : "")} - only the command line is served.");
                    break;

                default:
                    smtp.Logger.Log(LogLevel.Debug, $"SSH{from}: {Event.EventType}.");
                    break;

            }

        }

        #endregion


        #region DisposeAsync()

        /// <summary>
        /// Stop the SSH server: every session is told and given a moment to say
        /// goodbye, then its connection ends.
        /// </summary>
        public async ValueTask DisposeAsync()
        {

            var server = Interlocked.Exchange(ref sshServer, null);

            if (server is not null)
                await server.DisposeAsync();

        }

        #endregion


        #region (class) Authenticator

        /// <summary>
        /// An account of <see cref="SSHAccounts"/>, under its name, with one of
        /// its keys - asked again at every sign-in, nothing remembered between two.
        /// </summary>
        private sealed class Authenticator(SSHAccounts Accounts) : ISshUserAuthenticator
        {

            public IReadOnlyList<String> OfferedMethods { get; } = [ "publickey" ];

            public ValueTask<Boolean> AuthorizePublicKeyAsync(SshPublicKeyAuthRequest  Request,
                                                              CancellationToken        CancellationToken = default)

                => ValueTask.FromResult(Accounts.Find(Request.Username, Request.PublicKeyBlob) is not null);

            public ValueTask<SshSessionRestrictions> GetRestrictionsAsync(SshPublicKeyAuthRequest  Request,
                                                                          CancellationToken        CancellationToken = default)

                => ValueTask.FromResult(Accounts.Find(Request.Username, Request.PublicKeyBlob)?.Restrictions
                                            ?? SshSessionRestrictions.None);

        }

        #endregion

    }

}
