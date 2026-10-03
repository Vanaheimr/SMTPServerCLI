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

using System.Net;
using System.Text;
using System.Net.Sockets;

using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SMTP.CLI.Tests
{

    /// <summary>
    /// The server started as Program starts it - in a folder of its own, on
    /// free ports, without a word on the console - and spoken to as a mail
    /// client, an administrator at its prompt and one over SSH would.
    /// </summary>
    /// <remarks>
    /// Nothing here asks a name server elsewhere for anything that decides a
    /// test: the mail goes to a local domain, whose SPF, DKIM and DMARC the
    /// server records whatever they come to.
    /// </remarks>
    [TestFixture]
    public class ServerTests
    {

        #region Data

        private String              directory  = "";
        private SMTPServerInstance  server     = null!;
        private ISshHostKey         userKey    = null!;

        #endregion

        #region SetUp() / TearDown()

        [SetUp]
        public async Task SetUp()
        {

            directory  = Path.Combine(Path.GetTempPath(), "SMTPServerCLITests", Guid.NewGuid().ToString("N"));
            userKey    = SshHostKey.GenerateEd25519();

            Directory.CreateDirectory(directory);

            var keyFile = Path.Combine(directory, "alice.pub");
            File.WriteAllText(keyFile, SshPublicKey.FromHostKey(userKey, "alice").ToAuthorizedKeyLine());

            var settings = new ServerSettings {
                               Hostname         = "mail.example.org",
                               LocalDomains     = [ "example.org" ],
                               Port             = FreePort(),
                               SubmissionPort   = FreePort(),
                               ImplicitTlsPort  = FreePort(),
                               SSHPort          = FreePort(),
                               ConfigDirectory  = Path.Combine(directory, "config"),
                               MailStoragePath  = Path.Combine(directory, "mailstore"),
                               ConsoleLogLevel  = null
                           };

            settings.AuthorizeSSHKeys.Add(("alice", keyFile));

            server = new SMTPServerInstance(settings, new CLILogger(null));

            await server.Start();

        }

        [TearDown]
        public async Task TearDown()
        {

            await server.DisposeAsync();

            try { Directory.Delete(directory, true); } catch { }

        }

        #endregion


        #region TheFirstStartGeneratesWhatTheServerNeeds()

        /// <summary>
        /// Certificate, DKIM key, SSH host key and one account with a password
        /// shown once - and nothing of Hermod's demo accounts.
        /// </summary>
        [Test]
        public void TheFirstStartGeneratesWhatTheServerNeeds()
        {

            var config = server.Settings.ConfigDirectory;

            Assert.Multiple(() => {
                Assert.That(File.Exists(Path.Combine(config, "server.pfx")),                   Is.True);
                Assert.That(File.Exists(Path.Combine(config, "dkim_default.private.pem")),     Is.True);
                Assert.That(File.Exists(Path.Combine(config, "ssh", "ssh_host_ed25519_key")),  Is.True);
                Assert.That(File.Exists(Path.Combine(config, "ssh", "authorized", "alice")),   Is.True);
                Assert.That(server.FirstAccountPassword,                                        Is.Not.Null);
                Assert.That(server.Users.Read().Select(account => account.Name),                Is.EqualTo(new[] { "admin" }));
                Assert.That(server.IsRunning,                                                   Is.True);
                Assert.That(Banner.Lines(server),                                               Has.Some.Contains(server.FirstAccountPassword));
                Assert.That(Banner.Lines(server, AtStart: false),                               Has.None.Contains(server.FirstAccountPassword));
            });

        }

        #endregion

        #region MailForALocalDomainArrivesInTheMailbox()

        /// <summary>
        /// A message for a local recipient, over the MTA port, is in the mailbox
        /// - as 'mailbox' lists it and 'mailbox show' prints it.
        /// </summary>
        [Test]
        [CancelAfter(30_000)]
        public async Task MailForALocalDomainArrivesInTheMailbox(CancellationToken CancellationToken)
        {

            var replies = await Deliver("bob@example.org", "Hello from the tests", CancellationToken);

            Assert.That(replies.Last(r => r.StartsWith("250 2.0.0")), Is.Not.Null, String.Join(" | ", replies));

            using var cli = new SMTPCLI(server);

            var listed  = await cli.Execute("mailbox", CancellationToken);
            var name    = MailboxCommand.Messages(server).Select(file => Path.GetFileNameWithoutExtension(file)!).Single();
            var shown   = await cli.Execute($"mailbox show {name[..15]}", CancellationToken);

            Assert.Multiple(() => {
                Assert.That(listed, Has.Some.Contains("alice@client.test -> bob@example.org: Hello from the tests"));
                Assert.That(shown,  Has.Some.EqualTo("Subject: Hello from the tests"));
                Assert.That(shown,  Has.Some.StartsWith("Authentication-Results: mail.example.org"));
            });

        }

        #endregion

        #region MailForElsewhereNeedsAnAccount()

        /// <summary>
        /// Relay without authentication is refused: no open relay.
        /// </summary>
        [Test]
        [CancelAfter(30_000)]
        public async Task MailForElsewhereNeedsAnAccount(CancellationToken CancellationToken)
        {

            var replies = await Deliver("someone@example.com", "Relay me", CancellationToken);

            Assert.That(replies, Has.Some.Matches<String>(reply => reply!.StartsWith("530") || reply.StartsWith("550") || reply.StartsWith("554")),
                        String.Join(" | ", replies));
            Assert.That(MailboxCommand.Messages(server), Is.Empty);

        }

        #endregion

        #region TheCommandsAnswerAndComplete()

        /// <summary>
        /// The commands answer, change what they say they change, and Tab
        /// completes them and their words.
        /// </summary>
        [Test]
        public async Task TheCommandsAnswerAndComplete()
        {

            using var cli = new SMTPCLI(server);

            var help     = await cli.Execute("help");
            var status   = await cli.Execute("status");
            var added    = await cli.Execute("user add bob");
            var queue    = await cli.Execute("queue");
            var dns      = await cli.Execute("dns");
            var log      = await cli.Execute("log warning");
            var who      = await cli.Execute("who");

            var tabQ     = (await cli.Suggest("qu")).        Select(s => s.Suggestion);
            var tabUser  = (await cli.Suggest("user passwd")).Select(s => s.Suggestion);
            var tabLog   = (await cli.Suggest("log d")).     Select(s => s.Suggestion);

            Assert.Multiple(() => {
                Assert.That(help,                                Has.Some.StartsWith("queue ["));
                Assert.That(status,                              Has.Some.Contains("accepting"));
                Assert.That(added.Single(),                      Does.StartWith("'bob' has the password"));
                Assert.That(server.Users.Read().Select(a => a.Name), Is.EquivalentTo(new[] { "admin", "bob" }));
                Assert.That(queue.Single(),                      Does.StartWith("Nothing waits to go out."));
                Assert.That(dns,                                 Has.Some.StartsWith("example.org.  IN MX   10 mail.example.org."));
                Assert.That(dns,                                 Has.Some.StartsWith("default._domainkey.mail.example.org.  IN TXT  ( \"v=DKIM1; k=rsa; p="));
                Assert.That(log.Single(),                        Is.EqualTo("The console shows the log from warning up now."));
                Assert.That(server.Logger.MinimumLevel,          Is.EqualTo(LogLevel.Warning));
                Assert.That(who.Single(),                        Does.StartWith("Nobody is signed in over SSH"));
                Assert.That(tabQ,                                Is.EquivalentTo(new[] { "queue", "quit" }));
                Assert.That(tabUser,                             Is.EquivalentTo(new[] { "user passwd admin", "user passwd bob" }));
                Assert.That(tabLog,                              Is.EquivalentTo(new[] { "log debug" }));
            });

        }

        #endregion

        #region TheCommandLineIsServedOverSSH()

        /// <summary>
        /// An account with an authorized key signs in, gets the command line,
        /// is seen by 'who' as itself, and leaves with 'quit' - while the server
        /// keeps running.
        /// </summary>
        [Test]
        [CancelAfter(30_000)]
        public async Task TheCommandLineIsServedOverSSH(CancellationToken CancellationToken)
        {

            await using var client  = await Connect("alice", userKey, CancellationToken);
            await using var shell   = await client.OpenShellAsync(new SshPty("xterm", new SshWindowSize(120, 30), new Dictionary<Byte, UInt32>()),
                                                                  CancellationToken: CancellationToken);

            var screen = new StringBuilder();
            _ = ReadInto(shell, screen, CancellationToken);

            await WaitFor(screen, "signed in as 'alice'", CancellationToken);

            await shell.WriteAsync("who\r", CancellationToken);
            await WaitFor(screen, "<- you", CancellationToken);

            Assert.That(server.SSH!.Sessions.Single().Account, Is.EqualTo("alice"));

            await shell.WriteAsync("quit\r", CancellationToken);
            await shell.Closed.WaitAsync(CancellationToken);

            Assert.Multiple(() => {
                Assert.That(shell.ExitStatus.Result,    Is.EqualTo(0));
                Assert.That(server.IsRunning,           Is.True,  "quit over SSH leaves the session, not the server");
            });

        }

        #endregion

        #region AKeyNobodyAuthorizedGetsNowhere()

        /// <summary>
        /// A key nobody authorized, and the authorized key under another name,
        /// are both refused.
        /// </summary>
        [Test]
        [CancelAfter(30_000)]
        public async Task AKeyNobodyAuthorizedGetsNowhere(CancellationToken CancellationToken)
        {

            await Assert.CatchAsync<Exception>(async () => await (await Connect("alice", SshHostKey.GenerateEd25519(), CancellationToken)).DisposeAsync(),
                                         "a key nobody authorized");

            await Assert.CatchAsync<Exception>(async () => await (await Connect("admin", userKey, CancellationToken)).DisposeAsync(),
                                         "alice's key under another account's name");

        }

        #endregion


        #region (private) Deliver(To, Subject, CancellationToken)

        /// <summary>
        /// One message over the MTA port, as the server's last reply to each step.
        /// </summary>
        private async Task<List<String>> Deliver(String To, String Subject, CancellationToken CancellationToken)
        {

            using var tcp     = new TcpClient();
            await tcp.ConnectAsync(System.Net.IPAddress.Loopback, server.Settings.Port, CancellationToken);

            var stream        = tcp.GetStream();
            var reader        = new StreamReader(stream, Encoding.ASCII);
            var writer        = new StreamWriter(stream, Encoding.ASCII) { NewLine = "\r\n", AutoFlush = true };
            var replies       = new List<String>();

            async Task Reply()
            {
                String? line;
                do
                {
                    line = await reader.ReadLineAsync(CancellationToken);
                }
                while (line is not null && line.Length > 3 && line[3] == '-');

                replies.Add(line ?? "(closed)");
            }

            await Reply();

            foreach (var command in new[] { "EHLO client.test", "MAIL FROM:<alice@client.test>", $"RCPT TO:<{To}>" })
            {
                await writer.WriteLineAsync(command);
                await Reply();
            }

            if (replies[^1].StartsWith("250"))
            {

                await writer.WriteLineAsync("DATA");
                await Reply();

                await writer.WriteAsync($"From: alice@client.test\r\nTo: {To}\r\nSubject: {Subject}\r\n\r\nA line.\r\n.\r\n");
                await Reply();

            }

            await writer.WriteLineAsync("QUIT");
            await Reply();

            return replies;

        }

        #endregion

        #region (private) Connect(Account, Key, CancellationToken)

        /// <summary>
        /// Sign in over SSH, trusting only the host key the banner names.
        /// </summary>
        private ValueTask<SshClient> Connect(String Account, ISshHostKey Key, CancellationToken CancellationToken)

            => SshClient.ConnectAsync("127.0.0.1",
                                      server.Settings.SSHPort,
                                      new SshClientOptions {
                                          Username       = Account,
                                          Credentials    = [ Key ],
                                          VerifyHostKey  = blob => server.SSH!.HostKey!.EndsWith(SshFingerprint.Sha256(blob))
                                      },
                                      CancellationToken);

        #endregion

        #region (private static) ReadInto(Shell, Screen, CancellationToken) / WaitFor(Screen, Text, CancellationToken)

        private static async Task ReadInto(SshClientShell Shell, StringBuilder Screen, CancellationToken CancellationToken)
        {

            var buffer = new Byte[4096];

            try
            {
                while (await Shell.Output.ReadAsync(buffer, CancellationToken) is var read and > 0)
                    lock (Screen)
                        Screen.Append(Encoding.UTF8.GetString(buffer, 0, read));
            }
            catch
            {
                // The session ended.
            }

        }

        private static async Task WaitFor(StringBuilder Screen, String Text, CancellationToken CancellationToken)
        {
            while (true)
            {

                lock (Screen)
                    if (Screen.ToString().Contains(Text))
                        return;

                await Task.Delay(20, CancellationToken);

            }
        }

        #endregion

        #region (private static) FreePort()

        /// <summary>
        /// A port nothing listens on right now.
        /// </summary>
        private static UInt16 FreePort()
        {

            var listener = new TcpListener(System.Net.IPAddress.Loopback, 0);

            listener.Start();

            var port = (UInt16) ((IPEndPoint) listener.LocalEndpoint).Port;

            listener.Stop();

            return port;

        }

        #endregion

    }

}
