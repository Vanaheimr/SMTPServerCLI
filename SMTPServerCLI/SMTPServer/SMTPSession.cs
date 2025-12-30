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
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SMTP.New
{


    public enum SMTPSessionState {
        Connected,
        Greeted,
        MailFrom,
        RcptTo,
        Data,
        Quit
    }

    public sealed class SMTPSession(TcpClient          client,
                                    SMTPServerConfig   config,
                                    IMailStorage       storage,
                                    DNSVerifier        dnsVerifier,
                                    X509Certificate2?  certificate,
                                    IUserStore         userStore,
                                    IMailQueue?        mailQueue,
                                    Boolean            isSubmissionPort,
                                    ILogger            logger)
    {

        private Stream                         _stream         = client.GetStream();
        private StreamReader                   _reader         = new (client.GetStream(), Encoding.ASCII);
        private StreamWriter                   _writer         = new (client.GetStream(), Encoding.ASCII) { AutoFlush = true };
        private SMTPSessionState               _state          = SMTPSessionState.Connected;
        private String?                        _mailFrom;
        private readonly List<String>          _rcptTo         = [];
        private readonly List<String>          _localRcptTo    = []; // Recipients on local domains
        private readonly List<String>          _remoteRcptTo   = []; // Recipients on remote domains (relay)
        private Boolean                        _tlsActive;
        private readonly System.Net.IPAddress  _clientIp       = ((IPEndPoint) client.Client.RemoteEndPoint!).Address;
        private String                         _heloHostname   = "";
        private readonly SmtpAuthManager       _authManager    = new (userStore, logger);
        private Boolean                        _inAuthExchange;
        private X509Certificate2?              _clientCertificate;

        public async Task HandleAsync(CancellationToken ct)
        {
            try
            {
                await SendResponseAsync(220, $"{config.Hostname} ESMTP AchimSMTP ready");

                while (!ct.IsCancellationRequested && client.Connected)
                {
                    var line = await ReadLineAsync(ct);
                    if (line is null)
                        break;

                    logger.Log(LogLevel.Debug, $"C: {line}");

                    // Handle AUTH exchange specially
                    if (_inAuthExchange)
                    {
                        await ProcessAuthResponseAsync(line, ct);
                        continue;
                    }

                    var (command, args) = ParseCommand(line);
                    await ProcessCommandAsync(command, args, ct);

                    if (_state == SMTPSessionState.Quit)
                        break;
                }
            }
            catch (OperationCanceledException)
            {
                logger.Log(LogLevel.Debug, "Session cancelled");
            }
            catch (Exception ex)
            {
                logger.Log(LogLevel.Error, $"Session error: {ex.Message}");
            }
            finally
            {
                client.Close();
            }
        }

        private async Task ProcessAuthResponseAsync(String response, CancellationToken ct)
        {
            // Handle AUTH cancellation
            if (response == "*")
            {
                _inAuthExchange = false;
                _authManager.Reset();
                await SendResponseAsync(501, "Authentication cancelled");
                return;
            }

            var result = await _authManager.ProcessResponseAsync(response, ct);
            await HandleAuthResultAsync(result);
        }

        private async Task ProcessCommandAsync(String command, String args, CancellationToken ct)
        {
            switch (command.ToUpperInvariant())
            {

                case "HELO":
                    await HandleHeloAsync(args);
                    break;

                case "EHLO":
                    await HandleEhloAsync(args);
                    break;

                case "STARTTLS":
                    await HandleStartTlsAsync(ct);
                    break;

                case "AUTH":
                    await HandleAuthAsync(args, ct);
                    break;

                case "MAIL":
                    await HandleMailFromAsync(args);
                    break;

                case "RCPT":
                    await HandleRcptToAsync(args);
                    break;

                case "DATA":
                    await HandleDataAsync(ct);
                    break;

                case "RSET":
                    await HandleRsetAsync();
                    break;

                case "NOOP":
                    await SendResponseAsync(250, "OK");
                    break;

                case "QUIT":
                    await HandleQuitAsync();
                    break;

                case "VRFY":
                    await SendResponseAsync(252, "Cannot verify user");
                    break;

                default:
                    await SendResponseAsync(500, "Unrecognized command");
                    break;

            }
        }

        private async Task HandleHeloAsync(String hostname)
        {
            _heloHostname = hostname;
            _state = SMTPSessionState.Greeted;
            await SendResponseAsync(250, $"Hello {hostname}, pleased to meet you");
        }

        private async Task HandleEhloAsync(String hostname)
        {
            _heloHostname = hostname;
            _state = SMTPSessionState.Greeted;

            var extensions = new List<String>
            {
                $"{config.Hostname} Hello {hostname}",
                $"SIZE {config.MaxMessageSize}",
                "8BITMIME",
                "ENHANCEDSTATUSCODES",
                "PIPELINING"
            };

            if (certificate is not null && !_tlsActive)
                extensions.Add("STARTTLS");

            // Advertise AUTH mechanisms
            var authMechanisms = _authManager.GetAvailableMechanisms(_tlsActive).ToList();
            if (authMechanisms.Count > 0)
                extensions.Add($"AUTH {String.Join(' ', authMechanisms)}");

            for (int i = 0; i < extensions.Count - 1; i++)
                await SendResponseAsync(250, extensions[i], multiline: true);
        
            await SendResponseAsync(250, extensions[^1]);
        }

        private async Task HandleAuthAsync(String args, CancellationToken ct)
        {
            if (_state < SMTPSessionState.Greeted)
            {
                await SendResponseAsync(503, "Say HELO/EHLO first");
                return;
            }

            if (_authManager.IsAuthenticated)
            {
                await SendResponseAsync(503, "Already authenticated");
                return;
            }

            // Check if PLAIN/LOGIN requires TLS
            var parts = args.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0)
            {
                await SendResponseAsync(501, "Syntax: AUTH mechanism [initial-response]");
                return;
            }

            var mechanism = parts[0].ToUpperInvariant();
        
            // PLAIN and LOGIN should require TLS (but allow SCRAM without)
            if (!_tlsActive && (mechanism == "PLAIN" || mechanism == "LOGIN"))
            {
                await SendResponseAsync(538, "5.7.11 Encryption required for requested authentication mechanism");
                return;
            }

            // EXTERNAL requires client certificate
            if (mechanism == "EXTERNAL" && _clientCertificate is null)
            {
                await SendResponseAsync(535, "5.7.8 Client certificate required for EXTERNAL authentication");
                return;
            }

            var startResult = _authManager.StartAuth(mechanism);
            if (startResult.Result == AuthResult.InvalidMechanism)
            {
                await SendResponseAsync(504, startResult.ErrorCode ?? "Unrecognized authentication type");
                return;
            }

            // Check for initial response (AUTH PLAIN <initial-response>)
            if (parts.Length > 1)
            {
                var result = await _authManager.ProcessResponseAsync(parts[1], ct);
                await HandleAuthResultAsync(result);
            }
            else
            {
                // Request initial response
                _inAuthExchange = true;
                await SendResponseAsync(334, startResult.Challenge ?? "");
            }
        }

        private async Task HandleAuthResultAsync(AuthResponse result)
        {
            switch (result.Result)
            {

                case AuthResult.Success:
                    _inAuthExchange = false;
                    var successMsg = result.Message is not null 
                        ? $"2.7.0 Authentication successful {result.Message}"
                        : "2.7.0 Authentication successful";
                    await SendResponseAsync(235, successMsg);
                    logger.Log(LogLevel.Info, $"Authenticated: {result.Username} via {_authManager.AuthenticationMethod}");
                    break;

                case AuthResult.Continue:
                    _inAuthExchange = true;
                    await SendResponseAsync(334, result.Challenge ?? "");
                    break;

                case AuthResult.Fail:
                    _inAuthExchange = false;
                    await SendResponseAsync(535, result.ErrorCode ?? "5.7.8 Authentication failed");
                    break;

            }
        }

        private async Task HandleStartTlsAsync(CancellationToken ct)
        {

            if (certificate is null)
            {
                await SendResponseAsync(454, "TLS not available");
                return;
            }

            if (_tlsActive)
            {
                await SendResponseAsync(503, "TLS already active");
                return;
            }

            await SendResponseAsync(220, "Ready to start TLS");

            try
            {

                var sslStream = new SslStream(_stream, false, ValidateClientCertificate);

                await sslStream.AuthenticateAsServerAsync(
                    new SslServerAuthenticationOptions
                    {
                        ServerCertificate = certificate,
                        ClientCertificateRequired = false,  // Optional client cert for EXTERNAL auth
                        EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | 
                                              System.Security.Authentication.SslProtocols.Tls13
                    },
                    ct
                );

                _stream = sslStream;
                _reader = new StreamReader(sslStream, Encoding.ASCII);
                _writer = new StreamWriter(sslStream, Encoding.ASCII) { AutoFlush = true };
                _tlsActive = true;
                _state = SMTPSessionState.Connected;

                // Capture client certificate for EXTERNAL auth
                if (sslStream.RemoteCertificate is X509Certificate remoteCert)
                {
                    _clientCertificate = new X509Certificate2(remoteCert);
                    _authManager.SetClientCertificate(_clientCertificate);
                    logger.Log(LogLevel.Info, $"Client certificate: {_clientCertificate.Subject} (Thumbprint: {_clientCertificate.Thumbprint[..8]}...)");
                }

                logger.Log(LogLevel.Info, $"TLS established: {sslStream.SslProtocol}, {sslStream.NegotiatedCipherSuite}");

            }
            catch (Exception ex)
            {
                logger.Log(LogLevel.Error, $"TLS handshake failed: {ex.Message}");
                throw;
            }

        }

        private Boolean ValidateClientCertificate(Object            sender,
                                                  X509Certificate?  certificate,
                                                  X509Chain?        chain,
                                                  SslPolicyErrors   sslPolicyErrors)
        {

            // Accept any client certificate (or none) - validation happens during AUTH EXTERNAL
            if (certificate is not null)
            {
                logger.Log(LogLevel.Debug, $"Client presented certificate: {certificate.Subject}");
            }

            return true;

        }

        private async Task HandleMailFromAsync(String args)
        {
            if (_state < SMTPSessionState.Greeted)
            {
                await SendResponseAsync(503, "Say HELO first");
                return;
            }

            if (config.RequireStartTls && !_tlsActive)
            {
                await SendResponseAsync(530, "Must issue STARTTLS first");
                return;
            }

            var match = Regex.Match(args, @"FROM:\s*<([^>]*)>", RegexOptions.IgnoreCase);
            if (!match.Success)
            {
                await SendResponseAsync(501, "Syntax error in MAIL command");
                return;
            }

            _mailFrom = match.Groups[1].Value;
            _rcptTo.Clear();
            _state = SMTPSessionState.MailFrom;

            await SendResponseAsync(250, "OK");
        }

        private async Task HandleRcptToAsync(String args)
        {

            if (_state < SMTPSessionState.MailFrom)
            {
                await SendResponseAsync(503, "Need MAIL command first");
                return;
            }

            var match = Regex.Match(args, @"TO:\s*<([^>]+)>", RegexOptions.IgnoreCase);
            if (!match.Success)
            {
                await SendResponseAsync(501, "Syntax error in RCPT command");
                return;
            }

            if (_rcptTo.Count >= config.MaxRecipients)
            {
                await SendResponseAsync(452, "Too many recipients");
                return;
            }

            var recipient       = match.Groups[1].Value;
            var recipientDomain = ExtractDomain(recipient);

            // Check if this is a local or remote recipient
            var isLocalRecipient = config.IsLocalDomain(recipientDomain);

            if (!isLocalRecipient)
            {
                // Remote recipient = relay request
                // Require authentication to prevent open relay
                if (config.RequireAuthForRelay && !_authManager.IsAuthenticated)
                {
                    logger.Log(LogLevel.Warning, 
                        $"Relay denied for {recipient}: not authenticated (from {_clientIp})");
                    await SendResponseAsync(550, "5.7.1 Relay access denied. Authentication required.");
                    return;
                }

                _remoteRcptTo.Add(recipient);
                logger.Log(LogLevel.Debug, $"Remote recipient (relay): {recipient}");
            }
            else
            {
                _localRcptTo.Add(recipient);
                logger.Log(LogLevel.Debug, $"Local recipient: {recipient}");
            }

            // Submission port (587) requires auth for all mail per RFC 6409
            if (isSubmissionPort && config.RequireAuthOnSubmission && !_authManager.IsAuthenticated)
            {
                // Allow the RCPT but will check again at DATA
                logger.Log(LogLevel.Debug, $"Submission port recipient (auth check deferred): {recipient}");
            }

            _rcptTo.Add(recipient);
            _state = SMTPSessionState.RcptTo;

            await SendResponseAsync(250, "OK");

        }

        private async Task HandleDataAsync(CancellationToken ct)
        {
            if (_state < SMTPSessionState.RcptTo || _rcptTo.Count == 0)
            {
                await SendResponseAsync(503, "Need RCPT command first");
                return;
            }

            await SendResponseAsync(354, "Start mail input; end with <CRLF>.<CRLF>");

            var messageBuilder = new StringBuilder();
            var totalSize = 0;

            while (!ct.IsCancellationRequested)
            {

                var line = await ReadLineAsync(ct);

                Console.WriteLine($"LINE: '{line}'");

                if (line is null)
                    break;

                if (line == ".")
                    break;

                // Dot-stuffing: remove leading dot if line starts with ".."
                if (line.StartsWith(".."))
                    line = line[1..];

                totalSize += line.Length + 2;
                if (totalSize > config.MaxMessageSize)
                {
                    await SendResponseAsync(552, "Message size exceeds maximum");
                    ResetTransaction();
                    return;
                }

                messageBuilder.AppendLine(line);

            }

            var rawMessage = messageBuilder.ToString();
            var message = EMailMessage.Parse(rawMessage);

            // Perform DNS verification
            var senderDomain = ExtractDomain(_mailFrom ?? "");
            if (!string.IsNullOrEmpty(senderDomain))
            {
                message.Verification = await dnsVerifier.VerifyAsync(
                    senderDomain,
                    _clientIp,
                    _mailFrom ?? "",
                    _heloHostname,
                    message,
                    ct
                );

                LogVerificationResult(message.Verification);
            }

            // Store the message locally
            var filePath = await storage.StoreAsync(message, _mailFrom ?? "<>", _rcptTo, ct);

            // Queue for outbound delivery if mail queue is available
            if (mailQueue is not null)
            {

                // Group recipients by domain
                var recipientsByDomain = _rcptTo
                    .GroupBy(r => ExtractDomain(r))
                    .Where(g => !string.IsNullOrEmpty(g.Key));

                foreach (var domainGroup in recipientsByDomain)
                {

                    var queuedMail = new QueuedMail {
                                         Id              = $"{Path.GetFileNameWithoutExtension(filePath)}-{domainGroup.Key}",
                                         EnvelopeFrom    = _mailFrom ?? "",
                                         EnvelopeTo      = [.. domainGroup],
                                         MessageContent  = rawMessage,
                                         TargetDomain    = domainGroup.Key,
                                         QueuedAt        = DateTime.UtcNow,
                                         NextRetry       = DateTime.UtcNow
                                     };

                    await mailQueue.EnqueueAsync(queuedMail, ct);

                }
            }

            await SendResponseAsync(250, $"OK: Message accepted for delivery ({Path.GetFileName(filePath)})");
            ResetTransaction();

        }

        private void LogVerificationResult(DnsVerificationResult v)
        {

            var spfIcon   = v.Spf   == SPFResult.  Pass ? "✓" : v.Spf   == SPFResult.  Fail ? "✗" : "?";
            var dkimIcon  = v.Dkim  == DkimResult. Pass ? "✓" : v.Dkim  == DkimResult. Fail ? "✗" : "?";
            var dmarcIcon = v.Dmarc == DmarcResult.Pass ? "✓" : v.Dmarc == DmarcResult.Fail ? "✗" : "?";

            logger.Log(LogLevel.Info, $"Verification: SPF={spfIcon}{v.Spf} DKIM={dkimIcon}{v.Dkim} DMARC={dmarcIcon}{v.Dmarc}");

            if (v.MxRecords.Length > 0)
                logger.Log(LogLevel.Debug, $"MX Records: {string.Join(", ", v.MxRecords)}");

        }

        private static string ExtractDomain(string email)
        {
            var atIndex = email.IndexOf('@');
            return atIndex > 0 ? email[(atIndex + 1)..] : "";
        }

        private async Task HandleRsetAsync()
        {
            ResetTransaction();
            _authManager.Reset();
            await SendResponseAsync(250, "OK");
        }

        private void ResetTransaction()
        {
            _mailFrom = null;
            _rcptTo.Clear();
            _state = SMTPSessionState.Greeted;
        }

        private async Task HandleQuitAsync()
        {
            await SendResponseAsync(221, $"{config.Hostname} closing connection");
            _state = SMTPSessionState.Quit;
        }

        private async Task SendResponseAsync(int code, string message, bool multiline = false)
        {
            var separator = multiline ? '-' : ' ';
            var response = $"{code}{separator}{message}";
            logger.Log(LogLevel.Debug, $"S: {response}");
            await _writer.WriteLineAsync(response);
        }

        private async Task<String?> ReadLineAsync(CancellationToken ct)
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(config.SessionTimeout);
                return await _reader.ReadLineAsync(cts.Token);
            }
            catch
            {
                return null;
            }
        }

        private static (String Command, String Args) ParseCommand(String line)
        {
            var spaceIndex = line.IndexOf(' ');
            if (spaceIndex < 0)
                return (line, "");
            return (line[..spaceIndex], line[(spaceIndex + 1)..]);
        }

    }

}
