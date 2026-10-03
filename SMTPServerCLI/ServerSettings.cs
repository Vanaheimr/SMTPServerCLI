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

namespace org.GraphDefined.Vanaheimr.Hermod.SMTP.CLI
{

    /// <summary>
    /// What one start of the server runs with: the defaults of
    /// <see cref="Configuration"/>, and whatever the switches said instead.
    /// </summary>
    /// <remarks>
    /// Only what somebody plausibly wants to change for one run has a switch:
    /// who the server is, where it listens, where its files are, how it reaches
    /// the rest of the world and how much it says. Everything else - rate
    /// limits, queue tuning, the reporting addresses - stays in
    /// <see cref="Configuration"/>, which is still the one place to change a
    /// default for good. Nothing a switch says is written anywhere.
    /// </remarks>
    public sealed class ServerSettings
    {

        #region Data

        private String?  dkimDomain;

        #endregion

        #region Identity & ports

        /// <summary>The public hostname: banner, EHLO, Received headers, the default DKIM and report domain.</summary>
        public String           Hostname                  { get; set; } = Configuration.Hostname;

        /// <summary>MTA port (inbound mail from other servers).</summary>
        public UInt16           Port                      { get; set; } = Configuration.Port;

        /// <summary>Message submission port (STARTTLS, authentication).</summary>
        public UInt16           SubmissionPort            { get; set; } = Configuration.SubmissionPort;

        /// <summary>Implicit-TLS submission port; only bound when there is a certificate.</summary>
        public UInt16           ImplicitTlsPort           { get; set; } = Configuration.ImplicitTlsPort;

        /// <summary>Domains delivered locally. "localhost" and "localhost.localdomain" are always added.</summary>
        public HashSet<String>  LocalDomains              { get; set; } = [.. Configuration.LocalDomains];

        #endregion

        #region TLS

        /// <summary>
        /// A PKCS#12 file with the server's certificate and key. Null: the
        /// self-signed one generated into the configuration folder.
        /// </summary>
        public String?          CertificatePath           { get; set; }

        /// <summary>The password of the certificate file.</summary>
        public String           CertificatePassword       { get; set; } = Configuration.CertificatePassword;

        /// <summary>Refuse MAIL FROM before STARTTLS.</summary>
        public Boolean          RequireStartTls           { get; set; } = Configuration.RequireStartTls;

        #endregion

        #region Inbound checks

        public Boolean          VerifySpf                 { get; set; } = Configuration.VerifySpf;
        public Boolean          VerifyDkim                { get; set; } = Configuration.VerifyDkim;
        public Boolean          VerifyDmarc               { get; set; } = Configuration.VerifyDmarc;

        #endregion

        #region DKIM signing

        /// <summary>
        /// The DKIM d= domain. Follows <see cref="Hostname"/> as long as
        /// <see cref="Configuration.DkimDomain"/> does and nobody said otherwise,
        /// so that --hostname alone moves the signing domain along with it.
        /// </summary>
        public String           DkimDomain
        {

            get
                => dkimDomain ?? (Configuration.DkimDomain == Configuration.Hostname
                                      ? Hostname
                                      : Configuration.DkimDomain);

            set
                => dkimDomain = value;

        }

        /// <summary>The DKIM s= selector.</summary>
        public String           DkimSelector              { get; set; } = Configuration.DkimSelector;

        #endregion

        #region Outbound

        public String?          SmartHost                 { get; set; } = Configuration.SmartHost;
        public UInt16           SmartHostPort             { get; set; } = Configuration.SmartHostPort;
        public String?          SmartHostUsername         { get; set; } = Configuration.SmartHostUsername;
        public String?          SmartHostPassword         { get; set; } = Configuration.SmartHostPassword;

        #endregion

        #region Folders

        /// <summary>The TLS certificate and the DKIM keys.</summary>
        public String           ConfigDirectory           { get; set; } = DefaultFolder("config");

        /// <summary>Received mail, the outbound queue, users.txt and the reporting state.</summary>
        public String           MailStoragePath           { get; set; } = DefaultFolder("mailstore");

        /// <summary>The accounts the server authenticates: users.txt in the mail store, where Hermod looks for it.</summary>
        public String           UsersFilePath
            => Path.Combine(MailStoragePath, "users.txt");

        #endregion

        #region The command line over SSH

        /// <summary>Whether the command line is served over SSH.</summary>
        public Boolean          SSHEnabled                { get; set; } = Configuration.EnableSSH;

        /// <summary>The port it is served on.</summary>
        public UInt16           SSHPort                   { get; set; } = Configuration.SSHPort;

        /// <summary>Every address rather than the loopback only.</summary>
        public Boolean          SSHAnyAddress             { get; set; }

        /// <summary>Keys to let in before the start: an account and a file with its public key(s).</summary>
        public List<(String Account, String File)>  AuthorizeSSHKeys  { get; } = [];

        #endregion

        #region Console

        /// <summary>From which level up the log is written to the console; null for none of it.</summary>
        public LogLevel?        ConsoleLogLevel           { get; set; } = LogLevel.Info;

        #endregion


        #region (static) DefaultFolder(Name)

        /// <summary>
        /// Where a folder is when no switch says: beside the project in a
        /// checkout of this repository, wherever the server is started from;
        /// and in the current directory anywhere else, which is the folder a
        /// published server is started in.
        /// </summary>
        /// <remarks>
        /// A checkout is recognised by the solution file at its root, looked
        /// for upwards from the binary and from the current directory. "dotnet
        /// run --project SMTPServerCLI" from the repository root and F5 in an
        /// IDE then use the same config/ - the one in git - rather than one each.
        /// </remarks>
        /// <param name="Name">The folder's name.</param>
        public static String DefaultFolder(String Name)
        {

            foreach (var start in new[] { AppContext.BaseDirectory, Environment.CurrentDirectory })
            {

                var directory = new DirectoryInfo(start);

                while (directory is not null)
                {

                    if (File.Exists(Path.Combine(directory.FullName, "SMTPServerCLI.slnx")))
                        return Path.Combine(directory.FullName, "SMTPServerCLI", Name);

                    directory = directory.Parent;

                }

            }

            return Path.Combine(Environment.CurrentDirectory, Name);

        }

        #endregion

    }

}
