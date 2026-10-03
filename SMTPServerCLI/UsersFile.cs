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

using System.Text;
using System.Security.Cryptography;

using org.GraphDefined.Vanaheimr.Hermod.SMTP.Server;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SMTP.CLI
{

    /// <summary>
    /// One account in users.txt, as far as anybody at the console needs to see it.
    /// </summary>
    /// <param name="Name">The user name.</param>
    /// <param name="HasPassword">Whether it can authenticate with PLAIN and LOGIN.</param>
    /// <param name="HasScram">Whether it can authenticate with SCRAM-SHA-256.</param>
    /// <param name="CertificateThumbprints">The client certificates it can authenticate with EXTERNAL; "*" is any.</param>
    /// <param name="WellKnownPassword">The password everybody knows it has, where it still has one of those.</param>
    public sealed record UserAccount(String    Name,
                                     Boolean   HasPassword,
                                     Boolean   HasScram,
                                     String[]  CertificateThumbprints,
                                     String?   WellKnownPassword);


    /// <summary>
    /// The accounts the server authenticates, in the file Hermod's
    /// <see cref="FileUserStore"/> reads them from - which notices a change and
    /// reads the file again, so what is written here counts at the next AUTH.
    /// </summary>
    /// <remarks>
    /// <para>
    /// One line per account: <c>name:sha256:salt:storedKey:serverKey:iterations:thumbprints</c>.
    /// Comments and lines this class does not understand are kept as they are.
    /// </para>
    /// <para>
    /// Left to itself, Hermod writes a file without accounts (before Hermod
    /// #104 it wrote the demo accounts admin, user and demo, whose passwords
    /// were in its source, and that is what <see cref="UserAccount.WellKnownPassword"/>
    /// still looks out for). A server nobody can sign in to is no use, so the
    /// first start writes the file itself instead, with one account and a
    /// password nobody has seen before - see <see cref="CreateWithFirstAccount"/>.
    /// </para>
    /// </remarks>
    /// <param name="Path">The file.</param>
    public sealed class UsersFile(String Path)
    {

        #region Data

        /// <summary>
        /// The passwords of the accounts Hermod writes when it finds no file,
        /// as their hashes - which is how they are recognised in one.
        /// </summary>
        private static readonly Dictionary<String, String> wellKnownPasswords = new[] { "test123", "demo" }.
                                                                                     ToDictionary(Hash, password => password);

        /// <summary>
        /// The characters a made-up password is made of: none that look like
        /// another in a terminal's font, so that it can be typed off the screen.
        /// </summary>
        private const String passwordCharacters = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";

        private readonly Lock padlock = new();

        #endregion

        #region Properties

        /// <summary>
        /// The file.
        /// </summary>
        public String   Path      { get; } = Path;

        /// <summary>
        /// Whether there is one yet.
        /// </summary>
        public Boolean  Exists
            => File.Exists(Path);

        #endregion


        #region Read()

        /// <summary>
        /// The accounts in the file, in its order; none when there is no file.
        /// </summary>
        public IReadOnlyList<UserAccount> Read()
        {
            lock (padlock)
            {

                if (!File.Exists(Path))
                    return [];

                return [.. File.ReadAllLines(Path).
                                Select(Parse).
                                Where (account => account is not null).
                                Cast<UserAccount>()];

            }
        }

        #endregion

        #region CreateWithFirstAccount(Name, out Password)

        /// <summary>
        /// Write the file with one account, whose password is made up here and
        /// handed back to be shown once - unless there is a file already, which
        /// is then left alone.
        /// </summary>
        /// <param name="Name">The account's name.</param>
        /// <param name="Password">The password made up for it.</param>
        public Boolean CreateWithFirstAccount(String       Name,
                                              out String?  Password)
        {
            lock (padlock)
            {

                Password = null;

                if (File.Exists(Path))
                    return false;

                Password = MakeUpPassword();

                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(Path)) ?? ".");

                Write([
                    "# SMTP accounts, read by Hermod's FileUserStore and re-read whenever this file changes.",
                    "# Format: username:password_sha256:scram_salt:scram_stored_key:scram_server_key:iterations:cert_thumbprints",
                    "# Manage them at the server's command line: user add | passwd | remove",
                    "",
                    Line(Name, Password, [])
                ]);

                return true;

            }
        }

        #endregion

        #region SetPassword(Name, Password, MustExist)

        /// <summary>
        /// Give an account a password, adding the account where it is not in the
        /// file yet. The certificates it may authenticate with stay what they were.
        /// </summary>
        /// <param name="Name">The account's name.</param>
        /// <param name="Password">Its new password.</param>
        /// <param name="MustExist">True: change the password of an existing account, and refuse a new one. False: add one, and refuse an existing one.</param>
        /// <returns>Null when done, or why not.</returns>
        public String? SetPassword(String   Name,
                                   String   Password,
                                   Boolean  MustExist)
        {

            if (Name.Length == 0 || Name.Contains(':') || Name.Any(Char.IsWhiteSpace) || Name.StartsWith('#'))
                return $"'{Name}' cannot be an account name: no colon, no whitespace, no leading '#'.";

            if (Password.Length == 0)
                return "An empty password is no password.";

            lock (padlock)
            {

                var lines  = File.Exists(Path) ? File.ReadAllLines(Path).ToList() : [];
                var index  = lines.FindIndex(line => Parse(line)?.Name.Equals(Name, StringComparison.OrdinalIgnoreCase) == true);

                if (MustExist && index < 0)
                    return $"There is no account '{Name}'.";

                if (!MustExist && index >= 0)
                    return $"There is an account '{Name}' already; 'user passwd {Name}' gives it a new password.";

                if (index >= 0)
                    lines[index] = Line(Parse(lines[index])!.Name, Password, Parse(lines[index])!.CertificateThumbprints);

                else
                    lines.Add(Line(Name, Password, []));

                Write(lines);

                return null;

            }

        }

        #endregion

        #region Remove(Name)

        /// <summary>
        /// Take an account out of the file.
        /// </summary>
        /// <param name="Name">The account's name.</param>
        /// <returns>Whether there was one.</returns>
        public Boolean Remove(String Name)
        {
            lock (padlock)
            {

                if (!File.Exists(Path))
                    return false;

                var lines  = File.ReadAllLines(Path).ToList();
                var count  = lines.RemoveAll(line => Parse(line)?.Name.Equals(Name, StringComparison.OrdinalIgnoreCase) == true);

                if (count > 0)
                    Write(lines);

                return count > 0;

            }
        }

        #endregion

        #region (static) MakeUpPassword()

        /// <summary>
        /// A password of 20 characters nobody has seen before.
        /// </summary>
        public static String MakeUpPassword()

            => RandomNumberGenerator.GetString(passwordCharacters, 20);

        #endregion


        #region (private static) Parse(Line)

        private static UserAccount? Parse(String Line)
        {

            if (String.IsNullOrWhiteSpace(Line) || Line.StartsWith('#'))
                return null;

            var parts = Line.Split(':');

            if (parts.Length < 7 || parts[0].Length == 0)
                return null;

            return new UserAccount(
                       Name:                    parts[0],
                       HasPassword:             parts[1].Length > 0,
                       HasScram:                parts[2].Length > 0 && parts[3].Length > 0 && parts[4].Length > 0,
                       CertificateThumbprints:  parts[6].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
                       WellKnownPassword:       wellKnownPasswords.GetValueOrDefault(parts[1].ToLowerInvariant())
                   );

        }

        #endregion

        #region (private static) Line(Name, Password, CertificateThumbprints)

        /// <summary>
        /// An account as the file writes it: the SHA-256 of the password for
        /// PLAIN and LOGIN, and the SCRAM-SHA-256 credentials derived from it.
        /// </summary>
        private static String Line(String    Name,
                                   String    Password,
                                   String[]  CertificateThumbprints)
        {

            var scram = ScramCredentialGenerator.Generate(Password);

            return $"{Name}:{Hash(Password)}:{scram.SaltBase64}:{scram.StoredKeyBase64}:{scram.ServerKeyBase64}:{scram.Iterations}:" +
                   String.Join(",", CertificateThumbprints);

        }

        #endregion

        #region (private static) Hash(Password)

        private static String Hash(String Password)

            => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Password))).ToLowerInvariant();

        #endregion

        #region (private) Write(Lines)

        /// <summary>
        /// Replace the file as a whole, so that the server never reads half of it.
        /// </summary>
        private void Write(IEnumerable<String> Lines)
        {

            var temporary = $"{Path}.{Environment.ProcessId}.tmp";

            File.WriteAllLines(temporary, Lines);
            File.Move(temporary, Path, overwrite: true);

        }

        #endregion

    }

}
