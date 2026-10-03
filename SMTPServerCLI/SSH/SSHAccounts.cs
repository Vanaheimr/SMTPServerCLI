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

using System.Diagnostics.CodeAnalysis;

using org.GraphDefined.Vanaheimr.Hermod.SSH;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SMTP.CLI
{

    /// <summary>
    /// Who may sign in to the command line over SSH, and with which keys: one
    /// file per account, in the format of OpenSSH's authorized_keys, named
    /// after the account.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These are not the SMTP accounts of users.txt. An SMTP account may send
    /// mail; an account here may run the server - add SMTP accounts, empty the
    /// queue, read the mailbox. The two are kept apart on purpose, so that the
    /// password of a mail client is never the way into the console.
    /// </para>
    /// <para>
    /// Keys only, no passwords. A file is read again at every sign-in, so a
    /// key added or removed by hand counts at once. Every option OpenSSH has
    /// for a line is honoured by Hermod's parser - from=, no-pty, restrict,
    /// expiry-time - or the line is refused, never half-honoured.
    /// </para>
    /// </remarks>
    /// <param name="Directory">Where the files are.</param>
    public sealed class SSHAccounts(String Directory)
    {

        #region Properties

        /// <summary>
        /// Where the files are.
        /// </summary>
        public String Directory { get; } = Directory;

        #endregion


        #region Find(Account, PublicKeyBlob)

        /// <summary>
        /// The line of the account's file that lets the given key in now, or null.
        /// </summary>
        public AuthorizedKey? Find(String                Account,
                                   ReadOnlySpan<Byte>    PublicKeyBlob)
        {

            var now = DateTimeOffset.UtcNow;

            foreach (var entry in Of(Account))
                if (!entry.IsCertAuthority && entry.Matches(PublicKeyBlob) && entry.IsValidAt(now))
                    return entry;

            return null;

        }

        #endregion

        #region Of(Account)

        /// <summary>
        /// The keys of the given account; none for a name that is no account name.
        /// </summary>
        public IReadOnlyList<AuthorizedKey> Of(String Account)
        {

            if (!IsAccountName(Account))
                return [];

            var file = FileOf(Account);

            if (!File.Exists(file))
                return [];

            try
            {
                return AuthorizedKeysFile.Parse(File.ReadAllText(file));
            }
            catch
            {
                return [];
            }

        }

        #endregion

        #region AccountsWithKeys()

        /// <summary>
        /// The accounts that have at least one key, by name.
        /// </summary>
        public IReadOnlyList<String> AccountsWithKeys()

            => System.IO.Directory.Exists(Directory)
                   ? [.. System.IO.Directory.EnumerateFiles(Directory).
                                             Select(Path.GetFileName).
                                             OfType<String>().
                                             Where (account => IsAccountName(account) && Of(account).Count > 0).
                                             Order (StringComparer.Ordinal)]
                   : [];

        #endregion

        #region TryAuthorize(Account, Text, out Added, out Refused)

        /// <summary>
        /// Let the given account in with the keys in the given text - lines as an
        /// authorized_keys file has them, or the RFC 4716 block PuTTYgen saves.
        /// A key the account has already is not written twice.
        /// </summary>
        /// <param name="Account">The account.</param>
        /// <param name="Text">The public key(s).</param>
        /// <param name="Added">The fingerprints of the keys that were new.</param>
        /// <param name="Refused">Why not.</param>
        public Boolean TryAuthorize(String                                          Account,
                                    String                                          Text,
                                    out IReadOnlyList<String>                       Added,
                                    [NotNullWhen(false)] out String?                Refused)
        {

            Added = [];

            if (!IsAccountName(Account))
            {
                Refused = $"'{Account}' cannot be an account name: letters, digits, '.', '-' and '_', beginning with a letter or digit.";
                return false;
            }

            if (!TryRead(Text, out var lines, out Refused))
                return false;

            var known  = Of(Account);
            var added  = new List<String>();
            var write  = new List<String>();

            foreach (var line in lines)
            {

                AuthorizedKeysFile.TryParseLine(line, out var entry);

                if (entry is null || known.Any(key => key.Matches(entry.PublicKey.Blob)) || write.Contains(line))
                    continue;

                write.Add(line);
                added.Add(SshFingerprint.Sha256(entry.PublicKey.Blob));

            }

            if (write.Count > 0)
            {
                System.IO.Directory.CreateDirectory(Directory);
                File.AppendAllLines(FileOf(Account), write);
            }

            Added = added;
            return true;

        }

        #endregion


        #region (static) IsAccountName(Name)

        /// <summary>
        /// Whether the given name can be an account here - and a file name, on
        /// every system, without a way out of the directory.
        /// </summary>
        public static Boolean IsAccountName(String Name)

            => Name.Length is > 0 and <= 64 &&
               Char.IsAsciiLetterOrDigit(Name[0]) &&
               Name.All(c => Char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_');

        #endregion

        #region (static) TryRead(Text, out Lines, out Refused)

        /// <summary>
        /// The keys in what somebody hands over, each as the line it is written
        /// to a file as.
        /// </summary>
        public static Boolean TryRead(String                                         Text,
                                      [NotNullWhen(true)]  out IReadOnlyList<String>?  Lines,
                                      [NotNullWhen(false)] out String?                 Refused)
        {

            Lines    = null;
            Refused  = null;

            if (Text.Contains("---- BEGIN SSH2 PUBLIC KEY ----", StringComparison.Ordinal))
            {
                try
                {
                    Lines = [ SshPublicKey.ParseRfc4716(Text).ToAuthorizedKeyLine() ];
                    return true;
                }
                catch (Exception problem)
                {
                    Refused = $"it is an RFC 4716 public key that could not be read: {problem.Message}";
                    return false;
                }
            }

            if (Text.Contains("PRIVATE KEY", StringComparison.Ordinal) || Text.StartsWith("PuTTY-User-Key-File", StringComparison.Ordinal))
            {
                Refused = "it is a private key. Only the public key goes here - the .pub file, or what PuTTYgen shows for an authorized_keys file.";
                return false;
            }

            var lines = new List<String>();

            foreach (var raw in Text.ReplaceLineEndings("\n").Split('\n'))
            {

                var line = raw.Trim();

                if (line.Length == 0 || line.StartsWith('#'))
                    continue;

                if (!AuthorizedKeysFile.TryParseLine(line, out _))
                {
                    Refused = $"'{(line.Length > 40 ? line[..40] + "..." : line)}' is no public key as an authorized_keys file has one.";
                    return false;
                }

                lines.Add(line);

            }

            if (lines.Count == 0)
            {
                Refused = "there is no public key in it.";
                return false;
            }

            Lines = lines;
            return true;

        }

        #endregion

        #region (private) FileOf(Account)

        private String FileOf(String Account)

            => Path.Combine(Directory, Account);

        #endregion

    }

}
