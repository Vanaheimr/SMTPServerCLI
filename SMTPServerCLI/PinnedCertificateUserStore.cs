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

using System.Security.Cryptography.X509Certificates;

using org.GraphDefined.Vanaheimr.Hermod.SMTP.Server;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SMTP.CLI
{

    /// <summary>
    /// Hermod's file of accounts, except that a client certificate
    /// authenticates an account (SASL EXTERNAL) only when its thumbprint is
    /// written down for that account.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The session accepts any client certificate in the TLS handshake and
    /// never checks it against a CA, so a certificate is nothing more than a
    /// key pair somebody made. Hermod's FileUserStore used to take it for an
    /// account when the account said "*" - any certificate at all - or when
    /// the certificate's common name was the account's name; since Hermod
    /// #104 it, too, matches pinned thumbprints only.
    /// </para>
    /// <para>
    /// A thumbprint names one certificate, and the handshake has proved that
    /// the client holds its private key - that is the one way of matching in
    /// here. The thumbprints are read through <see cref="UsersFile"/>, the
    /// parser behind the user command, so what the console lists is what
    /// authenticates. Passwords are FileUserStore's, unchanged.
    /// </para>
    /// </remarks>
    /// <param name="Users">The accounts.</param>
    public sealed class PinnedCertificateUserStore(UsersFile Users) : IUserStore
    {

        #region Data

        private readonly FileUserStore passwords = new (Users.Path);

        #endregion


        #region GetUserAsync(Username, CancellationToken)

        public Task<UserCredentials?> GetUserAsync(String             Username,
                                                   CancellationToken  CancellationToken = default)

            => passwords.GetUserAsync(Username, CancellationToken);

        #endregion

        #region ValidatePasswordAsync(Username, Password, CancellationToken)

        public Task<Boolean> ValidatePasswordAsync(String             Username,
                                                   String             Password,
                                                   CancellationToken  CancellationToken = default)

            => passwords.ValidatePasswordAsync(Username, Password, CancellationToken);

        #endregion

        #region GetUserByCertificateAsync(Certificate, CancellationToken)

        public Task<UserCredentials?> GetUserByCertificateAsync(X509Certificate2   Certificate,
                                                                CancellationToken  CancellationToken = default)
        {

            // SHA-1 (X509Certificate2.Thumbprint) or SHA-256, as Hermod's FileUserStore accepts them.
            var sha256  = Certificate.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256);
            var account = Users.Read().FirstOrDefault(account => account.CertificateThumbprints.Contains(Certificate.Thumbprint, StringComparer.OrdinalIgnoreCase) ||
                                                                 account.CertificateThumbprints.Contains(sha256,                StringComparer.OrdinalIgnoreCase));

            return account is not null
                       ? passwords.GetUserAsync(account.Name, CancellationToken)
                       : Task.FromResult<UserCredentials?>(null);

        }

        #endregion

    }

}
