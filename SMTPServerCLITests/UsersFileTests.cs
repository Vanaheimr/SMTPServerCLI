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

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using org.GraphDefined.Vanaheimr.Hermod.SMTP.Server;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SMTP.CLI.Tests
{

    /// <summary>
    /// users.txt as the CLI writes it, and as Hermod reads it.
    /// </summary>
    [TestFixture]
    public class UsersFileTests
    {

        private String directory = "";

        [SetUp]
        public void SetUp()
        {
            directory = Path.Combine(Path.GetTempPath(), "SMTPServerCLITests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
        }

        [TearDown]
        public void TearDown()
        {
            try { Directory.Delete(directory, true); } catch { }
        }

        private String UsersPath
            => Path.Combine(directory, "users.txt");


        /// <summary>
        /// The first start writes one account with a password nobody has seen,
        /// which Hermod then accepts - and leaves a file it finds alone.
        /// </summary>
        [Test]
        public async Task TheFirstStartWritesOneAccountHermodAccepts()
        {

            var users = new UsersFile(UsersPath);

            Assert.That(users.CreateWithFirstAccount("admin", out var password), Is.True);
            Assert.That(users.CreateWithFirstAccount("admin", out var again),    Is.False);

            var accounts = users.Read();

            Assert.Multiple(() => {
                Assert.That(password,                        Has.Length.EqualTo(20));
                Assert.That(again,                           Is.Null);
                Assert.That(accounts.Select(a => a.Name),    Is.EqualTo(new[] { "admin" }));
                Assert.That(accounts[0].HasPassword,         Is.True);
                Assert.That(accounts[0].HasScram,            Is.True);
                Assert.That(accounts[0].WellKnownPassword,   Is.Null);
            });

            var store = new FileUserStore(UsersPath);

            Assert.That(await store.ValidatePasswordAsync("admin", password!), Is.True);
            Assert.That(await store.ValidatePasswordAsync("admin", "test123"), Is.False);

        }

        /// <summary>
        /// add refuses an account there is, passwd one there is not, and a name
        /// the file format cannot hold is no name at all.
        /// </summary>
        [Test]
        public async Task AddPasswdAndRemoveKeepToTheirAccounts()
        {

            var users = new UsersFile(UsersPath);

            Assert.Multiple(() => {
                Assert.That(users.SetPassword("bob",     "first",  MustExist: false), Is.Null);
                Assert.That(users.SetPassword("bob",     "second", MustExist: false), Does.Contain("already"));
                Assert.That(users.SetPassword("nobody",  "x",      MustExist: true),  Does.Contain("no account"));
                Assert.That(users.SetPassword("bad:one", "x",      MustExist: false), Does.Contain("cannot be an account name"));
                Assert.That(users.SetPassword("with space", "x",   MustExist: false), Does.Contain("cannot be an account name"));
                Assert.That(users.SetPassword("bob",     "",       MustExist: true),  Does.Contain("empty"));
                Assert.That(users.SetPassword("bob",     "second", MustExist: true),  Is.Null);
            });

            Assert.That(await new FileUserStore(UsersPath).ValidatePasswordAsync("bob", "second"), Is.True);

            Assert.That(users.Remove("bob"),    Is.True);
            Assert.That(users.Remove("bob"),    Is.False);
            Assert.That(users.Read(),           Is.Empty);

        }

        /// <summary>
        /// Comments and lines that are no account stay where they were.
        /// </summary>
        [Test]
        public void CommentsAndForeignLinesSurviveAChange()
        {

            File.WriteAllLines(UsersPath, [ "# a comment", "not an account line", "" ]);

            var users = new UsersFile(UsersPath);

            Assert.That(users.SetPassword("carol", "pw", MustExist: false), Is.Null);

            var lines = File.ReadAllLines(UsersPath);

            Assert.That(lines.Take(2), Is.EqualTo(new[] { "# a comment", "not an account line" }));
            Assert.That(lines.Last(),  Does.StartWith("carol:"));

        }

        /// <summary>
        /// The demo accounts older Hermod versions wrote are recognised by
        /// their passwords, and a '*' for any certificate is seen.
        /// </summary>
        [Test]
        public void TheOldDemoAccountsAreRecognised()
        {

            var test123 = Convert.ToHexString(SHA256.HashData("test123"u8)).ToLowerInvariant();

            File.WriteAllLines(UsersPath, [
                $"admin:{test123}:::::",
                 "certonly::::::*"
            ]);

            var accounts = new UsersFile(UsersPath).Read();

            Assert.Multiple(() => {
                Assert.That(accounts[0].WellKnownPassword,       Is.EqualTo("test123"));
                Assert.That(accounts[1].CertificateThumbprints,  Is.EqualTo(new[] { "*" }));
            });

        }

        /// <summary>
        /// A client certificate is an account only by a thumbprint written down
        /// for it - SHA-1 or SHA-256 - and never by its common name.
        /// </summary>
        [Test]
        public async Task ACertificateIsAnAccountOnlyByItsPinnedThumbprint()
        {

            var users = new UsersFile(UsersPath);

            users.CreateWithFirstAccount("admin", out _);

            using var forged  = SelfSigned("CN=admin");
            using var pinned  = SelfSigned("CN=whoever");
            using var other   = SelfSigned("CN=whoever");

            var sha256 = pinned.GetCertHashString(HashAlgorithmName.SHA256);

            File.WriteAllLines(UsersPath, File.ReadAllLines(UsersPath).Select(line => line.StartsWith("admin:") ? line + sha256 : line));

            var store = new PinnedCertificateUserStore(users);

            var byName    = await store.GetUserByCertificateAsync(forged);
            var byOther   = await store.GetUserByCertificateAsync(other);
            var byPinned  = await store.GetUserByCertificateAsync(pinned);

            Assert.Multiple(() => {
                Assert.That(byName,              Is.Null,              "a common name is no credential");
                Assert.That(byOther,             Is.Null,              "another certificate is not the pinned one");
                Assert.That(byPinned?.Username,  Is.EqualTo("admin"),  "the pinned one is the account");
            });

        }

        private static X509Certificate2 SelfSigned(String Subject)
        {
            using var rsa = RSA.Create(2048);
            return new CertificateRequest(Subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).
                       CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        }

    }

}
