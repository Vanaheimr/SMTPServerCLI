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

using org.GraphDefined.Vanaheimr.Hermod.SSH;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SMTP.CLI.Tests
{

    /// <summary>
    /// Who may sign in to the command line over SSH, with which keys.
    /// </summary>
    [TestFixture]
    public class SSHAccountsTests
    {

        private String directory = "";

        [SetUp]
        public void SetUp()
            => directory = Path.Combine(Path.GetTempPath(), "SMTPServerCLITests", Guid.NewGuid().ToString("N"));

        [TearDown]
        public void TearDown()
        {
            try { Directory.Delete(directory, true); } catch { }
        }


        [TestCase("admin",        true)]
        [TestCase("alice.smith",  true)]
        [TestCase("ops-1_b",      true)]
        [TestCase("",             false)]
        [TestCase(".hidden",      false)]
        [TestCase("../etc",       false)]
        [TestCase("a/b",          false)]
        [TestCase("a b",          false)]
        public void AnAccountNameIsAlsoASafeFileName(String Name, Boolean Valid)

            => Assert.That(SSHAccounts.IsAccountName(Name), Is.EqualTo(Valid));


        /// <summary>
        /// A key handed over as an OpenSSH line or as PuTTYgen's RFC 4716 block
        /// lets the account in with that key, and only that key, and only under
        /// that account's name.
        /// </summary>
        [Test]
        public void AnAuthorizedKeyLetsItsAccountInAndNothingElse()
        {

            var accounts  = new SSHAccounts(directory);
            var key       = SshHostKey.GenerateEd25519();
            var other     = SshHostKey.GenerateEd25519();
            var putty     = SshHostKey.GenerateEd25519();

            Assert.That(accounts.TryAuthorize("alice", SshPublicKey.FromHostKey(key,   "alice").ToAuthorizedKeyLine(), out var added,  out var refused), Is.True, refused);
            Assert.That(accounts.TryAuthorize("alice", SshPublicKey.FromHostKey(putty, "alice").ToRfc4716(),           out var added2, out refused),     Is.True, refused);

            Assert.Multiple(() => {
                Assert.That(added,                                         Has.Count.EqualTo(1));
                Assert.That(added[0],                                      Is.EqualTo(SshFingerprint.Sha256(key.PublicKeyBlob)));
                Assert.That(added2,                                        Has.Count.EqualTo(1));
                Assert.That(accounts.Find("alice", key.PublicKeyBlob),     Is.Not.Null);
                Assert.That(accounts.Find("alice", putty.PublicKeyBlob),   Is.Not.Null);
                Assert.That(accounts.Find("alice", other.PublicKeyBlob),   Is.Null,  "a key nobody authorized");
                Assert.That(accounts.Find("bob",   key.PublicKeyBlob),     Is.Null,  "alice's key under another name");
                Assert.That(accounts.AccountsWithKeys(),                   Is.EqualTo(new[] { "alice" }));
            });

        }

        /// <summary>
        /// The same key twice is written once.
        /// </summary>
        [Test]
        public void TheSameKeyIsNotWrittenTwice()
        {

            var accounts  = new SSHAccounts(directory);
            var line      = SshPublicKey.FromHostKey(SshHostKey.GenerateEd25519(), "alice").ToAuthorizedKeyLine();

            accounts.TryAuthorize("alice", line, out _,     out _);
            accounts.TryAuthorize("alice", line, out var again, out _);

            Assert.That(again,                    Is.Empty);
            Assert.That(accounts.Of("alice"),     Has.Count.EqualTo(1));

        }

        /// <summary>
        /// What is no public key is refused with a reason, and a private key
        /// above all.
        /// </summary>
        [TestCase("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----", "private key")]
        [TestCase("PuTTY-User-Key-File-3: ssh-ed25519\n",                                       "private key")]
        [TestCase("not a key at all",                                                            "no public key")]
        [TestCase("\n# only a comment\n",                                                        "no public key")]
        public void WhatIsNoPublicKeyIsRefused(String Text, String Why)
        {

            var accounts = new SSHAccounts(directory);

            Assert.That(accounts.TryAuthorize("alice", Text, out var added, out var refused), Is.False);
            Assert.That(refused,                                                             Does.Contain(Why));
            Assert.That(added,                                                               Is.Empty);

        }

        /// <summary>
        /// A key whose line says it has expired lets nobody in any more.
        /// </summary>
        [Test]
        public void AnExpiredKeyLetsNobodyIn()
        {

            var key = SshHostKey.GenerateEd25519();

            Directory.CreateDirectory(directory);
            File.WriteAllText(Path.Combine(directory, "alice"),
                              "expiry-time=\"20200101\" " + SshPublicKey.FromHostKey(key, "alice").ToAuthorizedKeyLine() + "\n");

            Assert.That(new SSHAccounts(directory).Find("alice", key.PublicKeyBlob), Is.Null);

        }

    }

}
