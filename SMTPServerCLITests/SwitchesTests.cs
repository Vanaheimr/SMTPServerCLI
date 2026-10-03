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

namespace org.GraphDefined.Vanaheimr.Hermod.SMTP.CLI.Tests
{

    /// <summary>
    /// What the switches make of the settings, and which of them end the
    /// program before it starts - with 2, and a sentence on the error stream.
    /// </summary>
    [TestFixture]
    public class SwitchesTests
    {

        private static (Int32? ExitCode, ServerSettings Settings) Parse(params String[] Arguments)
        {

            var settings  = new ServerSettings();
            var error     = Console.Error;

            try
            {
                Console.SetError(TextWriter.Null);
                return (Program.Parse(Arguments, settings), settings);
            }
            finally
            {
                Console.SetError(error);
            }

        }


        /// <summary>
        /// The switches of a real start end up in the settings, and the DKIM
        /// domain is the domain the mail is from - the first local one.
        /// </summary>
        [Test]
        public void TheSwitchesOfARealStartEndUpInTheSettings()
        {

            var (exitCode, settings) = Parse("--hostname",          "Mail.Example.org.",
                                             "--local-domain",      "example.org",
                                             "--local-domain",      "example.net",
                                             "--port",              "25",
                                             "--submission-port",   "587",
                                             "--implicit-tls-port", "465",
                                             "--smarthost",         "relay.example.net:2525",
                                             "--smarthost-user",    "me",
                                             "--smarthost-password","secret",
                                             "--ssh-port",          "2222",
                                             "--ssh-any",
                                             "--quiet");

            Assert.Multiple(() => {
                Assert.That(exitCode,                    Is.Null);
                Assert.That(settings.Hostname,           Is.EqualTo("mail.example.org"));
                Assert.That(settings.DkimDomain,         Is.EqualTo("example.org"));
                Assert.That(settings.LocalDomains,       Is.EquivalentTo(new[] { "example.org", "example.net" }));
                Assert.That(settings.Port,               Is.EqualTo(25));
                Assert.That(settings.SubmissionPort,     Is.EqualTo(587));
                Assert.That(settings.ImplicitTlsPort,    Is.EqualTo(465));
                Assert.That(settings.SmartHost,          Is.EqualTo("relay.example.net"));
                Assert.That(settings.SmartHostPort,      Is.EqualTo(2525));
                Assert.That(settings.SSHPort,            Is.EqualTo(2222));
                Assert.That(settings.SSHAnyAddress,      Is.True);
                Assert.That(settings.ConsoleLogLevel,    Is.EqualTo(LogLevel.Warning));
            });

        }

        /// <summary>
        /// The DKIM domain: what --dkim-domain says; else the first local
        /// domain other than localhost; else the hostname.
        /// </summary>
        [TestCase(new[] { "--hostname", "mail.example.org", "--dkim-domain", "Example.NET." },                  "example.net")]
        [TestCase(new[] { "--hostname", "mail.example.org", "--local-domain", "example.org" },                  "example.org")]
        [TestCase(new[] { "--local-domain", "localhost", "--local-domain", "b.example", "--local-domain", "a.example" }, "b.example")]
        [TestCase(new[] { "--hostname", "mail.example.org", "--local-domain", "localhost" },                    "mail.example.org")]
        [TestCase(new[] { "--hostname", "mail.example.org" },                                                   "mail.example.org")]
        [TestCase(new String[0],                                                                                "localhost")]
        public void TheDkimDomainIsTheDomainTheMailIsFrom(String[] Arguments, String Expected)

            => Assert.That(Parse(Arguments).Settings.DkimDomain, Is.EqualTo(Expected));

        [Test]
        public void AnAuthorizedKeyIsRememberedForTheStart()
        {

            var (exitCode, settings) = Parse("--authorize-ssh-key", "alice=keys/alice.pub", "--no-ssh");

            Assert.Multiple(() => {
                Assert.That(exitCode,                    Is.Null);
                Assert.That(settings.AuthorizeSSHKeys,   Is.EqualTo(new[] { ("alice", "keys/alice.pub") }));
                Assert.That(settings.SSHEnabled,         Is.False);
            });

        }

        [TestCase("--help")]
        [TestCase("-h")]
        [TestCase("--version")]
        public void HelpAndVersionEndWithZero(String Switch)
        {

            var output = Console.Out;

            try
            {
                Console.SetOut(TextWriter.Null);
                Assert.That(Parse(Switch).ExitCode, Is.EqualTo(0));
            }
            finally
            {
                Console.SetOut(output);
            }

        }

        [TestCase("--bogus")]
        [TestCase("--port")]
        [TestCase("--port", "0")]
        [TestCase("--port", "65536")]
        [TestCase("--port", "abc")]
        [TestCase("--port", "2587")]                                       // the submission port's default
        [TestCase("--ssh-port", "2525")]                                   // the MTA port's default
        [TestCase("--smarthost", "relay:none")]
        [TestCase("--smarthost-user", "me")]                               // without a password
        [TestCase("--dkim-selector", "bad selector")]
        [TestCase("--log-level", "loud")]
        [TestCase("--authorize-ssh-key", "nokey")]
        [TestCase("--authorize-ssh-key", "../x=file.pub")]
        [TestCase("--certificate", "there-is-no-such-file.pfx")]
        public void WhatMakesNoSenseEndsWithTwo(params String[] Arguments)

            => Assert.That(Parse(Arguments).ExitCode, Is.EqualTo(2));

    }

}
