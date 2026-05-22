// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Reflection;
using FluentAssertions;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Regression tests for the private <c>CERTInextCAPlugin.ExtractSerialFromPem</c>
    /// helper, which feeds the audit-log SerialNumber field.  After the BouncyCastle
    /// migration (replacing <c>X509Certificate2.SerialNumber</c>) we need to pin the
    /// format invariants — particularly the leading-zero-byte case where the old BCL
    /// behaviour and a naive <c>BigInteger.ToString(16)</c> diverge.
    /// </summary>
    public class ExtractSerialFromPemTests
    {
        private static string InvokeExtractSerialFromPem(string pem)
        {
            var method = typeof(CERTInextCAPlugin)
                .GetMethod("ExtractSerialFromPem", BindingFlags.NonPublic | BindingFlags.Static);
            method.Should().NotBeNull("test pins the format produced by ExtractSerialFromPem");
            return (string)method!.Invoke(null, new object[] { pem })!;
        }

        /// <summary>
        /// Generates a self-signed PEM cert with the specified serial number.  Uses
        /// BouncyCastle throughout — no BCL crypto — per the project's crypto policy.
        /// </summary>
        private static string GeneratePemWithSerial(BigInteger serial)
        {
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            AsymmetricCipherKeyPair keyPair = keyGen.GenerateKeyPair();

            var subject = new X509Name("CN=test-serial-parity");
            var notBefore = DateTime.UtcNow.AddMinutes(-1);
            var notAfter = notBefore.AddDays(1);

            var builder = new X509V3CertificateGenerator();
            builder.SetSerialNumber(serial);
            builder.SetIssuerDN(subject);
            builder.SetSubjectDN(subject);
            builder.SetNotBefore(notBefore);
            builder.SetNotAfter(notAfter);
            builder.SetPublicKey(keyPair.Public);

            var signerFactory = new Asn1SignatureFactory("SHA256withRSA", keyPair.Private);
            X509Certificate cert = builder.Generate(signerFactory);

            return "-----BEGIN CERTIFICATE-----\n"
                + Convert.ToBase64String(cert.GetEncoded(), Base64FormattingOptions.InsertLineBreaks)
                + "\n-----END CERTIFICATE-----";
        }

        [Fact]
        public void ExtractSerialFromPem_PreservesLeadingZeroByte()
        {
            // Serial bytes 0x00 0x0A 0xFF 0xFF as an unsigned big-endian integer = 720895
            // X509Certificate2.SerialNumber would produce "0AFFFF" (sign byte stripped,
            // remaining bytes hex-encoded, leading-zero NIBBLE preserved within byte boundary).
            // A naive BigInteger.ToString(16) would produce "afff" (a 4-digit hex, dropping
            // the leading zero nibble), which mis-correlates with Command's stored serial.
            //
            // Use a serial that has a leading-zero nibble in its first non-zero byte:
            // 0x0A123456 → unsigned hex "0A123456" (8 nibbles). Anything that drops the
            // leading zero produces "A123456" (7 nibbles).
            var serial = new BigInteger("0A123456", 16);
            string pem = GeneratePemWithSerial(serial);

            string result = InvokeExtractSerialFromPem(pem);

            result.Should().Be("0A123456",
                "the serial must preserve the leading-zero nibble within its first byte " +
                "so audit-log correlation against Command's stored serial succeeds");
        }

        [Fact]
        public void ExtractSerialFromPem_NormalSerial_UppercaseHexNoLeadingZero()
        {
            // Plain mid-range serial; just confirms format is uppercase hex without separators.
            var serial = new BigInteger("DEADBEEFCAFE", 16);
            string pem = GeneratePemWithSerial(serial);

            string result = InvokeExtractSerialFromPem(pem);

            result.Should().Be("DEADBEEFCAFE");
        }

        [Fact]
        public void ExtractSerialFromPem_LongSerial_AllBytesPreservedUppercase()
        {
            // 20-byte serial (the max CA/B Forum permits).  Each byte must be uppercase
            // hex, no separators, no leading-zero loss.
            var serial = new BigInteger("01020304050607080910111213141516171819FA", 16);
            string pem = GeneratePemWithSerial(serial);

            string result = InvokeExtractSerialFromPem(pem);

            result.Should().Be("01020304050607080910111213141516171819FA");
        }

        [Fact]
        public void ExtractSerialFromPem_GarbageInput_ReturnsParseError()
        {
            // Robustness — audit-log path must never throw, only mark the failure.
            InvokeExtractSerialFromPem("not a pem")
                .Should().Be("(parse-error)");
        }

        [Fact]
        public void ExtractSerialFromPem_EmptyBody_ReturnsEmptyPem()
        {
            InvokeExtractSerialFromPem("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----")
                .Should().Be("(empty-pem)");
        }
    }
}
