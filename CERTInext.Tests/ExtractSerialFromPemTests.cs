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

        /// <summary>
        /// Functional coverage for the minimal chain-PEM shape (acceptance criterion: "leaf +
        /// intermediate chain PEM -> the leaf's serial"), built the same way V2 enroll/sync
        /// assemble it (<c>AssembleV2CertChain</c>: leaf PEM, then each intermediate PEM
        /// appended after a newline, each block keeping its own BEGIN/END markers and base64
        /// padding). Whether this specific 2-block combination reproduces the pre-fix
        /// "(parse-error)" bug depends on the leaf's DER byte length modulo 3 (whether its
        /// base64 body needs '=' padding) — see
        /// <see cref="ExtractSerialFromPem_LeafPlusTwoIntermediatesChainPem_ReturnsLeafSerial"/>
        /// for the deterministic reproduction of issue 0050 (matches the live gateway log's
        /// ChainPemCount=2 evidence). Both must return the leaf's serial, never the
        /// intermediate's.
        /// </summary>
        [Fact]
        public void ExtractSerialFromPem_LeafPlusIntermediateChainPem_ReturnsLeafSerial()
        {
            var leafSerial = new BigInteger("7994334872", 10);
            var intermediateSerial = new BigInteger("00E0353B0E133906D77D5137E5E5D6A1", 16);

            string leafPem = GeneratePemWithSerial(leafSerial);
            string intermediatePem = GeneratePemWithSerial(intermediateSerial);

            // Mirrors CERTInextCAPlugin.AssembleV2CertChain: leaf.TrimEnd() + "\n" + intermediate.TrimEnd().
            string chainPem = leafPem.TrimEnd() + "\n" + intermediatePem.TrimEnd();

            string result = InvokeExtractSerialFromPem(chainPem);

            result.Should().Be(Convert.ToHexString(leafSerial.ToByteArrayUnsigned()).ToUpperInvariant(),
                "the audit log must report the leaf certificate's serial, matching what Command records");
            result.Should().NotBe(Convert.ToHexString(intermediateSerial.ToByteArrayUnsigned()).ToUpperInvariant(),
                "the intermediate's serial must never be mistaken for the leaf's");
        }

        /// <summary>
        /// Regression for issue 0050: leaf + two intermediates (three PEM blocks total),
        /// matching the live gateway log evidence (ChainPemCount=2, both V2 reissue
        /// enrollments logged "SerialNumber=(parse-error)"). Deterministically reproduces
        /// the pre-fix bug — verified by reverting <c>ExtractSerialFromPem</c> to its
        /// pre-fix body and confirming this test fails with "(parse-error)" while the other
        /// tests in this class still pass, across repeated runs (ruling out flakiness from
        /// the fresh RSA key generated per run).
        /// </summary>
        [Fact]
        public void ExtractSerialFromPem_LeafPlusTwoIntermediatesChainPem_ReturnsLeafSerial()
        {
            var leafSerial = new BigInteger("9817499991", 10);
            var intermediateSerial1 = new BigInteger("00FEABDFF1B29657D9AF75ABC6CDCAAE", 16);
            var intermediateSerial2 = new BigInteger("DEADBEEF", 16);

            string leafPem = GeneratePemWithSerial(leafSerial);
            string intermediatePem1 = GeneratePemWithSerial(intermediateSerial1);
            string intermediatePem2 = GeneratePemWithSerial(intermediateSerial2);

            string chainPem = leafPem.TrimEnd() + "\n" + intermediatePem1.TrimEnd() + "\n" + intermediatePem2.TrimEnd();

            string result = InvokeExtractSerialFromPem(chainPem);

            result.Should().Be(Convert.ToHexString(leafSerial.ToByteArrayUnsigned()).ToUpperInvariant());
        }
    }
}
