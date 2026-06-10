// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// At http://www.apache.org/licenses/LICENSE-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Key-algorithm coverage matrix: RSA 2048/3072/4096/6144/8192, ECDSA P-256/P-384/P-521,
    /// Ed25519, and Ed448.
    ///
    /// Motivation: every other test in the suite hardcodes an RSA-2048 CSR, so only RSA-2048
    /// certificates were ever exercised end-to-end (and that is all that showed up in Command).
    /// The plugin takes the CSR as enrollment input and submits it verbatim, so the key
    /// algorithm is entirely determined by the CSR. These tests parameterise CSR generation
    /// (BouncyCastle — never BCL crypto) across the full matrix.
    ///
    /// Two layers, matching the agreed scope (submission / CSR-validity only — no DCV, no issuance):
    ///   1. <see cref="Csr_RoundTripsKeyAlgorithm"/> — deterministic, no API, always runs. Proves we
    ///      emit a structurally valid, self-consistent PKCS#10 CSR for each algorithm (the public key
    ///      type/size round-trips and the request signature verifies).
    ///   2. <see cref="Enroll_AcceptsKeyAlgorithm"/> — opt-in (creates real sandbox orders). Proves
    ///      whether CERTInext *accepts* each algorithm at order submission. A CA-side rejection
    ///      (e.g. "algorithm not supported") is reported as an explicit Skip carrying the CA's own
    ///      message, so the suite documents real CA support rather than failing on a CA limitation.
    ///
    /// Caveat: "accepted at submission" is weaker than "will issue". A public CA may accept the
    /// order and only reject an exotic key (Ed25519/Ed448, very large RSA) at issuance, after DCV.
    /// End-to-end issuance per algorithm would require the DCV build + a Cloudflare round per order.
    /// </summary>
    public class AlgorithmMatrixTests : IClassFixture<IntegrationTestFixture>
    {
        /// <summary>Set <c>CERTINEXT_ALGO_MATRIX=1</c> to run the live submission theory (creates real orders).</summary>
        private const string OptInFlag = "CERTINEXT_ALGO_MATRIX";

        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;

        public AlgorithmMatrixTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output = output;
        }

        // ---------------------------------------------------------------------------
        // Key-algorithm specifications
        // ---------------------------------------------------------------------------

        private enum KeyKind { Rsa, Ecdsa, Ed25519, Ed448 }

        private sealed class KeySpec
        {
            public string Tag;                 // stable, human-readable id ("RSA-2048", "ECDSA-P256", ...)
            public KeyKind Kind;
            public int Strength;               // RSA modulus bits, or EC field size in bits (informational for Ed)
            public string SignatureAlgorithm;  // BouncyCastle signature-algorithm name for the CSR
            public DerObjectIdentifier CurveOid; // EC named-curve OID (null for non-EC)
        }

        // CA/Baseline-Requirements hash pairing: P-256→SHA256, P-384→SHA384, P-521→SHA512.
        private static readonly KeySpec[] Specs =
        {
            new() { Tag = "RSA-2048",   Kind = KeyKind.Rsa, Strength = 2048, SignatureAlgorithm = "SHA256withRSA" },
            new() { Tag = "RSA-3072",   Kind = KeyKind.Rsa, Strength = 3072, SignatureAlgorithm = "SHA256withRSA" },
            new() { Tag = "RSA-4096",   Kind = KeyKind.Rsa, Strength = 4096, SignatureAlgorithm = "SHA256withRSA" },
            new() { Tag = "RSA-6144",   Kind = KeyKind.Rsa, Strength = 6144, SignatureAlgorithm = "SHA256withRSA" },
            new() { Tag = "RSA-8192",   Kind = KeyKind.Rsa, Strength = 8192, SignatureAlgorithm = "SHA256withRSA" },
            new() { Tag = "ECDSA-P256", Kind = KeyKind.Ecdsa, Strength = 256, SignatureAlgorithm = "SHA256withECDSA", CurveOid = SecObjectIdentifiers.SecP256r1 },
            new() { Tag = "ECDSA-P384", Kind = KeyKind.Ecdsa, Strength = 384, SignatureAlgorithm = "SHA384withECDSA", CurveOid = SecObjectIdentifiers.SecP384r1 },
            new() { Tag = "ECDSA-P521", Kind = KeyKind.Ecdsa, Strength = 521, SignatureAlgorithm = "SHA512withECDSA", CurveOid = SecObjectIdentifiers.SecP521r1 },
            new() { Tag = "Ed25519",    Kind = KeyKind.Ed25519, Strength = 256, SignatureAlgorithm = "Ed25519" },
            new() { Tag = "Ed448",      Kind = KeyKind.Ed448, Strength = 448, SignatureAlgorithm = "Ed448" },
        };

        private static KeySpec SpecFor(string tag) => Specs.Single(s => s.Tag == tag);

        /// <summary>xUnit member-data source — one row per key type, keyed by its stable tag.</summary>
        public static IEnumerable<object[]> KeyTypes => Specs.Select(s => new object[] { s.Tag });

        // ---------------------------------------------------------------------------
        // CSR generation (BouncyCastle)
        // ---------------------------------------------------------------------------

        private static AsymmetricCipherKeyPair GenerateKeyPair(KeySpec spec)
        {
            switch (spec.Kind)
            {
                case KeyKind.Rsa:
                {
                    var gen = new RsaKeyPairGenerator();
                    gen.Init(new KeyGenerationParameters(new SecureRandom(), spec.Strength));
                    return gen.GenerateKeyPair();
                }
                case KeyKind.Ecdsa:
                {
                    var gen = new ECKeyPairGenerator("ECDSA");
                    gen.Init(new ECKeyGenerationParameters(spec.CurveOid, new SecureRandom()));
                    return gen.GenerateKeyPair();
                }
                case KeyKind.Ed25519:
                {
                    var gen = new Ed25519KeyPairGenerator();
                    gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
                    return gen.GenerateKeyPair();
                }
                case KeyKind.Ed448:
                {
                    var gen = new Ed448KeyPairGenerator();
                    gen.Init(new Ed448KeyGenerationParameters(new SecureRandom()));
                    return gen.GenerateKeyPair();
                }
                default:
                    throw new ArgumentOutOfRangeException(nameof(spec), spec.Kind, "unhandled key kind");
            }
        }

        private static string GenerateCsrPem(string commonName, KeySpec spec)
        {
            var keyPair = GenerateKeyPair(spec);
            var subject = new X509Name($"CN={commonName}");
            var csr = new Pkcs10CertificationRequest(spec.SignatureAlgorithm, subject, keyPair.Public, null, keyPair.Private);

            return "-----BEGIN CERTIFICATE REQUEST-----\n"
                + Convert.ToBase64String(csr.GetEncoded(), Base64FormattingOptions.InsertLineBreaks)
                + "\n-----END CERTIFICATE REQUEST-----";
        }

        private static byte[] DerFromPem(string pem)
        {
            var b64 = pem
                .Replace("-----BEGIN CERTIFICATE REQUEST-----", string.Empty)
                .Replace("-----END CERTIFICATE REQUEST-----", string.Empty)
                .Replace("\r", string.Empty)
                .Replace("\n", string.Empty)
                .Trim();
            return Convert.FromBase64String(b64);
        }

        // ---------------------------------------------------------------------------
        // Layer 1 — deterministic CSR-validity round-trip (no API, always runs)
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Generates a CSR for the given key type, re-parses it, and asserts the public key
        /// algorithm/size round-trips and the request signature verifies. Fully offline.
        ///
        /// Note: RSA-6144 and RSA-8192 key generation is intentionally slow (seconds to tens of
        /// seconds) — that cost is inherent to large RSA keygen, not the test.
        /// </summary>
        [Theory]
        [MemberData(nameof(KeyTypes))]
        public void Csr_RoundTripsKeyAlgorithm(string tag)
        {
            var spec = SpecFor(tag);

            string pem = GenerateCsrPem($"algo-{tag.ToLowerInvariant().Replace("-", string.Empty)}.example.com", spec);

            var request = new Pkcs10CertificationRequest(DerFromPem(pem));

            request.Verify().Should().BeTrue($"the {tag} CSR must be self-signed with a verifiable signature");

            var pub = request.GetPublicKey();

            switch (spec.Kind)
            {
                case KeyKind.Rsa:
                    pub.Should().BeOfType<RsaKeyParameters>();
                    // BouncyCastle generates a modulus of exactly 'Strength' bits (top bit set).
                    ((RsaKeyParameters)pub).Modulus.BitLength.Should().Be(spec.Strength,
                        $"the RSA modulus must be {spec.Strength} bits");
                    break;

                case KeyKind.Ecdsa:
                    pub.Should().BeOfType<ECPublicKeyParameters>();
                    ((ECPublicKeyParameters)pub).Parameters.Curve.FieldSize.Should().Be(spec.Strength,
                        $"the EC field size must be {spec.Strength} bits");
                    break;

                case KeyKind.Ed25519:
                    pub.Should().BeOfType<Ed25519PublicKeyParameters>();
                    break;

                case KeyKind.Ed448:
                    pub.Should().BeOfType<Ed448PublicKeyParameters>();
                    break;
            }

            _output.WriteLine($"[OK] {tag}: CSR generated ({pem.Length} chars PEM), signature verified, public key type confirmed.");
        }

        // ---------------------------------------------------------------------------
        // Layer 2 — live submission acceptance (opt-in; creates real sandbox orders)
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Submits a real order to CERTInext for each key type and asserts the order is accepted
        /// (a CARequestID is returned). A CA-side rejection is reported as an explicit Skip carrying
        /// the CA's own error message — so the suite documents which algorithms CERTInext accepts
        /// rather than failing on a legitimate CA limitation.
        ///
        /// Opt-in: requires <c>CERTINEXT_ALGO_MATRIX=1</c> because each run creates a real (pending,
        /// non-issued) DV order on the sandbox account. No DCV is performed, so the orders park at
        /// EXTERNALVALIDATION and are not cleaned up here.
        /// </summary>
        [SkippableTheory]
        [MemberData(nameof(KeyTypes))]
        public async Task Enroll_AcceptsKeyAlgorithm(string tag)
        {
            IntegrationSkip.IfNotConfigured(_fixture);
            Skip.IfNot(
                Environment.GetEnvironmentVariable(OptInFlag) == "1",
                $"Set {OptInFlag}=1 to run the live algorithm-submission matrix (creates real sandbox orders).");

            var spec = SpecFor(tag);
            string cn = $"algo-{tag.ToLowerInvariant().Replace("-", string.Empty)}.example.com";
            string csrPem = GenerateCsrPem(cn, spec);

            var productInfo = new EnrollmentProductInfo
            {
                ProductID = _fixture.ProductCode,
                ProductParameters = new Dictionary<string, string>
                {
                    [Constants.EnrollmentParam.ProfileId]      = _fixture.ProductCode,
                    [Constants.EnrollmentParam.ProductCode]    = _fixture.ProductCode,
                    [Constants.EnrollmentParam.RequesterName]  = _fixture.RequestorName,
                    [Constants.EnrollmentParam.RequesterEmail] = _fixture.RequestorEmail,
                }
            };

            var sanDict = new Dictionary<string, string[]> { ["DNS"] = new[] { cn } };

            var plugin = new CERTInextCAPlugin(_fixture.Client, _fixture.Config);

            EnrollmentResult enrollResult = null;
            try
            {
                enrollResult = await plugin.Enroll(
                    csrPem,
                    $"CN={cn}",
                    sanDict,
                    productInfo,
                    RequestFormat.PKCS10,
                    EnrollmentType.New);
            }
            catch (Exception ex)
            {
                // Per agreed scope: a CA-side rejection (algorithm not supported, or other
                // account/provisioning gap) becomes an explicit Skip carrying the CA's message,
                // so the matrix documents real CERTInext support without a hard failure.
                _output.WriteLine($"[SKIP] {tag}: CERTInext rejected submission — {ex.Message}");
                Skip.If(true,
                    $"CERTInext did not accept a {tag} order. This may be an unsupported key algorithm " +
                    $"or an account/provisioning limitation. CA message: {ex.Message}");
            }

            enrollResult.Should().NotBeNull($"{tag}: Enroll must return a non-null result when accepted");
            if (enrollResult == null) return; // satisfies nullable analysis; assertion above already failed

            enrollResult.CARequestID.Should().NotBeNullOrWhiteSpace(
                $"{tag}: a CARequestID must be returned when CERTInext accepts the order");

            _output.WriteLine($"[OK] {tag}: CERTInext accepted the order. CARequestID={enrollResult.CARequestID}");
        }
    }
}
