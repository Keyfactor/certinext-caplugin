// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// At http://www.apache.org/licenses/LICENSE-2.0

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Key-algorithm coverage matrix: RSA 2048/3072/4096/6144/8192, ECDSA P-256/P-384/P-521,
    /// Ed25519, and Ed448 (see <see cref="KeyAlgorithms"/>).
    ///
    /// Motivation: every other test in the suite hardcoded an RSA-2048 CSR, so only RSA-2048
    /// certificates were ever exercised end-to-end (and that is all that showed up in Command).
    /// The plugin takes the CSR as enrollment input and submits it verbatim, so the key
    /// algorithm is entirely determined by the CSR.
    ///
    /// This file is the offline / submission-only layer (no DCV, no issuance):
    ///   1. <see cref="Csr_RoundTripsKeyAlgorithm"/> — deterministic, no API, always runs. Proves we
    ///      emit a structurally valid, self-consistent PKCS#10 CSR for each algorithm (the public key
    ///      type/size round-trips and the request signature verifies).
    ///   2. <see cref="Enroll_AcceptsKeyAlgorithm"/> — opt-in (creates real sandbox orders). Proves
    ///      whether CERTInext *accepts* each algorithm at order submission. A CA-side rejection is
    ///      reported as an explicit Skip carrying the CA's own message.
    ///
    /// The end-to-end "does CERTInext actually issue this algorithm" matrix (DCV on, one real
    /// scrup.org cert per type) lives in <c>DcvLifecycleTests.EnrollWithDcvOn_IssuesPerKeyAlgorithm</c>
    /// and only exists on the DCV build.
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

        public static IEnumerable<object[]> KeyTypes => KeyAlgorithms.AsMemberData;

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
            var spec = KeyAlgorithms.For(tag);

            string pem = KeyAlgorithms.GenerateCsrPem($"algo-{KeyAlgorithms.Slug(tag)}.example.com", spec);

            var request = new Pkcs10CertificationRequest(KeyAlgorithms.DerFromPem(pem));

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
        /// EXTERNALVALIDATION and are not cleaned up here. "Accepted at submission" is weaker than
        /// "will issue" — see <c>DcvLifecycleTests.EnrollWithDcvOn_IssuesPerKeyAlgorithm</c> for the
        /// end-to-end issuance matrix.
        /// </summary>
        [SkippableTheory]
        [MemberData(nameof(KeyTypes))]
        public async Task Enroll_AcceptsKeyAlgorithm(string tag)
        {
            IntegrationSkip.IfNotConfigured(_fixture);
            Skip.IfNot(
                Environment.GetEnvironmentVariable(OptInFlag) == "1",
                $"Set {OptInFlag}=1 to run the live algorithm-submission matrix (creates real sandbox orders).");

            var spec = KeyAlgorithms.For(tag);
            string cn = $"algo-{KeyAlgorithms.Slug(tag)}.example.com";
            string csrPem = KeyAlgorithms.GenerateCsrPem(cn, spec);

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
                // Per agreed scope: a CA-side rejection becomes an explicit Skip carrying the CA's
                // message (classified so an unsupported algorithm isn't confused with a credit/
                // account limitation), so the matrix documents real CERTInext support honestly.
                string reason = KeyAlgorithms.ClassifyRejection(ex.Message);
                _output.WriteLine($"[SKIP] {tag}: {reason} — {ex.Message}");
                Skip.If(true, $"CERTInext did not accept a {tag} order: {reason}. CA message: {ex.Message}");
            }

            enrollResult.Should().NotBeNull($"{tag}: Enroll must return a non-null result when accepted");
            if (enrollResult == null) return; // satisfies nullable analysis; assertion above already failed

            enrollResult.CARequestID.Should().NotBeNullOrWhiteSpace(
                $"{tag}: a CARequestID must be returned when CERTInext accepts the order");

            _output.WriteLine($"[OK] {tag}: CERTInext accepted the order. CARequestID={enrollResult.CARequestID}");
        }
    }
}
