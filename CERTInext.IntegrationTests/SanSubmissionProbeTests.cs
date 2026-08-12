// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// At http://www.apache.org/licenses/LICENSE-2.0
//
// Probe: establish empirically how CERTInext treats the SAN/domain fields on
// GenerateOrderSSL. Written because the plugin's original behaviour encoded three
// assumptions that were never measured:
//
//   A. certificateInformation.additionalDomains is the field that puts extra names on
//      the certificate (so a UCC order that omits it yields a CN-only certificate).
//   B. additionalDomains accepts DNS names only, so a non-DNS SAN is rejected by the CA.
//   C. Repeating the primary domainName inside additionalDomains is harmful (duplicate
//      domain / consumes the UCC allowance), so it should be de-duplicated.
//
// None of these had a test. This probe answers them against the live API by placing one
// order per variant and reading back the domain set CERTInext actually registered, via
// TrackOrder's domainVerification block (keys are the domains on the order). That is
// ground truth for "which names did the CA put on this order" without waiting for DCV
// and issuance to complete.
//
// ---------------------------------------------------------------------------------------
// MEASURED RESULTS — SANDBOX ONLY: sandbox-us, account 4951571271, product 844 (OV SSL UCC),
// 2026-08-12. (Product 840 / DV UCC is not enabled on that account: "Invalid Product Code".)
//
// These are sandbox observations. Re-run against production before treating B or C as
// settled there — point ~/.env_certinext at the production account and set
// CERTINEXT_SAN_PROBE_PRODUCTS to a UCC code that account can actually order (product
// numbering is per-account; the codes in Constants.Products are defaults, not guarantees).
// Finding A and the CSR-SAN result below are separately corroborated by production: the
// customer report that prompted this work was a production UCC order whose CSR carried the
// SANs and whose issued certificate held only the CN.
//
//   A. CONFIRMED. additionalDomains is what puts extra names on the order. Submitting
//      CN + extra1.<cn> registered BOTH domains.
//
//   B. DISPROVEN. Non-DNS values are NOT rejected. An email address, an IPv4 literal and
//      an https:// URI were each accepted at placement AND registered as order domains
//      ("san-probe@example.com", "192.0.2.10", "https://san-probe.example.com/x" all came
//      back as domainVerification keys). So the CA does not validate the field's contents
//      at order time; such an order is created and then cannot pass DCV, rather than
//      failing cleanly up front.
//
//   C. PARTLY DISPROVEN. Repeating the primary domainName inside additionalDomains is
//      accepted and CERTInext collapses it itself — the order came back with the CN
//      registered once. De-duplicating on our side is therefore belt-and-braces, not a
//      correctness requirement.
//
//   Root cause of the customer-reported "UCC SANs not populating": CERTInext IGNORES the
//   subjectAltName extension in the CSR. A CSR carrying CN + extra2.<cn>, submitted with
//   additionalDomains omitted, registered ONLY the CN. SANs must be sent in
//   additionalDomains or they do not reach the certificate, no matter what the CSR says.
// ---------------------------------------------------------------------------------------
//
// Opt-in: this places real orders against whatever account ~/.env_certinext points at.
//
//   set -a; . ~/.env_certinext; set +a
//   export CERTINEXT_SAN_PROBE=1
//   dotnet test CERTInext.IntegrationTests/CERTInext.IntegrationTests.csproj -c Release \
//     --filter "FullyQualifiedName~SanSubmissionProbeTests" \
//     --logger "console;verbosity=detailed" > /tmp/sanprobe.log 2>&1
//
// (xUnit buffers ITestOutputHelper output until the test ends — read the report at the tail.)

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    public class SanSubmissionProbeTests : IClassFixture<IntegrationTestFixture>
    {
        private const string OptInFlag = "CERTINEXT_SAN_PROBE";

        /// <summary>
        /// Comma-separated product codes to probe. Defaults to the Multi-Domain (UCC) codes,
        /// because additional domains are only meaningful on a UCC product — a single-domain
        /// product (e.g. 842 = OV SSL) registers the CN and nothing else no matter what
        /// additionalDomains contains, which makes it useless as a probe target.
        /// </summary>
        private const string ProductCodesFlag = "CERTINEXT_SAN_PROBE_PRODUCTS";
        private const string DefaultProductCodes = "840,844";

        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _out;

        public SanSubmissionProbeTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _out = output;
        }

        // -------------------------------------------------------------------------
        // CSR generation (BouncyCastle — project crypto policy)
        // -------------------------------------------------------------------------

        /// <summary>
        /// Generates a PKCS#10 CSR for <paramref name="cn"/>, optionally carrying a
        /// subjectAltName extension (via the PKCS#9 extensionRequest attribute) holding
        /// <paramref name="dnsSans"/>. The SAN-bearing form is what lets this probe ask
        /// whether CERTInext reads SANs out of the CSR at all.
        /// </summary>
        private static string GenerateCsrPem(string cn, params string[] dnsSans)
        {
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            AsymmetricCipherKeyPair kp = keyGen.GenerateKeyPair();

            Asn1Set attributes = null;
            if (dnsSans != null && dnsSans.Length > 0)
            {
                var names = new GeneralNames(
                    dnsSans.Select(d => new GeneralName(GeneralName.DnsName, d)).ToArray());

                var extGen = new X509ExtensionsGenerator();
                extGen.AddExtension(X509Extensions.SubjectAlternativeName, critical: false, extValue: names);

                attributes = new DerSet(new AttributePkcs(
                    PkcsObjectIdentifiers.Pkcs9AtExtensionRequest,
                    new DerSet(extGen.Generate())));
            }

            var csr = new Pkcs10CertificationRequest(
                "SHA256withRSA", new X509Name($"CN={cn}"), kp.Public, attributes, kp.Private);

            return "-----BEGIN CERTIFICATE REQUEST-----\n"
                 + Convert.ToBase64String(csr.GetEncoded(), Base64FormattingOptions.InsertLineBreaks)
                 + "\n-----END CERTIFICATE REQUEST-----";
        }

        // -------------------------------------------------------------------------
        // One probe variant
        // -------------------------------------------------------------------------

        private sealed class ProbeOutcome
        {
            public string ProductCode;
            public string Label;
            public bool Accepted;
            public string OrderNumber;
            public string Detail;
            /// <summary>Domains CERTInext registered on the order, per TrackOrder.</summary>
            public List<string> RegisteredDomains = new List<string>();
            /// <summary>Names we asked CERTInext to put on the order, for comparison.</summary>
            public List<string> RequestedDomains = new List<string>();

            /// <summary>
            /// True when the rejection was "Invalid Product Code" — the product simply is not
            /// enabled on this account, which is not a data point about SAN handling.
            /// </summary>
            public bool ProductUnavailable;
        }

        /// <summary>
        /// Places one order and reads back the domain set CERTInext registered for it.
        /// <paramref name="sans"/> drives certificateInformation.additionalDomains;
        /// <paramref name="csrSans"/> drives the SAN extension inside the CSR. They are
        /// varied independently on purpose — that separation is the whole point of the probe.
        /// </summary>
        private async Task<ProbeOutcome> ProbeAsync(
            string productCode,
            string label,
            Func<string, List<SanEntry>> sansFactory,
            string[] csrSans)
        {
            var outcome = new ProbeOutcome { ProductCode = productCode, Label = label };

            var client = new CERTInextClient(_fixture.Config);
            string cn = $"sanprobe-{DateTime.UtcNow:yyyyMMddHHmmssfff}.{SafeLabel(label)}.example.com";

            var sans = sansFactory?.Invoke(cn);
            outcome.RequestedDomains = sans == null
                ? new List<string>()
                : sans.Select(s => $"{s.Type}:{s.Value}").ToList();

            var req = new EnrollCertificateRequest
            {
                Csr            = GenerateCsrPem(cn, csrSans == null ? null : csrSans.Select(s => Format(s, cn)).ToArray()),
                Subject        = $"CN={cn}",
                Sans           = sans,
                ProfileId      = productCode,
                RequesterName  = _fixture.RequestorName,
                RequesterEmail = _fixture.RequestorEmail
            };

            try
            {
                var resp = await client.EnrollCertificateAsync(req);
                outcome.Accepted = true;
                outcome.OrderNumber = resp?.Id;
                outcome.Detail = $"OrderNumber={resp?.Id} Status={resp?.Status}";
            }
            catch (Exception ex)
            {
                outcome.Accepted = false;
                outcome.Detail = ex.Message;
                outcome.ProductUnavailable =
                    ex.Message.IndexOf("Invalid Product Code", StringComparison.OrdinalIgnoreCase) >= 0;
                return outcome;
            }

            // Read back which domains the CA actually put on the order.
            try
            {
                var track = await client.TrackOrderAsync(outcome.OrderNumber);
                var entries = track.OrderDetails?.DomainVerification?.GetDomainEntries();
                if (entries != null)
                    outcome.RegisteredDomains = entries.Keys.OrderBy(k => k, StringComparer.OrdinalIgnoreCase).ToList();
            }
            catch (Exception ex)
            {
                outcome.Detail += $" | TrackOrder failed: {ex.Message}";
            }

            return outcome;
        }

        /// <summary>Substitutes the generated CN into a variant's placeholder template.</summary>
        private static string Format(string template, string cn) => template.Replace("{cn}", cn);

        private static string SafeLabel(string label) =>
            new string(label.ToLowerInvariant().Select(c => char.IsLetterOrDigit(c) ? c : '-').ToArray())
                .Trim('-');

        // -------------------------------------------------------------------------
        // The probe
        // -------------------------------------------------------------------------

        [SkippableFact]
        public async Task Probe_SanSubmissionBehaviour()
        {
            IntegrationSkip.IfNotConfigured(_fixture);
            Skip.IfNot(
                Environment.GetEnvironmentVariable(OptInFlag) == "1",
                $"Set {OptInFlag}=1 to run this probe — it places real orders on the configured account.");

            var variants = new List<(string Label, Func<string, List<SanEntry>> Sans, string[] CsrSans)>
            {
                // 1. Assumption A, positive control: additionalDomains carries an extra DNS
                //    name. If the extra name comes back registered, additionalDomains works.
                ("dns-extra-via-additionalDomains",
                    cn => new List<SanEntry>
                    {
                        new SanEntry { Type = "dns", Value = cn },
                        new SanEntry { Type = "dns", Value = $"extra1.{cn}" }
                    },
                    new[] { "{cn}", "extra1.{cn}" }),

                // 2. Assumption A, the actual bug: CSR carries both names, additionalDomains
                //    is omitted entirely. This is what v1.0.1 sent for every UCC enrollment.
                //    If only the CN comes back registered, the CA does NOT read CSR SANs and
                //    the diagnosis is confirmed.
                ("csr-sans-only-no-additionalDomains",
                    _ => null,
                    new[] { "{cn}", "extra2.{cn}" }),

                // 3. Assumption C: primary domainName repeated inside additionalDomains.
                //    Does the CA reject it, or silently collapse it?
                ("cn-duplicated-in-additionalDomains",
                    cn => new List<SanEntry>
                    {
                        new SanEntry { Type = "dns", Value = cn },
                        new SanEntry { Type = "dns", Value = cn }
                    },
                    new[] { "{cn}" }),

                // 4-6. Assumption B: non-DNS values in additionalDomains. Rejected, ignored,
                //      or accepted? Each is submitted alongside a valid DNS name so a rejection
                //      is attributable to the non-DNS value rather than an empty domain set.
                ("nondns-email-in-additionalDomains",
                    cn => new List<SanEntry>
                    {
                        new SanEntry { Type = "dns",   Value = cn },
                        new SanEntry { Type = "email", Value = "san-probe@example.com" }
                    },
                    new[] { "{cn}" }),

                ("nondns-ip-in-additionalDomains",
                    cn => new List<SanEntry>
                    {
                        new SanEntry { Type = "dns", Value = cn },
                        new SanEntry { Type = "ip",  Value = "192.0.2.10" }
                    },
                    new[] { "{cn}" }),

                ("nondns-uri-in-additionalDomains",
                    cn => new List<SanEntry>
                    {
                        new SanEntry { Type = "dns", Value = cn },
                        new SanEntry { Type = "uri", Value = "https://san-probe.example.com/x" }
                    },
                    new[] { "{cn}" }),
            };

            string[] productCodes =
                (Environment.GetEnvironmentVariable(ProductCodesFlag) ?? DefaultProductCodes)
                    .Split(',', StringSplitOptions.RemoveEmptyEntries)
                    .Select(p => p.Trim())
                    .Where(p => p.Length > 0)
                    .ToArray();

            var results = new List<ProbeOutcome>();
            foreach (string productCode in productCodes)
            {
                bool unavailable = false;
                foreach (var (label, sans, csrSans) in variants)
                {
                    var outcome = await ProbeAsync(productCode, label, sans, csrSans);
                    results.Add(outcome);

                    // Don't burn five more orders proving the same product code is not
                    // enabled on this account.
                    if (outcome.ProductUnavailable)
                    {
                        unavailable = true;
                        break;
                    }

                    // Throttle: the sandbox rate-limits order bursts (~16 orders / 10 s).
                    await Task.Delay(1500);
                }

                if (unavailable)
                    _out.WriteLine($"(product {productCode} is not enabled on this account — skipped)");
            }

            _out.WriteLine("=== CERTInext SAN submission probe ===");
            _out.WriteLine($"ProductCodes probed : {string.Join(", ", productCodes)}");
            _out.WriteLine($"(fixture default    : {_fixture.ProductCode})");
            _out.WriteLine("");

            foreach (var group in results.GroupBy(r => r.ProductCode))
            {
                _out.WriteLine($"--- ProductCode {group.Key} ---");
                foreach (var r in group)
                {
                    _out.WriteLine($"[{(r.Accepted ? "ACCEPTED" : "REJECTED")}] {r.Label}");
                    _out.WriteLine($"    requested (additionalDomains): {(r.RequestedDomains.Count > 0 ? string.Join(", ", r.RequestedDomains) : "(field omitted)")}");
                    _out.WriteLine($"    detail                       : {r.Detail}");
                    _out.WriteLine($"    registeredDomains (TrackOrder): {(r.RegisteredDomains.Count > 0 ? string.Join(", ", r.RegisteredDomains) : "(none reported)")}");
                    _out.WriteLine("");
                }
            }

            _out.WriteLine("=== How to read this ===");
            _out.WriteLine("registeredDomains is TrackOrder's domainVerification key set — the domains");
            _out.WriteLine("CERTInext put on the order. Compare it against 'requested':");
            _out.WriteLine("(1) vs (2): if (1) registers the extra name and (2) does not, then");
            _out.WriteLine("    additionalDomains is required and CSR SANs alone are ignored.");
            _out.WriteLine("(3)      : whether repeating the CN is rejected or collapsed.");
            _out.WriteLine("(4)-(6)  : whether non-DNS values are rejected, ignored, or accepted");
            _out.WriteLine("           AT PLACEMENT TIME. An order accepted here can still be");
            _out.WriteLine("           rejected later during validation/approval.");

            // The probe reports; it does not assert a specific CA behaviour, because its purpose
            // is to discover what that behaviour is. What must hold is that at least one UCC
            // product was actually exercised — otherwise the run proved nothing and should not
            // read as a pass.
            var usable = results
                .Where(r => !r.ProductUnavailable)
                .GroupBy(r => r.ProductCode)
                .ToList();

            Skip.If(
                usable.Count == 0,
                "None of the probed product codes are enabled on this account " +
                $"({string.Join(", ", productCodes)}). Set {ProductCodesFlag} to a Multi-Domain (UCC) " +
                "code this account can order.");

            foreach (var group in usable)
            {
                var control = group.First(r => r.Label == "dns-extra-via-additionalDomains");
                Assert.True(
                    control.Accepted,
                    $"Positive control failed on product {group.Key} — could not place even a " +
                    $"plain DNS UCC order: {control.Detail}");
            }
        }
    }
}
