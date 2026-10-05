// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// At http://www.apache.org/licenses/LICENSE-2.0
//
// Probe: reproduce the kfclab gateway's "Inactive Account User." failure on
// PlaceOrder by submitting the exact field shape kfclab sends. Then flip one
// field at a time back to the integration-test default to isolate which
// individual field trips the CERTInext error.
//
// Baseline integration test config (proven to work — created order 7518968666):
//   SignerIp              = "127.0.0.1"
//   SignerPlace           = "Gateway"
//   RequestorMobileNumber = "0000000000"
//   RequestorIsdCode      = "1"
//
// kfclab gateway config:
//   SignerIp              = "0.0.0.0"
//   SignerPlace           = "Lab"
//   RequestorMobileNumber = ""        (unset → empty string on the wire)
//   RequestorIsdCode      = ""        (unset → plugin defaults to "1")
//
// Run with: dotnet test --filter FullyQualifiedName~KfclabFieldProbeTests

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Keyfactor.Extensions.CAPlugin.CERTInext;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    public class KfclabFieldProbeTests : IClassFixture<IntegrationTestFixture>
    {
        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _out;

        public KfclabFieldProbeTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _out = output;
        }

        private static string GenerateCsrPem(string cn)
        {
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            var kp = keyGen.GenerateKeyPair();
            var csr = new Pkcs10CertificationRequest(
                "SHA256withRSA", new X509Name($"CN={cn}"), kp.Public, null, kp.Private);
            return "-----BEGIN CERTIFICATE REQUEST-----\n"
                 + Convert.ToBase64String(csr.GetEncoded(), Base64FormattingOptions.InsertLineBreaks)
                 + "\n-----END CERTIFICATE REQUEST-----";
        }

        private CERTInextConfig BuildConfig(
            string signerIp,
            string signerPlace,
            string mobile,
            string isdCode,
            string requestorName)
        {
            return new CERTInextConfig
            {
                ApiUrl              = _fixture.ApiUrl.TrimEnd('/') + "/",
                AuthMode            = "AccessKey",
                ApiKey              = _fixture.AccessKey,
                AccountNumber       = _fixture.AccountNumber,
                GroupNumber         = _fixture.GroupNumber,
                OrganizationNumber  = _fixture.OrgNumber,
                RequestorName       = requestorName,
                RequestorEmail      = _fixture.RequestorEmail,
                RequestorIsdCode    = isdCode,
                RequestorMobileNumber = mobile,
                SignerPlace         = signerPlace,
                SignerIp            = signerIp,
                DefaultProductCode  = "842",
                PageSize            = 100
            };
        }

        private async Task<(bool ok, string detail)> TryEnrollAsync(CERTInextConfig cfg, string label)
        {
            var client = new CERTInextClient(cfg);
            string cn = $"probe-{label}-{DateTime.UtcNow:yyyyMMddHHmmss}.lab.example.com";
            string csr = GenerateCsrPem(cn);

            var req = new EnrollCertificateRequest
            {
                Csr            = csr,
                Subject        = $"CN={cn}",
                Sans           = new List<SanEntry> { new SanEntry { Type = "DNS", Value = cn } },
                ProfileId      = "842",
                RequesterName  = cfg.RequestorName,
                RequesterEmail = cfg.RequestorEmail,
            };

            try
            {
                var resp = await client.EnrollCertificateAsync(req);
                return (true, $"OrderNumber={resp?.Id} Status={resp?.Status}");
            }
            catch (Exception ex)
            {
                return (false, ex.Message);
            }
        }

        // Run each variant in a single fact so we get one consolidated report.
        [SkippableFact]
        public async Task Probe_FieldByField()
        {
            IntegrationSkip.IfNotConfigured(_fixture);

            // 1. baseline: integration-test config (known good)
            var baseline = BuildConfig(
                signerIp:      "127.0.0.1",
                signerPlace:   "Gateway",
                mobile:        "0000000000",
                isdCode:       "1",
                requestorName: _fixture.RequestorName);

            // 2. kfclab exact
            var kfclab = BuildConfig(
                signerIp:      "0.0.0.0",
                signerPlace:   "Lab",
                mobile:        "",
                isdCode:       "",
                requestorName: "Keyfactor Plugin Test"); // no quotes

            // 3..n. baseline-but-one-field-set-to-kfclab-value
            var bSignerIp   = BuildConfig("0.0.0.0",  "Gateway", "0000000000", "1", _fixture.RequestorName);
            var bSignerPlc  = BuildConfig("127.0.0.1", "Lab",    "0000000000", "1", _fixture.RequestorName);
            var bMobile     = BuildConfig("127.0.0.1", "Gateway", "",         "1", _fixture.RequestorName);
            var bIsd        = BuildConfig("127.0.0.1", "Gateway", "0000000000", "", _fixture.RequestorName);
            var bReqName    = BuildConfig("127.0.0.1", "Gateway", "0000000000", "1", "Keyfactor Plugin Test");

            var probes = new (string Label, CERTInextConfig Cfg)[]
            {
                ("baseline (integration-test defaults)", baseline),
                ("kfclab exact",                          kfclab),
                ("baseline + SignerIp=0.0.0.0",           bSignerIp),
                ("baseline + SignerPlace=Lab",            bSignerPlc),
                ("baseline + RequestorMobile=empty",      bMobile),
                ("baseline + RequestorIsdCode=empty",     bIsd),
                ("baseline + RequestorName=unquoted",     bReqName),
            };

            _out.WriteLine("=== Field-by-field PlaceOrder probe ===");
            _out.WriteLine($"fixture RequestorName (literal, may contain quotes): [{_fixture.RequestorName}]");
            _out.WriteLine("");

            foreach (var (label, cfg) in probes)
            {
                var (ok, detail) = await TryEnrollAsync(cfg, label.Replace(" ", "-"));
                _out.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {label,-44} → {detail}");
                // throttle ~1s between probes — sandbox sometimes throttles bursts
                await Task.Delay(1000);
            }
        }
    }
}
