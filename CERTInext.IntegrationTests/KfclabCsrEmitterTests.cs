// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// At http://www.apache.org/licenses/LICENSE-2.0
//
// Utility: emit BouncyCastle-generated PKCS#10 CSRs (CN + DNS SANs) to disk for manual
// Command-driven lab enrollments (e.g. Command Reissue via /Enrollment/CSR, UCC multi-SAN
// checks). Makes no CA calls. Opt-in: set CERTINEXT_EMIT_CSR_DIR (output directory) and
// CERTINEXT_EMIT_CSR_SPEC, a ';'-separated list of "<file-stem>=<cn>[,<extra-san>...]".
// The CN is always included as the first DNS SAN.
//
// Example:
//   CERTINEXT_EMIT_CSR_DIR=/tmp/csrs \
//   CERTINEXT_EMIT_CSR_SPEC="reissue=a.example.com;ucc=b.example.com,c.example.com" \
//   dotnet test --filter FullyQualifiedName~KfclabCsrEmitterTests

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
    public class KfclabCsrEmitterTests
    {
        private readonly ITestOutputHelper _out;

        public KfclabCsrEmitterTests(ITestOutputHelper output)
        {
            _out = output;
        }

        private static string GenerateCsrPem(string cn, IReadOnlyList<string> dnsSans)
        {
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            var kp = keyGen.GenerateKeyPair();

            var names = new GeneralNames(dnsSans.Select(s => new GeneralName(GeneralName.DnsName, s)).ToArray());
            var extGen = new X509ExtensionsGenerator();
            extGen.AddExtension(X509Extensions.SubjectAlternativeName, false, names);
            var attrs = new DerSet(new AttributePkcs(
                PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extGen.Generate())));

            var csr = new Pkcs10CertificationRequest(
                "SHA256withRSA", new X509Name($"CN={cn}"), kp.Public, attrs, kp.Private);
            return "-----BEGIN CERTIFICATE REQUEST-----\n"
                 + Convert.ToBase64String(csr.GetEncoded(), Base64FormattingOptions.InsertLineBreaks)
                 + "\n-----END CERTIFICATE REQUEST-----\n";
        }

        [SkippableFact]
        public void EmitCsrs()
        {
            string dir = Environment.GetEnvironmentVariable("CERTINEXT_EMIT_CSR_DIR");
            string spec = Environment.GetEnvironmentVariable("CERTINEXT_EMIT_CSR_SPEC");
            Skip.If(string.IsNullOrWhiteSpace(dir) || string.IsNullOrWhiteSpace(spec),
                "Set CERTINEXT_EMIT_CSR_DIR and CERTINEXT_EMIT_CSR_SPEC to emit CSRs.");

            Directory.CreateDirectory(dir);
            foreach (string entry in spec.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                string[] kv = entry.Split('=', 2);
                Assert.True(kv.Length == 2, $"Bad CSR spec entry '{entry}' (expected <file-stem>=<cn>[,<san>...]).");
                string[] hosts = kv[1].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                Assert.NotEmpty(hosts);

                string path = Path.Combine(dir, kv[0] + ".csr");
                File.WriteAllText(path, GenerateCsrPem(hosts[0], hosts));
                _out.WriteLine($"{path}: CN={hosts[0]} SANs={string.Join(",", hosts)}");
            }
        }
    }
}
