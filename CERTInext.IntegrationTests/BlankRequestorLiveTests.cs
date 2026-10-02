// Copyright 2026 Keyfactor
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Live probe: does CERTInext accept a DV order whose <c>requestorInformation.requestorName</c>
    /// is empty (connector <c>RequestorName=""</c>, <c>TechnicalContactName=""</c>)?  In that
    /// configuration the plugin sends an empty requestorName and omits technicalPointOfContact
    /// (blank first name).  The test only records CERTInext's answer; it asserts nothing about
    /// accept vs. reject so either outcome is a valid finding.
    ///
    /// It also captures the outbound GenerateOrderSSL body (the client's Trace
    /// "PlaceOrderAsync request payload" dump, taken with <c>LogSensitiveRequestData=true</c> so
    /// the empty requestorName is not masked; <c>meta.authKey</c> is always redacted by the client
    /// and the body is never printed) and asserts requestorName is exactly "", no
    /// technicalPointOfContact key, and signerName "Keyfactor Gateway". The dump's equivalence to
    /// the WireMock-captured POST body is pinned by <c>BlankRequestorWireTests</c> in CERTInext.Tests.
    /// For the TrackOrder response it records only blank/non-blank for requestorName (and whether
    /// it equals a configured value) and the names of any technical-contact-like JSON keys.
    ///
    /// Opt-in: set <c>CERTINEXT_BLANK_REQUESTOR_LIVE=1</c> as a REAL environment variable (a value in
    /// <c>~/.env_certinext</c> is refused).  The order, if placed, is revoked/cancelled in a finally
    /// block and re-read read-only to confirm.
    /// </summary>
    public class BlankRequestorLiveTests : IClassFixture<IntegrationTestFixture>
    {
        private const string OptInFlag = "CERTINEXT_BLANK_REQUESTOR_LIVE";

        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;

        public BlankRequestorLiveTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output = output;
        }

        private void SkipUnlessOptedIn()
        {
            IntegrationSkip.IfNotConfigured(_fixture);

            Skip.If(Environment.GetEnvironmentVariable(OptInFlag) != "1",
                $"Opt-in: set {OptInFlag}=1 as a real environment variable to place a live sandbox order.");

            string envFile = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".env_certinext");
            bool inFile = File.Exists(envFile) && File.ReadAllLines(envFile)
                .Any(l => l.TrimStart().StartsWith(OptInFlag + "=", StringComparison.Ordinal));
            Skip.If(inFile, $"{OptInFlag} must be a real environment variable, not set in ~/.env_certinext.");
        }

        private CERTInextConfig BuildBlankRequestorConfig()
        {
            var c = _fixture.Config;
            return new CERTInextConfig
            {
                ApiUrl                = c.ApiUrl,
                AuthMode              = c.AuthMode,
                ApiKey                = c.ApiKey,
                AccountNumber         = c.AccountNumber,
                GroupNumber           = c.GroupNumber,
                OrganizationNumber    = c.OrganizationNumber,
                RequestorName         = string.Empty,
                TechnicalContactName  = string.Empty,
                RequestorEmail        = c.RequestorEmail,
                RequestorIsdCode      = c.RequestorIsdCode,
                RequestorMobileNumber = c.RequestorMobileNumber,
                SignerPlace           = c.SignerPlace,
                SignerIp              = c.SignerIp,
                DefaultProductCode    = c.DefaultProductCode,
                PageSize              = c.PageSize,
                DcvEnabled            = false,
                // Needed so the Trace payload dumps keep the (empty) requestorName verbatim.
                // authKey is redacted regardless; the dumps are only inspected, never printed.
                LogSensitiveRequestData = true,
            };
        }

        private sealed class CapturingLogger : ILogger
        {
            public ConcurrentQueue<string> Messages { get; } = new();
            public IDisposable BeginScope<TState>(TState state) => null;
            public bool IsEnabled(LogLevel logLevel) => true;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception,
                Func<TState, Exception, string> formatter) => Messages.Enqueue(formatter(state, exception));
        }

        private const string PlaceOrderDumpPrefix = "PlaceOrderAsync request payload: ";

        /// <summary>Last dump of the given kind whose text contains <paramref name="marker"/>, parsed; null if absent.</summary>
        private static JsonDocument LastDump(CapturingLogger logger, string startsWith, string marker)
        {
            string msg = logger.Messages
                .Where(m => m != null && m.StartsWith(startsWith, StringComparison.Ordinal) && m.Contains(marker))
                .LastOrDefault();
            if (msg == null) return null;
            string json = msg.Substring(msg.IndexOf('{'));
            return JsonDocument.Parse(json);
        }

        /// <summary>All values of JSON properties named <paramref name="name"/> at any depth (case-insensitive).</summary>
        private static List<JsonElement> FindProps(JsonElement e, string name)
        {
            var hits = new List<JsonElement>();
            void Walk(JsonElement x)
            {
                if (x.ValueKind == JsonValueKind.Object)
                    foreach (var p in x.EnumerateObject())
                    {
                        if (string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase)) hits.Add(p.Value);
                        Walk(p.Value);
                    }
                else if (x.ValueKind == JsonValueKind.Array)
                    foreach (var i in x.EnumerateArray()) Walk(i);
            }
            Walk(e);
            return hits;
        }

        /// <summary>Names of every JSON property (any depth) that looks like a technical-contact field.</summary>
        private static List<string> TechContactLikeKeys(JsonElement e)
        {
            var names = new List<string>();
            void Walk(JsonElement x)
            {
                if (x.ValueKind == JsonValueKind.Object)
                    foreach (var p in x.EnumerateObject())
                    {
                        if (Regex.IsMatch(p.Name, "technical|poc|contact", RegexOptions.IgnoreCase)) names.Add(p.Name);
                        Walk(p.Value);
                    }
                else if (x.ValueKind == JsonValueKind.Array)
                    foreach (var i in x.EnumerateArray()) Walk(i);
            }
            Walk(e);
            return names.Distinct().ToList();
        }

        private static string GenerateCsrPem(string commonName)
        {
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            var keyPair = keyGen.GenerateKeyPair();
            var csr = new Pkcs10CertificationRequest(
                "SHA256withRSA", new X509Name($"CN={commonName}"), keyPair.Public, null, keyPair.Private);
            return "-----BEGIN CERTIFICATE REQUEST-----\n"
                + Convert.ToBase64String(csr.GetEncoded(), Base64FormattingOptions.InsertLineBreaks)
                + "\n-----END CERTIFICATE REQUEST-----";
        }

        /// <summary>Masks anything that looks like an email address, then truncates to 500 chars.</summary>
        private static string Scrub(string s)
        {
            if (s == null) return null;
            s = Regex.Replace(s, @"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", "<email>");
            return s.Length > 500 ? s.Substring(0, 500) : s;
        }

        [SkippableFact]
        public async Task DvOrder_WithBlankRequestorNameAndTechnicalContactName_RecordsCertinextResponse()
        {
            SkipUnlessOptedIn();

            string cn = $"blankreq-{Guid.NewGuid():N}".Substring(0, 20) + ".scrup.org";
            string code = _fixture.Config.DefaultProductCode ?? Constants.Products.DvSsl;
            var productInfo = new EnrollmentProductInfo
            {
                ProductID = code,
                ProductParameters = new Dictionary<string, string>
                {
                    ["ProfileId"] = code,
                    ["ValidityYears"] = "1"
                }
            };

            var config = BuildBlankRequestorConfig();
            // The client builds the order body from ITS config, so it must be constructed from the
            // blank-requestor config (the shared fixture client carries the populated RequestorName).
            var client = new CERTInextClient(config);
            var plugin = new CERTInextCAPlugin(client, config);
            var created = new List<string>();

            // Process-wide client logger swap (restored on dispose) so the Trace payload dumps can be inspected.
            var capture = new CapturingLogger();
            using var loggerOverride = CERTInextClient.OverrideLoggerForTests(capture);

            _output.WriteLine($"PROBE: RequestorName=\"\" TechnicalContactName=\"\" ProductCode={code} CN={cn}");
            try
            {
                try
                {
                    var result = await plugin.Enroll(
                        GenerateCsrPem(cn), $"CN={cn}",
                        new Dictionary<string, string[]> { ["dns"] = new[] { cn } },
                        productInfo, RequestFormat.PKCS10, EnrollmentType.New);

                    created.Add(result.CARequestID);
                    _output.WriteLine($"RESULT: ACCEPTED order={result.CARequestID} status={result.Status} " +
                                      $"statusMessage={Scrub(result.StatusMessage)}");

                    var track = await client.TrackOrderAsync(result.CARequestID);
                    string storedName = track.OrderDetails?.RequestorInformation?.RequestorName;
                    _output.WriteLine($"TRACK: orderStatusId={track.OrderDetails?.OrderStatusId} ({track.OrderDetails?.OrderStatus}), " +
                                      $"certificateStatusId={track.OrderDetails?.CertificateStatusId} ({track.OrderDetails?.CertificateStatus}), " +
                                      $"stored requestorName blank={string.IsNullOrWhiteSpace(storedName)}");
                }
                catch (Exception ex)
                {
                    _output.WriteLine($"RESULT: REJECTED/FAILED {ex.GetType().Name}: {Scrub(ex.Message)}");
                    if (ex.InnerException != null)
                        _output.WriteLine($"  inner {ex.InnerException.GetType().Name}: {Scrub(ex.InnerException.Message)}");
                }
            }
            finally
            {
                await CleanupAsync(client, plugin, created);
            }

            // ---- Outbound body (captured from the live PlaceOrder call; body itself is never printed) ----
            using var sent = LastDump(capture, PlaceOrderDumpPrefix, cn);
            Assert.True(sent != null, "No 'PlaceOrderAsync request payload' dump was captured for this order.");
            var od = sent.RootElement.GetProperty("orderDetails");

            bool hasRi = od.TryGetProperty("requestorInformation", out var ri);
            bool hasName = hasRi && ri.TryGetProperty("requestorName", out _);
            string sentName = hasName ? ri.GetProperty("requestorName").GetString() : null;
            bool hasPoc = od.TryGetProperty("technicalPointOfContact", out _);
            string sentSigner = od.GetProperty("agreementDetails").GetProperty("signerName").GetString();
            _output.WriteLine($"WIRE: requestorInformation present={hasRi}; requestorName key present={hasName}, " +
                              $"value is empty string={sentName == string.Empty}, length={sentName?.Length}; " +
                              $"technicalPointOfContact key present={hasPoc}; " +
                              $"agreementDetails.signerName=\"Keyfactor Gateway\" -> {sentSigner == "Keyfactor Gateway"}");

            // ---- What CERTInext hands back for that order (blank/non-blank only; values not printed) ----
            foreach (string id in created)
            {
                using var tracked = LastDump(capture, "TrackOrderAsync response payload (Order=" + id + ")", id);
                if (tracked == null)
                {
                    _output.WriteLine($"TRACKRAW {id}: no TrackOrder payload dump captured");
                    continue;
                }
                var names = FindProps(tracked.RootElement, "requestorName");
                // Includes the plugin's built-in fallback name so a CERTInext-side substitution is distinguishable.
                var configured = new[] { _fixture.Config.RequestorName, _fixture.Config.TechnicalContactName,
                                         _fixture.Config.RequestorEmail, _fixture.Config.SignerPlace,
                                         "Keyfactor Gateway" }
                    .Where(v => !string.IsNullOrWhiteSpace(v)).ToList();
                foreach (var n in names)
                {
                    string v = n.ValueKind == JsonValueKind.String ? n.GetString() : null;
                    _output.WriteLine($"TRACKRAW {id}: requestorName kind={n.ValueKind}, blank={string.IsNullOrWhiteSpace(v)}, " +
                                      $"equals a configured value or the built-in fallback={(v != null && configured.Contains(v, StringComparer.OrdinalIgnoreCase))}, " +
                                      $"looks like an email={(v != null && v.Contains('@'))}");
                }
                if (names.Count == 0) _output.WriteLine($"TRACKRAW {id}: no requestorName property in response");
                var pocKeys = TechContactLikeKeys(tracked.RootElement);
                _output.WriteLine($"TRACKRAW {id}: technical-contact-like keys in response = " +
                                  (pocKeys.Count == 0 ? "(none)" : string.Join(", ", pocKeys)));
            }

            Assert.True(hasName, "requestorInformation.requestorName key must be present on the wire");
            Assert.Equal(string.Empty, sentName);
            Assert.False(hasPoc, "technicalPointOfContact must be omitted from the wire body");
            Assert.Equal("Keyfactor Gateway", sentSigner);
        }

        private async Task CleanupAsync(CERTInextClient client, CERTInextCAPlugin plugin, IEnumerable<string> orderNumbers)
        {
            var ids = orderNumbers.Where(o => !string.IsNullOrWhiteSpace(o)).Distinct().ToList();
            if (ids.Count == 0)
            {
                _output.WriteLine("CLEANUP: no order was placed; nothing to revoke.");
                return;
            }

            foreach (string id in ids)
            {
                try
                {
                    var before = await client.TrackOrderAsync(id);
                    int.TryParse(before.OrderDetails?.CertificateStatusId, out int st);
                    _output.WriteLine($"cleanup {id}: before certificateStatusId={st} ({before.OrderDetails?.CertificateStatus})");
                    if (st == Constants.CertificateStatusId.CertificateRevoked)
                        continue;

                    if (st == Constants.CertificateStatusId.CertificateGenerated
                        || st == Constants.CertificateStatusId.CertificateDownloaded)
                    {
                        int rc = await plugin.Revoke(id, string.Empty, 5);
                        _output.WriteLine($"cleanup {id}: plugin.Revoke returned {rc}");
                    }
                    else
                    {
                        // Not issued: record exactly what CERTInext says to a raw revoke/cancel.
                        await client.RevokeCertificateAsync(id, new RevokeCertificateRequest
                        {
                            Reason = Constants.RevocationReason.CessationOfOperation,
                            Comment = "blank-requestor live-test cleanup"
                        });
                        _output.WriteLine($"cleanup {id}: raw RevokeCertificateAsync accepted for non-issued order");
                    }
                }
                catch (Exception ex)
                {
                    _output.WriteLine($"cleanup {id}: REVOKE/CANCEL FAILED -> {ex.GetType().Name}: {Scrub(ex.Message)}");
                }
            }

            _output.WriteLine("--- cleanup verification (fresh read-only TrackOrder) ---");
            foreach (string id in ids)
            {
                try
                {
                    var after = await client.TrackOrderAsync(id);
                    _output.WriteLine($"verify {id}: orderStatusId={after.OrderDetails?.OrderStatusId} ({after.OrderDetails?.OrderStatus}), " +
                                      $"certificateStatusId={after.OrderDetails?.CertificateStatusId} ({after.OrderDetails?.CertificateStatus})");
                }
                catch (Exception ex)
                {
                    _output.WriteLine($"verify {id}: TrackOrder failed -> {ex.GetType().Name}: {Scrub(ex.Message)}");
                }
            }
        }
    }
}
