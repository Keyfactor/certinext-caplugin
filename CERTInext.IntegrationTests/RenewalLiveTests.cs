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

#if SUPPORTS_DCV
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.PKI.Enums.EJBCA;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Live-sandbox proof of the plugin-level renewal path that Keyfactor Command drives:
    /// <c>Enroll(EnrollmentType.RenewOrReissue)</c> with the prior certificate's serial in
    /// <c>PriorCertSN</c> -> <c>RenewOrReissueAsync</c> -> <c>client.RenewCertificateAsync</c> ->
    /// <c>GenerateOrderSSL</c>.  On 1.0.0 that order carried no <c>additionalInformation.remarks</c>
    /// and CERTInext rejected it with EMS-918; 1.0.1 rebuilds it through <c>BuildSslOrderDetails</c>.
    /// The client-level renewal is covered by
    /// <c>GroupAndWwwLiveTests.IssuedOrder_RenewedViaRenewCertificateAsync_StaysInGroup_WithNoWwwSan</c>;
    /// this class covers what the customer actually hits (the plugin, the renewal-window decision,
    /// the PriorCertSN to CARequestID lookup, and the template product code).
    ///
    /// Product: the sandbox's product 842 is DV SSL, so the first order is driven to issuance with
    /// Cloudflare DNS-01 (<c>CERTINEXT_CF_API_TOKEN</c> + <c>CERTINEXT_CF_ZONE_ID</c>); there is no
    /// auto-issuing private/OV product on this account (see TESTING.md, "Product Codes Are Per-Account").
    ///
    /// Opt-in: set <c>CERTINEXT_RENEWAL_E2E=1</c> as a REAL environment variable (it is never
    /// promoted from ~/.env_certinext, see <see cref="IntegrationTestFixture.OptInOnlyFlags"/>).
    /// Also needs <c>CERTINEXT_DCV_DOMAIN</c> (base domain for unique names) and the Cloudflare
    /// credentials.  Places 2 sandbox orders; both are revoked in a finally block and the final
    /// state is re-read and printed.
    /// </summary>
    public class RenewalLiveTests : IClassFixture<IntegrationTestFixture>, IDisposable
    {
        private const string OptInFlag = "CERTINEXT_RENEWAL_E2E";

        /// <summary>
        /// Deliberately NOT the product code on the template.  If the renewal (or the new
        /// enrollment) used the connector default instead of the template's code, CERTInext would
        /// reject it (EMS-1162, invalid product code) or the order report would show this value.
        /// </summary>
        private const string BogusDefaultProductCode = "999";

        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;
        private readonly List<IDisposable> _toDispose = new List<IDisposable>();

        public RenewalLiveTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output = output;
        }

        public void Dispose()
        {
            foreach (var d in _toDispose)
                d.Dispose();
            _toDispose.Clear();
        }

        // ---------------------------------------------------------------------------
        // Test doubles
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Stands in for Command's certificate inventory: maps the prior certificate's serial to
        /// its CARequestID and reports its expiry, and records every serial the plugin looked up.
        /// Returns null for an unknown serial, exactly like an inventory miss, so a wrong
        /// <c>PriorCertSN</c> makes the plugin fall back to a new enrollment (which the test detects).
        /// </summary>
        public class InventoryProxy : DispatchProxy
        {
            public string KnownSerialHex { get; set; }
            public string RequestId { get; set; }
            public DateTime? Expiry { get; set; }
            public List<string> SerialsRequested { get; } = new List<string>();

            protected override object Invoke(MethodInfo targetMethod, object[] args)
            {
                switch (targetMethod.Name)
                {
                    case "GetRequestIDBySerialNumber":
                        string sn = (string)args[0];
                        SerialsRequested.Add(sn);
                        return Task.FromResult(SameSerial(sn, KnownSerialHex) ? RequestId : null);
                    case "GetExpirationDateByRequestId":
                        return string.Equals((string)args[0], RequestId, StringComparison.Ordinal) ? Expiry : null;
                    default:
                        throw new NotSupportedException(targetMethod.Name);
                }
            }

            private static bool SameSerial(string a, string b) =>
                !string.IsNullOrEmpty(a) && !string.IsNullOrEmpty(b)
                && string.Equals(a.TrimStart('0'), b.TrimStart('0'), StringComparison.OrdinalIgnoreCase);
        }

        // ---------------------------------------------------------------------------
        // Helpers
        // ---------------------------------------------------------------------------

        private string SkipUnlessOptedIn()
        {
            IntegrationSkip.IfNotConfigured(_fixture);
            Skip.If(Environment.GetEnvironmentVariable(OptInFlag) != "1",
                $"Opt-in: export {OptInFlag}=1 in the shell to place live sandbox orders.");
            Skip.If(!_fixture.IsCloudflareConfigured,
                "CERTINEXT_CF_API_TOKEN + CERTINEXT_CF_ZONE_ID required to drive DV DCV to issuance.");
            string baseDomain = Environment.GetEnvironmentVariable("CERTINEXT_DCV_DOMAIN");
            Skip.If(string.IsNullOrWhiteSpace(baseDomain),
                "CERTINEXT_DCV_DOMAIN is required (base domain for unique test names).");
            Skip.If(string.IsNullOrWhiteSpace(_fixture.Config.DefaultProductCode),
                "CERTINEXT_PRODUCT_CODE is required (the template product code under test).");
            return baseDomain;
        }

        private CERTInextConfig BuildConfig()
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
                RequestorName         = c.RequestorName,
                RequestorEmail        = c.RequestorEmail,
                RequestorIsdCode      = c.RequestorIsdCode,
                RequestorMobileNumber = c.RequestorMobileNumber,
                SignerPlace           = c.SignerPlace,
                SignerIp              = c.SignerIp,
                PageSize              = c.PageSize,
                AutoSecureWww         = "0",
                // Differs from the template product code on purpose: the template code must win.
                DefaultProductCode    = BogusDefaultProductCode,
                DcvEnabled                 = true,
                DcvPropagationDelaySeconds = 5,
                DcvTimeoutMinutes          = 3,
            };
        }

        /// <summary>
        /// Template parameters as Command sends them for an enrollment/renewal.  <c>ProfileId</c> is
        /// the template's product code (the real sandbox DV code); <c>ValidityYears</c> follows the
        /// other live tests.
        /// </summary>
        private EnrollmentProductInfo TemplateProductInfo(string priorCertSn = null, int? renewalWindowDays = null)
        {
            string code = _fixture.Config.DefaultProductCode;
            var info = new EnrollmentProductInfo
            {
                ProductID         = code,
                ProductParameters = new Dictionary<string, string>
                {
                    ["ProfileId"]     = code,
                    ["ValidityYears"] = "1"
                }
            };
            if (priorCertSn != null)
                info.ProductParameters["PriorCertSN"] = priorCertSn;
            if (renewalWindowDays.HasValue)
                info.ProductParameters["RenewalWindowDays"] = renewalWindowDays.Value.ToString();
            return info;
        }

        /// <summary>Fresh RSA-2048 key + CSR (BouncyCastle); the public key is returned for comparison with the issued cert.</summary>
        private static (string Pem, AsymmetricKeyParameter PublicKey) GenerateCsr(string commonName)
        {
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            var keyPair = keyGen.GenerateKeyPair();
            var csr = new Pkcs10CertificationRequest(
                "SHA256withRSA", new X509Name($"CN={commonName}"), keyPair.Public, null, keyPair.Private);
            string pem = "-----BEGIN CERTIFICATE REQUEST-----\n"
                + Convert.ToBase64String(csr.GetEncoded(), Base64FormattingOptions.InsertLineBreaks)
                + "\n-----END CERTIFICATE REQUEST-----";
            return (pem, keyPair.Public);
        }

        /// <summary>
        /// Parses the leaf certificate the plugin returned.  Accepts a PEM block (first certificate
        /// wins) or bare base64 DER; fails with a descriptive message rather than a null reference.
        /// </summary>
        private static X509Certificate ParseCert(string certText)
        {
            certText.Should().NotBeNullOrWhiteSpace("the plugin must return a certificate body for an issued order");
            X509Certificate cert;
            if (certText.Contains("-----BEGIN", StringComparison.Ordinal))
            {
                using var reader = new StringReader(certText);
                cert = new PemReader(reader).ReadObject() as X509Certificate;
            }
            else
            {
                cert = new X509CertificateParser().ReadCertificate(
                    Convert.FromBase64String(certText.Trim()));
            }
            cert.Should().NotBeNull($"the returned certificate body must parse (length={certText.Length}, " +
                                    $"startsWith='{certText.Substring(0, Math.Min(12, certText.Length)).Replace("\n", " ")}')");
            return cert;
        }

        private static string SerialHex(X509Certificate cert) =>
            cert.SerialNumber.ToString(16).ToUpperInvariant();

        /// <summary>
        /// Polls GetSingleRecord (which re-runs DCV for EXTERNALVALIDATION orders) until the order is
        /// GENERATED <em>and</em> carries a certificate body.  CERTInext reports "Approved by System"
        /// (certificateStatusId 15) as GENERATED a little before the certificate is downloadable, so
        /// the status alone is not enough.
        /// </summary>
        private async Task<AnyCAPluginCertificate> DriveToIssuanceAsync(CERTInextCAPlugin plugin, string orderNumber)
        {
            AnyCAPluginCertificate rec = null;
            for (int pass = 1; pass <= 12; pass++)
            {
                rec = await plugin.GetSingleRecord(orderNumber);
                bool hasCert = !string.IsNullOrWhiteSpace(rec.Certificate);
                _output.WriteLine($"  issuance pass {pass}: {orderNumber} status={rec.Status} certificateBody={hasCert}");
                if (rec.Status == (int)EndEntityStatus.GENERATED && hasCert)
                    break;
                await Task.Delay(TimeSpan.FromSeconds(20));
            }
            return rec;
        }

        /// <summary>Finds an order in GetOrderReport (today onward first, then unfiltered).</summary>
        private async Task<OrderReportEntry> FindInOrderReportAsync(string orderNumber)
        {
            foreach (string from in new[] { DateTime.UtcNow.Date.AddDays(-1).ToString("yyyy-MM-dd"), null })
            {
                try
                {
                    await foreach (var e in _fixture.Client.ListOrdersAsync(orderDateFrom: from, pageSize: 100))
                        if (e.OrderNumber == orderNumber)
                            return e;
                }
                catch (Exception ex) when (from != null)
                {
                    _output.WriteLine($"  ListOrders(orderDateFrom={from}) failed ({ex.GetType().Name}); retrying unfiltered.");
                }
            }
            return null;
        }

        /// <summary>Domain names from TrackOrder.domainVerification, polled briefly while CERTInext populates the block.</summary>
        private async Task<List<string>> GetDomainListAsync(string orderNumber, string mustContain)
        {
            var names = new List<string>();
            for (int i = 0; i < 8; i++)
            {
                var track = await _fixture.Client.TrackOrderAsync(orderNumber);
                names = track.OrderDetails?.DomainVerification?.RawDomainEntries?.Keys.ToList() ?? new List<string>();
                if (names.Any(n => string.Equals(n, mustContain, StringComparison.OrdinalIgnoreCase)))
                    break;
                await Task.Delay(TimeSpan.FromSeconds(5));
            }
            return names;
        }

        /// <summary>
        /// Order-level assertions that hold for any order the test places: it is in the order report
        /// under the template product code (never the bogus connector default), its primary domain is
        /// the CN, and its domain list is exactly the requested name (no www.).
        /// </summary>
        private async Task AssertOrderShapeAsync(string label, string orderNumber, string cn)
        {
            var entry = await FindInOrderReportAsync(orderNumber);
            entry.Should().NotBeNull($"{label} order {orderNumber} must be listed by GetOrderReport");
            var domains = await GetDomainListAsync(orderNumber, cn);

            _output.WriteLine($"  [{label}] {orderNumber}: productCode={entry!.ProductCode} " +
                              $"(template={_fixture.Config.DefaultProductCode}, connector default={BogusDefaultProductCode}); " +
                              $"report domainName={TestOutputScrub.Scrub(entry.DomainName)}; " +
                              $"TrackOrder domains=[{TestOutputScrub.Scrub(string.Join(", ", domains))}]");

            entry.ProductCode.Should().Be(_fixture.Config.DefaultProductCode,
                $"{label} order must use the template/ProfileId product code, not DefaultProductCode={BogusDefaultProductCode}");
            entry.DomainName.Should().BeEquivalentTo(cn, $"{label} order's primary domain must be the subject CN");
            domains.Should().BeEquivalentTo(new[] { cn },
                $"{label} order's domain list must be exactly the requested SANs (AutoSecureWww=0, so no www.)");
        }

        /// <summary>
        /// Revokes every created order (plugin path for issued certs, raw revoke attempt otherwise),
        /// then re-reads each order read-only and prints its final state.  Returns true when every
        /// order ended revoked/cancelled/rejected.
        /// </summary>
        private async Task<bool> CleanupAsync(CERTInextCAPlugin plugin, IEnumerable<string> orderNumbers)
        {
            var ids = orderNumbers.Where(o => !string.IsNullOrWhiteSpace(o)).Distinct().ToList();
            foreach (string id in ids)
            {
                try
                {
                    var before = await _fixture.Client.TrackOrderAsync(id);
                    int.TryParse(before.OrderDetails?.CertificateStatusId, out int st);
                    _output.WriteLine($"  cleanup {id}: before certificateStatusId={st} ({TestOutputScrub.Scrub(before.OrderDetails?.CertificateStatus)})");
                    if (st == Constants.CertificateStatusId.CertificateRevoked)
                        continue;

                    if (st == Constants.CertificateStatusId.CertificateGenerated
                        || st == Constants.CertificateStatusId.CertificateDownloaded)
                    {
                        // CERTInext answers "Certificate Request still being processed" while it finishes
                        // generating an auto-approved order; retry for a few minutes.
                        for (int attempt = 1; ; attempt++)
                        {
                            try
                            {
                                int rc = await plugin.Revoke(id, string.Empty, 5);
                                _output.WriteLine($"  cleanup {id}: plugin.Revoke returned {rc} (attempt {attempt})");
                                break;
                            }
                            catch (Exception ex) when (attempt < 12
                                && ex.Message.Contains("still being processed", StringComparison.OrdinalIgnoreCase))
                            {
                                _output.WriteLine($"  cleanup {id}: revoke attempt {attempt} deferred (still being processed)");
                                await Task.Delay(TimeSpan.FromSeconds(20));
                            }
                        }
                    }
                    else
                    {
                        // Not issued: the plugin refuses (revocable only when GENERATED). Try the raw
                        // revoke and record exactly what CERTInext says; do not work around a refusal.
                        await _fixture.Client.RevokeCertificateAsync(id, new RevokeCertificateRequest
                        {
                            Reason = Constants.RevocationReason.CessationOfOperation,
                            Comment = "renewal e2e live-test cleanup"
                        });
                        _output.WriteLine($"  cleanup {id}: raw RevokeCertificateAsync accepted for non-issued order");
                    }
                }
                catch (Exception ex)
                {
                    _output.WriteLine($"  cleanup {id}: REVOKE/CANCEL FAILED -> {TestOutputScrub.Describe(ex)}");
                }
            }

            _output.WriteLine("  --- cleanup verification (fresh read-only TrackOrder) ---");
            bool allClean = true;
            foreach (string id in ids)
            {
                try
                {
                    var after = await _fixture.Client.TrackOrderAsync(id);
                    int.TryParse(after.OrderDetails?.CertificateStatusId, out int certSt);
                    int.TryParse(after.OrderDetails?.OrderStatusId, out int ordSt);
                    bool clean = certSt == Constants.CertificateStatusId.CertificateRevoked
                                 || ordSt == 4 || ordSt == 5; // rejected / cancelled
                    allClean &= clean;
                    _output.WriteLine($"  verify {id}: orderStatusId={after.OrderDetails?.OrderStatusId} ({TestOutputScrub.Scrub(after.OrderDetails?.OrderStatus)}), " +
                                      $"certificateStatusId={after.OrderDetails?.CertificateStatusId} ({TestOutputScrub.Scrub(after.OrderDetails?.CertificateStatus)}) clean={clean}");
                }
                catch (Exception ex)
                {
                    allClean = false;
                    _output.WriteLine($"  verify {id}: TrackOrder failed -> {TestOutputScrub.Describe(ex)}");
                }
            }
            _output.WriteLine($"  CLEANUP RESULT: {(allClean ? "all orders revoked/cancelled" : "some orders NOT cleaned up")} ({string.Join(", ", ids)})");
            return allClean;
        }

        // ---------------------------------------------------------------------------
        // Test
        // ---------------------------------------------------------------------------

        /// <summary>
        /// New order -> issued -> <c>Enroll(RenewOrReissue)</c> with a new CSR, the same subject/SAN
        /// and <c>PriorCertSN</c> = the issued certificate's serial, inside the renewal window.
        ///
        /// Accepted outcomes for the renewal <c>Enroll</c> result: GENERATED (issued in-band) or
        /// EXTERNALVALIDATION (pending, order exists; the renew path does not run in-call DCV and
        /// returns pending for a DV renewal still waiting on DNS-01).  Either way the order must
        /// exist at CERTInext; the test then drives it to issuance and checks the certificate.
        /// </summary>
        [SkippableFact]
        public async Task Enroll_RenewOrReissue_ThroughPlugin_PlacesRenewalOrder_WithTemplateProductCode()
        {
            string baseDomain = SkipUnlessOptedIn();

            string cn = $"renew-e2e-{Guid.NewGuid():N}".Substring(0, 20) + "." + baseDomain.TrimStart('.');
            var san = new Dictionary<string, string[]> { ["dns"] = new[] { cn } };
            string subject = $"CN={cn}";

            var recorder = DispatchProxy.Create<Client.ICERTInextClient, GroupAndWwwLiveTests.RecordingClientProxy>();
            ((GroupAndWwwLiveTests.RecordingClientProxy)(object)recorder).Target = _fixture.Client;
            var calls = ((GroupAndWwwLiveTests.RecordingClientProxy)(object)recorder).Calls;

            var inventory = DispatchProxy.Create<ICertificateDataReader, InventoryProxy>();
            var inventoryState = (InventoryProxy)(object)inventory;

            var plugin = new CERTInextCAPlugin(recorder, inventory, BuildConfig());
            var factory = new CloudflareDomainValidatorFactory(_fixture.CloudflareApiToken, _fixture.CloudflareZoneId);
            _toDispose.Add(factory);
            plugin.SetDomainValidatorFactory(factory);

            var created = new List<string>();
            bool cleanedUp = false;
            try
            {
                // 1. Fresh order through the plugin (template product code; connector default is bogus).
                var (firstCsr, _) = GenerateCsr(cn);
                var first = await plugin.Enroll(firstCsr, subject, san, TemplateProductInfo(),
                    RequestFormat.PKCS10, EnrollmentType.New);
                first.CARequestID.Should().NotBeNullOrWhiteSpace();
                created.Add(first.CARequestID);
                _output.WriteLine($"Original order {first.CARequestID}: Enroll status={first.Status}");
                await AssertOrderShapeAsync("original", first.CARequestID, cn);

                // 2. Drive to issuance and capture the issued cert's serial (what Command stores).
                var issued = await DriveToIssuanceAsync(plugin, first.CARequestID);
                // The sandbox sometimes parks a fresh DV order at "Pending for Approver"/"Pending System RA"
                // for much longer than the polling budget.  That is a precondition failure (no issued cert
                // to renew), not a renewal failure, so it is reported as a skip rather than a red test.
                bool preconditionMet = issued.Status == (int)EndEntityStatus.GENERATED
                                       && !string.IsNullOrWhiteSpace(issued.Certificate);
                Skip.IfNot(preconditionMet,
                    $"Precondition not met: original order {first.CARequestID} did not issue within the polling budget " +
                    $"(status={issued.Status}); the sandbox is holding it for approval. Re-run; the order is cleaned up.");
                var priorCert = ParseCert(issued.Certificate);
                string priorSerial = SerialHex(priorCert);
                _output.WriteLine($"Original order {first.CARequestID}: issued, serial length={priorSerial.Length} hex chars");

                // 3. Wire the inventory the way Command presents it: serial -> CARequestID + expiry.
                var track = await _fixture.Client.TrackOrderAsync(first.CARequestID);
                inventoryState.KnownSerialHex = priorSerial;
                inventoryState.RequestId = first.CARequestID;
                inventoryState.Expiry = priorCert.NotAfter.ToUniversalTime();
                _output.WriteLine($"Prior cert expires {priorCert.NotAfter:yyyy-MM-dd} UTC " +
                                  $"(TrackOrder certificateExpiryDate present={!string.IsNullOrWhiteSpace(track.OrderDetails?.CertificateExpiryDate)})");

                // 4. Renewal: new key + CSR, same subject/SAN, PriorCertSN, window wide enough that the
                //    1-year certificate is inside it so the renew API branch (UseRenewalApi=True) is taken.
                var (renewCsr, renewPublicKey) = GenerateCsr(cn);
                var renewInfo = TemplateProductInfo(priorCertSn: priorSerial, renewalWindowDays: 800);
                int callsBeforeRenewal = calls.Count;

                EnrollmentResult renewed;
                try
                {
                    renewed = await plugin.Enroll(renewCsr, subject, san, renewInfo,
                        RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);
                }
                catch (Exception ex)
                {
                    _output.WriteLine($"RENEWAL FAILED: {TestOutputScrub.Describe(ex)}");
                    throw;
                }

                // 5. Assertions on the renewal result.
                renewed.CARequestID.Should().NotBeNullOrWhiteSpace();
                created.Add(renewed.CARequestID);
                _output.WriteLine($"Renewal order {renewed.CARequestID}: Enroll status={renewed.Status} " +
                                  $"({(renewed.Status == (int)EndEntityStatus.GENERATED ? "issued in-band" : "pending")}), " +
                                  $"distinct from original = {renewed.CARequestID != first.CARequestID}; " +
                                  $"message={TestOutputScrub.Scrub(renewed.StatusMessage)}");

                inventoryState.SerialsRequested.Should().ContainSingle(s => SerialHexEquals(s, priorSerial),
                    "the plugin must resolve the prior certificate through PriorCertSN");
                var renewalCalls = calls.Skip(callsBeforeRenewal).ToList();
                _output.WriteLine($"Client calls during renewal Enroll: {string.Join(", ", renewalCalls)}");
                renewalCalls.Should().Contain("RenewCertificateAsync",
                    "the renewal-window branch must go through RenewCertificateAsync, not fall back to a fresh enrollment");

                renewed.CARequestID.Should().NotBe(first.CARequestID);
                new[] { (int)EndEntityStatus.GENERATED, (int)EndEntityStatus.EXTERNALVALIDATION }
                    .Should().Contain(renewed.Status, "the renewal order is either issued or pending validation, never failed");

                // 6. The renewal order exists at CERTInext with the template product code, CN and SANs.
                await AssertOrderShapeAsync("renewal", renewed.CARequestID, cn);

                // 7. Drive the renewal to issuance; the cert must carry the NEW key and the requested names.
                var renewedRec = await DriveToIssuanceAsync(plugin, renewed.CARequestID);
                renewedRec.Status.Should().Be((int)EndEntityStatus.GENERATED, "the renewal order must issue");
                var renewedCert = ParseCert(renewedRec.Certificate);
                renewedCert.SerialNumber.Should().NotBe(priorCert.SerialNumber, "a renewal is a new certificate");
                renewedCert.GetPublicKey().Should().Be(renewPublicKey, "the renewal must be issued against the NEW CSR's key");
                var sanNames = (renewedCert.GetSubjectAlternativeNames()
                                    ?? new List<System.Collections.Generic.IList<object>>())
                    .Select(e => e[1]?.ToString())
                    .ToList();
                _output.WriteLine($"Renewal cert: subject CN matches={renewedCert.SubjectDN.ToString().Contains(cn, StringComparison.OrdinalIgnoreCase)}, " +
                                  $"SANs=[{TestOutputScrub.Scrub(string.Join(", ", sanNames))}]");
                renewedCert.SubjectDN.ToString().Should().Contain(cn);
                sanNames.Should().Contain(n => string.Equals(n, cn, StringComparison.OrdinalIgnoreCase));
                sanNames.Should().NotContain(n => n.StartsWith("www.", StringComparison.OrdinalIgnoreCase));
            }
            finally
            {
                cleanedUp = await CleanupAsync(plugin, created);
            }

            cleanedUp.Should().BeTrue("every sandbox order the test placed must end revoked/cancelled");
        }

        /// <summary>
        /// Cleanup for orders left behind by an interrupted or skipped run: set
        /// <c>CERTINEXT_RENEWAL_E2E_CLEANUP_ORDERS</c> to a comma-separated list of order numbers (plus
        /// <c>CERTINEXT_RENEWAL_E2E=1</c>) and run this test.  No-op when the list is unset.
        /// </summary>
        [SkippableFact]
        public async Task CleanupLeftoverOrders()
        {
            IntegrationSkip.IfNotConfigured(_fixture);
            Skip.If(Environment.GetEnvironmentVariable(OptInFlag) != "1",
                $"Opt-in: export {OptInFlag}=1 in the shell.");
            string list = Environment.GetEnvironmentVariable("CERTINEXT_RENEWAL_E2E_CLEANUP_ORDERS");
            Skip.If(string.IsNullOrWhiteSpace(list), "CERTINEXT_RENEWAL_E2E_CLEANUP_ORDERS not set.");

            var plugin = new CERTInextCAPlugin(_fixture.Client, BuildConfig());
            var ids = list.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            (await CleanupAsync(plugin, ids)).Should().BeTrue("every listed order must end revoked/cancelled");
        }

        private static bool SerialHexEquals(string a, string b) =>
            string.Equals(a?.TrimStart('0'), b?.TrimStart('0'), StringComparison.OrdinalIgnoreCase);
    }
}
#endif
