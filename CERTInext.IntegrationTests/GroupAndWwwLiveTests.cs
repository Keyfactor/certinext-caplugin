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
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Live-sandbox proof of the V1 <c>GenerateOrderSSL</c> body fix: <c>orderDetails.groupNumber</c>
    /// and <c>orderDetails.autoSecureWWW</c> must be honoured by CERTInext for both new enrollment and
    /// the renewal path (<c>RenewCertificateAsync</c>, which shares <c>BuildSslOrderDetails</c>).
    ///
    /// Checks per order:
    ///   1. The order appears in <c>GetOrderReport</c> (ListOrders) under the configured group.
    ///   2. The <c>TrackOrder</c> domain list contains the requested name and no <c>www.</c> entry.
    ///
    /// Opt-in: set <c>CERTINEXT_WS1C_LIVE=1</c> as a REAL environment variable.  A value placed in
    /// <c>~/.env_certinext</c> is deliberately ignored (the fixture promotes file values into the
    /// process environment, so the file is inspected to refuse that case).  Also requires
    /// <c>CERTINEXT_GROUP_NUMBER</c>.  Every order created is revoked in a finally block and the
    /// final state is re-read and printed.
    /// </summary>
    public class GroupAndWwwLiveTests : IClassFixture<IntegrationTestFixture>
    {
        private const string OptInFlag = "CERTINEXT_WS1C_LIVE";

        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;

        public GroupAndWwwLiveTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output = output;
        }

        // ---------------------------------------------------------------------------
        // Gating + helpers
        // ---------------------------------------------------------------------------

        private void SkipUnlessOptedIn()
        {
            IntegrationSkip.IfNotConfigured(_fixture);

            Skip.If(Environment.GetEnvironmentVariable(OptInFlag) != "1",
                $"Opt-in: set {OptInFlag}=1 as a real environment variable to place live sandbox orders.");

            string envFile = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".env_certinext");
            bool inFile = File.Exists(envFile) && File.ReadAllLines(envFile)
                .Any(l => l.TrimStart().StartsWith(OptInFlag + "=", StringComparison.Ordinal));
            Skip.If(inFile, $"{OptInFlag} must be a real environment variable, not set in ~/.env_certinext.");

            Skip.If(string.IsNullOrWhiteSpace(_fixture.Config.GroupNumber),
                "CERTINEXT_GROUP_NUMBER is required to prove group placement.");
        }

        private CERTInextConfig BuildConfig(bool dcvEnabled)
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
                DefaultProductCode    = c.DefaultProductCode,
                PageSize              = c.PageSize,
                AutoSecureWww         = "0",
                DcvEnabled                 = dcvEnabled,
                DcvPropagationDelaySeconds = 5,
                DcvTimeoutMinutes          = 3,
            };
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

        // Local copy: IntegrationTestData lives in DcvLifecycleTests.cs, which is excluded on non-DCV builds.
        private EnrollmentProductInfo DvProductInfo()
        {
            string code = _fixture.Config.DefaultProductCode ?? Constants.Products.DvSsl;
            return new EnrollmentProductInfo
            {
                ProductID         = code,
                ProductParameters = new Dictionary<string, string>
                {
                    ["ProfileId"]     = code,
                    ["ValidityYears"] = "1"
                }
            };
        }

        private static Dictionary<string, string[]> DnsSan(string cn) =>
            new Dictionary<string, string[]> { ["dns"] = new[] { cn } };

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

        /// <summary>
        /// Domain names from TrackOrder.domainVerification.  Polled briefly because CERTInext may
        /// populate the block a few seconds after order placement.
        /// </summary>
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

        private void AssertGroupAndNoWww(string label, string orderNumber, OrderReportEntry entry, List<string> domains, string cn)
        {
            entry.Should().NotBeNull($"{label} order {orderNumber} must be listed by GetOrderReport");
            bool groupMatches = string.Equals(entry!.GroupNumber, _fixture.Config.GroupNumber, StringComparison.Ordinal);
            _output.WriteLine($"  [{label}] {orderNumber}: ListOrders groupNumber matches configured group = {groupMatches} " +
                              $"(report groupNumber blank = {string.IsNullOrWhiteSpace(entry.GroupNumber)})");
            _output.WriteLine($"  [{label}] {orderNumber}: TrackOrder domains = [{string.Join(", ", domains)}]; " +
                              $"report domainName = {entry.DomainName}");

            groupMatches.Should().BeTrue($"{label} order must land in the configured CERTInext group");
            domains.Should().Contain(d => string.Equals(d, cn, StringComparison.OrdinalIgnoreCase),
                "the TrackOrder domain list must be populated (otherwise 'no www' is vacuous)");
            domains.Should().NotContain(d => d.StartsWith("www.", StringComparison.OrdinalIgnoreCase),
                $"{label} order was placed with AutoSecureWww=0 so no www. SAN may be added");
        }

        /// <summary>
        /// Revokes every created order (plugin path for issued certs, raw revoke attempt otherwise),
        /// then re-reads each order read-only and prints its final state.
        /// </summary>
        private async Task CleanupAsync(CERTInextCAPlugin plugin, IEnumerable<string> orderNumbers)
        {
            foreach (string id in orderNumbers.Where(o => !string.IsNullOrWhiteSpace(o)).Distinct())
            {
                try
                {
                    var before = await _fixture.Client.TrackOrderAsync(id);
                    int.TryParse(before.OrderDetails?.CertificateStatusId, out int st);
                    _output.WriteLine($"  cleanup {id}: before certificateStatusId={st} ({before.OrderDetails?.CertificateStatus})");
                    if (st == Constants.CertificateStatusId.CertificateRevoked)
                        continue;

                    if (st == Constants.CertificateStatusId.CertificateGenerated
                        || st == Constants.CertificateStatusId.CertificateDownloaded)
                    {
                        int rc = await plugin.Revoke(id, string.Empty, 5);
                        _output.WriteLine($"  cleanup {id}: plugin.Revoke returned {rc}");
                    }
                    else
                    {
                        // Not issued: the plugin refuses (revocable only when GENERATED). Try the raw
                        // revoke and record exactly what CERTInext says; do not work around a refusal.
                        await _fixture.Client.RevokeCertificateAsync(id, new RevokeCertificateRequest
                        {
                            Reason = Constants.RevocationReason.CessationOfOperation,
                            Comment = "ws1c live-test cleanup"
                        });
                        _output.WriteLine($"  cleanup {id}: raw RevokeCertificateAsync accepted for non-issued order");
                    }
                }
                catch (Exception ex)
                {
                    _output.WriteLine($"  cleanup {id}: REVOKE/CANCEL FAILED -> {ex.GetType().Name}: {Truncate(ex.Message)}");
                }
            }

            _output.WriteLine("  --- cleanup verification (fresh read-only TrackOrder) ---");
            foreach (string id in orderNumbers.Where(o => !string.IsNullOrWhiteSpace(o)).Distinct())
            {
                try
                {
                    var after = await _fixture.Client.TrackOrderAsync(id);
                    _output.WriteLine($"  verify {id}: orderStatusId={after.OrderDetails?.OrderStatusId} ({after.OrderDetails?.OrderStatus}), " +
                                      $"certificateStatusId={after.OrderDetails?.CertificateStatusId} ({after.OrderDetails?.CertificateStatus})");
                }
                catch (Exception ex)
                {
                    _output.WriteLine($"  verify {id}: TrackOrder failed -> {ex.GetType().Name}: {Truncate(ex.Message)}");
                }
            }
        }

        private static string Truncate(string s) => s != null && s.Length > 500 ? s.Substring(0, 500) : s;

        // ---------------------------------------------------------------------------
        // Test A: new enrollment (compiles on both DcvSupport variants)
        // ---------------------------------------------------------------------------

        [SkippableFact]
        public async Task NewOrder_AutoSecureWwwOff_LandsInConfiguredGroup_WithNoWwwSan()
        {
            SkipUnlessOptedIn();

            string cn = $"ws1c-a-{Guid.NewGuid():N}".Substring(0, 20) + ".scrup.org";
            var plugin = new CERTInextCAPlugin(_fixture.Client, BuildConfig(dcvEnabled: false));
            var created = new List<string>();
            try
            {
                var result = await plugin.Enroll(
                    GenerateCsrPem(cn), $"CN={cn}", DnsSan(cn),
                    DvProductInfo(),
                    RequestFormat.PKCS10, EnrollmentType.New);
                created.Add(result.CARequestID);
                _output.WriteLine($"Enrolled order {result.CARequestID}, status={result.Status}");
                result.CARequestID.Should().NotBeNullOrWhiteSpace();

                var entry = await FindInOrderReportAsync(result.CARequestID);
                var domains = await GetDomainListAsync(result.CARequestID, cn);
                AssertGroupAndNoWww("new", result.CARequestID, entry, domains, cn);
            }
            finally
            {
                await CleanupAsync(plugin, created);
            }
        }

#if SUPPORTS_DCV
        // ---------------------------------------------------------------------------
        // Test B: new order -> DCV issuance -> renewal through RenewCertificateAsync
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Minimal ICertificateDataReader for the renewal path (the plugin only calls
        /// GetRequestIDBySerialNumber and GetExpirationDateByRequestId).  Built with DispatchProxy
        /// so the integration project needs no mocking package.
        /// </summary>
        public class ReaderProxy : DispatchProxy
        {
            public string RequestId { get; set; }
            public DateTime? Expiry { get; set; }

            protected override object Invoke(MethodInfo targetMethod, object[] args)
            {
                switch (targetMethod.Name)
                {
                    case "GetRequestIDBySerialNumber": return Task.FromResult(RequestId);
                    case "GetExpirationDateByRequestId": return Expiry;
                    default: throw new NotSupportedException(targetMethod.Name);
                }
            }
        }

        /// <summary>
        /// Forwarding decorator over the live client that records which interface methods the plugin
        /// called, so the test can prove the renewal went through RenewCertificateAsync rather than
        /// silently falling back to a new enrollment.
        /// </summary>
        public class RecordingClientProxy : DispatchProxy
        {
            public Client.ICERTInextClient Target { get; set; }
            public System.Collections.Concurrent.ConcurrentQueue<string> Calls { get; } =
                new System.Collections.Concurrent.ConcurrentQueue<string>();

            protected override object Invoke(MethodInfo targetMethod, object[] args)
            {
                Calls.Enqueue(targetMethod.Name);
                try
                {
                    return targetMethod.Invoke(Target, args);
                }
                catch (TargetInvocationException ex) when (ex.InnerException != null)
                {
                    System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(ex.InnerException).Throw();
                    throw;
                }
            }
        }

        [SkippableFact]
        public async Task IssuedOrder_RenewedViaRenewCertificateAsync_StaysInGroup_WithNoWwwSan()
        {
            SkipUnlessOptedIn();
            Skip.If(!_fixture.IsCloudflareConfigured,
                "CERTINEXT_CF_API_TOKEN + CERTINEXT_CF_ZONE_ID required to drive DCV to issuance.");

            string cn = $"ws1c-b-{Guid.NewGuid():N}".Substring(0, 20) + ".scrup.org";
            var config = BuildConfig(dcvEnabled: true);
            var factory = new CloudflareDomainValidatorFactory(_fixture.CloudflareApiToken, _fixture.CloudflareZoneId);
            var recorder = DispatchProxy.Create<Client.ICERTInextClient, RecordingClientProxy>();
            ((RecordingClientProxy)(object)recorder).Target = _fixture.Client;
            var calls = ((RecordingClientProxy)(object)recorder).Calls;
            var plugin = new CERTInextCAPlugin(recorder, factory, config);
            var reader = DispatchProxy.Create<ICertificateDataReader, ReaderProxy>();
            typeof(CERTInextCAPlugin)
                .GetField("_certificateDataReader", BindingFlags.NonPublic | BindingFlags.Instance)!
                .SetValue(plugin, reader);

            var created = new List<string>();
            try
            {
                // 1. New DV order, AutoSecureWww=0 + group, DCV-driven.
                var first = await plugin.Enroll(
                    GenerateCsrPem(cn), $"CN={cn}", DnsSan(cn),
                    DvProductInfo(),
                    RequestFormat.PKCS10, EnrollmentType.New);
                created.Add(first.CARequestID);
                first.CARequestID.Should().NotBeNullOrWhiteSpace();
                _output.WriteLine($"Original order {first.CARequestID}: Enroll status={first.Status}");

                // 2. Group + domain-list checks on the original order.
                AssertGroupAndNoWww("original", first.CARequestID,
                    await FindInOrderReportAsync(first.CARequestID),
                    await GetDomainListAsync(first.CARequestID, cn), cn);

                // 3. Drive to issuance (GetSingleRecord re-runs DCV for EXTERNALVALIDATION orders).
                await DriveToIssuanceAsync(plugin, first.CARequestID);
                var issued = await plugin.GetSingleRecord(first.CARequestID);
                _output.WriteLine($"Original order {first.CARequestID}: status after DCV = {issued.Status}");
                issued.Status.Should().Be((int)EndEntityStatus.GENERATED, "the renewal precondition is an issued certificate");

                // 4. Renew through the plugin's renewal path -> RenewCertificateAsync.
                var track = await _fixture.Client.TrackOrderAsync(first.CARequestID);
                DateTime.TryParse(track.OrderDetails?.CertificateExpiryDate, out var parsedExpiry);
                var proxy = (ReaderProxy)(object)reader;
                proxy.RequestId = first.CARequestID;
                proxy.Expiry = parsedExpiry == default ? DateTime.UtcNow.AddDays(30) : parsedExpiry.ToUniversalTime();

                var renewInfo = DvProductInfo();
                renewInfo.ProductParameters["PriorCertSN"] = "ws1c-prior-serial";
                renewInfo.ProductParameters["RenewalWindowDays"] = "800";   // force the renew API branch

                EnrollmentResult renewed;
                try
                {
                    renewed = await plugin.Enroll(
                        GenerateCsrPem(cn), $"CN={cn}", DnsSan(cn), renewInfo,
                        RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);
                }
                catch (Exception ex)
                {
                    _output.WriteLine($"RENEWAL REFUSED/FAILED: {ex.GetType().Name}: {Truncate(ex.Message)}");
                    throw;
                }

                created.Add(renewed.CARequestID);
                _output.WriteLine($"Renewal client calls: RenewCertificateAsync x{calls.Count(c => c == "RenewCertificateAsync")}");
                calls.Should().Contain("RenewCertificateAsync",
                    "the renewal must go through RenewCertificateAsync, not fall back to a fresh enrollment");
                _output.WriteLine($"Renewal order {renewed.CARequestID}: Enroll status={renewed.Status}, " +
                                  $"distinct from original = {renewed.CARequestID != first.CARequestID}");
                renewed.CARequestID.Should().NotBe(first.CARequestID);

                AssertGroupAndNoWww("renewal", renewed.CARequestID,
                    await FindInOrderReportAsync(renewed.CARequestID),
                    await GetDomainListAsync(renewed.CARequestID, cn), cn);

                // Let the renewal issue too, so it is cleanly revocable.
                await DriveToIssuanceAsync(plugin, renewed.CARequestID);
            }
            finally
            {
                await CleanupAsync(plugin, created);
            }
        }

        private async Task DriveToIssuanceAsync(CERTInextCAPlugin plugin, string orderNumber)
        {
            for (int pass = 1; pass <= 8; pass++)
            {
                var rec = await plugin.GetSingleRecord(orderNumber);
                _output.WriteLine($"  DCV pass {pass}: {orderNumber} status={rec.Status}");
                if (rec.Status == (int)EndEntityStatus.GENERATED)
                    return;
                await Task.Delay(TimeSpan.FromSeconds(20));
            }
        }
#endif
    }
}
