// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// At http://www.apache.org/licenses/LICENSE-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Basic smoke tests — one operation per test, no side effects.
    /// These verify the API is reachable and returning sensible data without
    /// creating or modifying any orders.
    ///
    /// All tests skip when CERTInext credentials are absent (<see cref="IntegrationSkip"/>).
    /// </summary>
    public class SmokeTests : IClassFixture<IntegrationTestFixture>
    {
        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;

        public SmokeTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output = output;
        }

        [SkippableFact]
        public async Task Ping_Succeeds()
        {
            IntegrationSkip.IfNotConfigured(_fixture);

            await _fixture.Client.Invoking(c => c.PingAsync())
                .Should().NotThrowAsync("credentials should be valid and API should be reachable");
        }

        [SkippableFact]
        public async Task GetProductDetails_ReturnsProducts()
        {
            IntegrationSkip.IfNotConfigured(_fixture);

            var products = await _fixture.Client.GetProductDetailsAsync();

            products.Should().NotBeNullOrEmpty("account must have at least one product configured");

            foreach (var p in products)
                _output.WriteLine($"  ProductCode={p.ProductCode}  Name={p.ProductName}  Type={p.ProductType}");
        }

        [SkippableFact]
        public async Task ListOrders_ReturnsFirstPage()
        {
            IntegrationSkip.IfNotConfigured(_fixture);

            var orders = new List<API.OrderReportEntry>();

            await foreach (var entry in _fixture.Client.ListOrdersAsync(pageSize: 10))
            {
                orders.Add(entry);
                if (orders.Count >= 10) break;
            }

            orders.Should().NotBeEmpty("sandbox account should have at least one order");

            _output.WriteLine($"Returned {orders.Count} orders (capped at 10):");
            foreach (var o in orders)
                _output.WriteLine($"  OrderNumber={o.OrderNumber}  Domain={o.DomainName}  Status={o.CertificateStatus}  Expiry={o.CertificateExpiryDate}");
        }

        [SkippableFact]
        public async Task TrackOrder_ReturnsDetails()
        {
            IntegrationSkip.IfNotConfigured(_fixture);

            string orderId = System.Environment.GetEnvironmentVariable("CERTINEXT_ORDER_ID");
            Skip.If(string.IsNullOrWhiteSpace(orderId),
                "Set CERTINEXT_ORDER_ID in ~/.env_certinext to run this test.");

            var response = await _fixture.Client.TrackOrderAsync(orderId);

            response.Should().NotBeNull();
            response.OrderDetails.Should().NotBeNull();

            var od = response.OrderDetails;
            _output.WriteLine($"OrderNumber:       {orderId}");
            _output.WriteLine($"OrderStatus:       {od.OrderStatus} (id={od.OrderStatusId})");
            _output.WriteLine($"CertificateStatus: {od.CertificateStatus} (id={od.CertificateStatusId})");
            _output.WriteLine($"CertificateExpiry: {od.CertificateExpiryDate}");
            _output.WriteLine($"TrackingUrl:       {od.TrackingUrl}");

            if (od.DomainVerification != null)
            {
                foreach (var kv in od.DomainVerification.GetDomainEntries())
                    _output.WriteLine($"  Domain [{kv.Key}]: dcvMethod={kv.Value.DcvMethod} dcvStatus={kv.Value.DcvStatus} verifiedDate={kv.Value.VerifiedDate}");
            }
        }

        [SkippableFact]
        public async Task GetSingleRecord_ReturnsRecord()
        {
            IntegrationSkip.IfNotConfigured(_fixture);

            string orderId = System.Environment.GetEnvironmentVariable("CERTINEXT_ORDER_ID");
            Skip.If(string.IsNullOrWhiteSpace(orderId),
                "Set CERTINEXT_ORDER_ID in ~/.env_certinext to run this test.");

            var plugin = new CERTInextCAPlugin(_fixture.Client, _fixture.Config);
            var record = await plugin.GetSingleRecord(orderId);

            record.Should().NotBeNull();

            _output.WriteLine($"CARequestID:  {record.CARequestID}");
            _output.WriteLine($"Status:       {record.Status}");
            _output.WriteLine($"Certificate:  {(string.IsNullOrWhiteSpace(record.Certificate) ? "(not yet issued)" : record.Certificate[..60] + "...")}");
        }

        /// <summary>
        /// Exercises <see cref="CERTInextCAPlugin.GetSingleRecord"/> against every order
        /// returned by <c>ListOrdersAsync</c>.  Validates that the per-order plugin
        /// code path (TrackOrder → GetCertificate → AnyCAPluginCertificate mapping)
        /// succeeds for every order on the account, regardless of certificate status.
        /// </summary>
        [SkippableFact]
        public async Task GetSingleRecord_ForAllOrders_AllSucceed()
        {
            IntegrationSkip.IfNotConfigured(_fixture);

            var plugin = new CERTInextCAPlugin(_fixture.Client, _fixture.Config);

            var orderNumbers = new List<string>();
            await foreach (var entry in _fixture.Client.ListOrdersAsync())
            {
                if (!string.IsNullOrWhiteSpace(entry.OrderNumber))
                    orderNumbers.Add(entry.OrderNumber);
            }

            orderNumbers.Should().NotBeEmpty("sandbox account should have at least one order");
            _output.WriteLine($"Calling GetSingleRecord for {orderNumbers.Count} order(s):");

            var failures = new List<(string Order, string Error)>();
            foreach (var orderId in orderNumbers)
            {
                try
                {
                    var record = await plugin.GetSingleRecord(orderId);
                    string certPreview = string.IsNullOrWhiteSpace(record.Certificate)
                        ? "(none)"
                        : $"{record.Certificate.Length} chars";
                    _output.WriteLine($"  [OK]   Order={orderId}  Status={record.Status}  Cert={certPreview}");
                }
                catch (Exception ex)
                {
                    failures.Add((orderId, ex.Message));
                    _output.WriteLine($"  [FAIL] Order={orderId}  Error={ex.Message}");
                }
            }

            failures.Should().BeEmpty(
                $"every order's GetSingleRecord call should succeed; {failures.Count} failed: " +
                string.Join("; ", failures.Select(f => $"{f.Order}={f.Error}")));
        }

        [SkippableFact]
        public async Task Synchronize_DumpsAllRecords()
        {
            IntegrationSkip.IfNotConfigured(_fixture);

            var plugin = new CERTInextCAPlugin(_fixture.Client, _fixture.Config);

            var records = new List<Keyfactor.AnyGateway.Extensions.AnyCAPluginCertificate>();
            var blockingCollection = new System.Collections.Concurrent.BlockingCollection<Keyfactor.AnyGateway.Extensions.AnyCAPluginCertificate>();

            var syncTask = plugin.Synchronize(blockingCollection, lastSync: null, fullSync: true, cancelToken: default);
            var collectTask = Task.Run(() =>
            {
                foreach (var r in blockingCollection.GetConsumingEnumerable())
                    records.Add(r);
            });

            await syncTask;
            blockingCollection.CompleteAdding();
            await collectTask;

            records.Should().NotBeEmpty("sandbox account should have at least one order");

            _output.WriteLine($"Synchronized {records.Count} records:");
            foreach (var r in records.Take(20))
                _output.WriteLine($"  CARequestID={r.CARequestID}  Status={r.Status}");

            if (records.Count > 20)
                _output.WriteLine($"  ... and {records.Count - 20} more");
        }
    }
}
