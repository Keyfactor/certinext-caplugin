// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// At http://www.apache.org/licenses/LICENSE-2.0

using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Keyfactor.Extensions.CAPlugin.CERTInext;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationRunner
{
    /// <summary>
    /// Minimal integration runner that exercises CERTInextClient against the live API.
    ///
    /// Reads credentials from ~/.env_certinext (KEY=VALUE format).
    /// Runs in three phases:
    ///   1. Ping  — ValidateCredentials
    ///   2. ListOrders — GetOrderReport (synchronize path)
    ///   3. If an ORDER_NUMBER env var or arg is provided, TrackOrder for that specific order
    /// </summary>
    internal static class Program
    {
        static async Task<int> Main(string[] args)
        {
            Console.WriteLine("=== CERTInext Integration Runner ===");
            Console.WriteLine();

            // Load credentials from ~/.env_certinext
            var env = LoadEnvFile(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".env_certinext"));

            string apiUrl         = Require(env, "CERTINEXT_API_URL");
            string accessKey      = Require(env, "CERTINEXT_ACCESS_KEY");
            string accountNumber  = Require(env, "CERTINEXT_ACCOUNT_NUMBER");
            string groupNumber    = env.GetValueOrDefault("CERTINEXT_GROUP_NUMBER", string.Empty);
            string requestorEmail = env.GetValueOrDefault("CERTINEXT_REQUESTOR_EMAIL", "plugin-test@keyfactor.com");
            string requestorName  = env.GetValueOrDefault("CERTINEXT_REQUESTOR_NAME", "Keyfactor Plugin Test");

            // Optional: order number to track (can also pass as first CLI argument)
            string targetOrderNumber = args.Length > 0 ? args[0] : env.GetValueOrDefault("CERTINEXT_TEST_ORDER_NUMBER", null);

            Console.WriteLine($"API URL:        {apiUrl}");
            Console.WriteLine($"Account Number: {accountNumber}");
            Console.WriteLine($"Group Number:   {groupNumber}");
            Console.WriteLine($"Requestor:      {requestorName} <{requestorEmail}>");
            if (targetOrderNumber != null)
                Console.WriteLine($"Target Order:   {targetOrderNumber}");
            Console.WriteLine();

            var config = new CERTInextConfig
            {
                ApiUrl          = apiUrl.TrimEnd('/') + "/",
                AuthMode        = "AccessKey",
                ApiKey          = accessKey,
                AccountNumber   = accountNumber,
                RequestorName   = requestorName,
                RequestorEmail  = requestorEmail,
                RequestorIsdCode = "1",
                RequestorMobileNumber = "0000000000",
                SignerPlace      = "Gateway",
                SignerIp         = "127.0.0.1",
                DefaultProductCode = env.GetValueOrDefault("CERTINEXT_PRODUCT_CODE", "100"),
                PageSize         = 100
            };

            var client = new CERTInextClient(config);
            var ct = CancellationToken.None;

            // -----------------------------------------------------------------------
            // Phase 1: Ping
            // -----------------------------------------------------------------------
            Console.WriteLine("--- Phase 1: ValidateCredentials (Ping) ---");
            try
            {
                await client.PingAsync(ct);
                Console.WriteLine("[PASS] Ping succeeded.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[FAIL] Ping failed: {ex.Message}");
                return 1;
            }
            Console.WriteLine();

            // -----------------------------------------------------------------------
            // Phase 2: GetProductDetails
            // -----------------------------------------------------------------------
            Console.WriteLine("--- Phase 2: GetProductDetails ---");
            try
            {
                var products = await client.GetProductDetailsAsync(ct);
                Console.WriteLine($"[PASS] Received {products.Count} product(s).");
                foreach (var p in products)
                    Console.WriteLine($"  ProductCode={p.ProductCode,-6}  Name={p.ProductName}  Type={p.ProductType}  Active={p.Active}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WARN] GetProductDetails failed: {ex.Message}");
                Console.WriteLine("       Continuing — this does not block other tests.");
            }
            Console.WriteLine();

            // -----------------------------------------------------------------------
            // Phase 3: ListOrdersAsync (GetOrderReport synchronize path)
            // -----------------------------------------------------------------------
            Console.WriteLine("--- Phase 3: ListOrdersAsync (GetOrderReport sync path) ---");
            int orderCount = 0;
            bool targetFound = false;
            try
            {
                await foreach (var order in client.ListOrdersAsync(orderDateFrom: null, pageSize: 100, ct: ct))
                {
                    orderCount++;
                    bool isTarget = targetOrderNumber != null && order.OrderNumber == targetOrderNumber;
                    string marker = isTarget ? " <-- TARGET ORDER" : string.Empty;
                    Console.WriteLine(
                        $"  Order={order.OrderNumber}  Product={order.ProductCode}  " +
                        $"Domain={order.DomainName}  OrderStatus={order.OrderStatus}  " +
                        $"CertStatus={order.CertificateStatus}{marker}");
                    if (isTarget)
                        targetFound = true;
                }
                Console.WriteLine($"[PASS] Enumerated {orderCount} order(s) via GetOrderReport.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[FAIL] ListOrdersAsync failed: {ex.Message}");
                return 1;
            }
            Console.WriteLine();

            // -----------------------------------------------------------------------
            // Phase 4: TrackOrder for specific order (if provided)
            // -----------------------------------------------------------------------
            if (targetOrderNumber != null)
            {
                Console.WriteLine($"--- Phase 4: TrackOrder for {targetOrderNumber} ---");
                try
                {
                    var track = await client.TrackOrderAsync(targetOrderNumber, ct);
                    var od = track.OrderDetails;
                    Console.WriteLine($"[PASS] TrackOrder succeeded.");
                    Console.WriteLine($"  OrderStatus:      {od?.OrderStatus} (id={od?.OrderStatusId})");
                    Console.WriteLine($"  CertStatus:       {od?.CertificateStatus} (id={od?.CertificateStatusId})");
                    Console.WriteLine($"  ExpiryDate:       {od?.CertificateExpiryDate}");
                    Console.WriteLine($"  TrackingUrl:      {od?.TrackingUrl}");
                    if (od?.RequestorInformation != null)
                        Console.WriteLine($"  RequestorEmail:   {od.RequestorInformation.RequestorEmail}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[FAIL] TrackOrder failed: {ex.Message}");
                }
                Console.WriteLine();

                if (targetFound)
                    Console.WriteLine($"[PASS] Target order {targetOrderNumber} WAS found in the GetOrderReport sync results.");
                else if (orderCount > 0)
                    Console.WriteLine($"[WARN] Target order {targetOrderNumber} was NOT found in GetOrderReport results " +
                                      $"(got {orderCount} orders — it may be on a later page or filtered out).");
                else
                    Console.WriteLine($"[WARN] GetOrderReport returned 0 orders — target could not be confirmed.");
            }

            Console.WriteLine();
            Console.WriteLine("=== Integration Runner Complete ===");
            return 0;
        }

        // -----------------------------------------------------------------------
        // Helpers
        // -----------------------------------------------------------------------

        private static Dictionary<string, string> LoadEnvFile(string path)
        {
            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (!File.Exists(path))
            {
                Console.WriteLine($"[WARN] ~/.env_certinext not found at {path}; relying on environment variables only.");
                return result;
            }
            foreach (string rawLine in File.ReadAllLines(path))
            {
                string line = rawLine.Trim();
                if (string.IsNullOrEmpty(line) || line.StartsWith("#"))
                    continue;
                int idx = line.IndexOf('=');
                if (idx <= 0) continue;
                string key = line.Substring(0, idx).Trim();
                string val = line.Substring(idx + 1).Trim();
                result[key] = val;
            }
            // Also overlay real environment variables so they take precedence
            foreach (System.Collections.DictionaryEntry de in System.Environment.GetEnvironmentVariables())
            {
                string k = de.Key?.ToString();
                string v = de.Value?.ToString();
                if (!string.IsNullOrEmpty(k))
                    result[k] = v ?? string.Empty;
            }
            return result;
        }

        private static string Require(Dictionary<string, string> env, string key)
        {
            if (env.TryGetValue(key, out string val) && !string.IsNullOrWhiteSpace(val))
                return val;
            Console.Error.WriteLine($"[ERROR] Required env var '{key}' is not set in ~/.env_certinext");
            Environment.Exit(1);
            return null; // unreachable
        }
    }
}
