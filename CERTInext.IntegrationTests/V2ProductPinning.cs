// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using Keyfactor.AnyGateway.Extensions;
using Xunit.Sdk;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// How a V2 enrollment test selects the CERTInext product, mirroring the two gateway template
    /// sets registered by <c>scripts/register/02-gateway-ca-config.sh</c>.
    /// </summary>
    public enum V2PinMode
    {
        /// <summary>
        /// "Pinned" template: <c>ProductID</c> is the product name (e.g. "DV SSL") and the template
        /// carries an explicit <c>ProductCode</c>, so the plugin sends <c>X-Product-Code</c>.
        /// </summary>
        Pinned,

        /// <summary>
        /// "V2 template" (unpinned): same <c>ProductID</c> but NO <c>ProductCode</c> parameter, so
        /// the plugin sends no <c>X-Product-Code</c> and CERTInext resolves the product itself.
        /// </summary>
        V2Template,
    }

    /// <summary>
    /// Builds the <see cref="EnrollmentProductInfo"/> a gateway template would hand the plugin, in
    /// either <see cref="V2PinMode"/>, and supplies the pin-mode rows for parameterised V2 tests.
    /// </summary>
    internal static class V2ProductPinning
    {
        /// <summary>
        /// Sandbox V2 catalog product codes per product name (the same codes stage 02's
        /// <c>PRODUCT_CODE_MAP_JSON</c> pins on the lab gateway: DV 842-845, OV 846-849, EV 850-851).
        /// Product codes are per-environment; override with <c>CERTINEXT_PRODUCT_CODE_MAP_JSON</c>
        /// (e.g. <c>{"OV SSL":"900"}</c>) or, for DV SSL only, <c>CERTINEXT_PRODUCT_CODE</c>.
        /// </summary>
        private static readonly Dictionary<string, string> SandboxCodes =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                [Constants.Products.DvSsl]            = "842",
                [Constants.Products.DvSslWildcard]    = "843",
                [Constants.Products.DvSslUcc]         = "844",
                [Constants.Products.DvSslWildcardUcc] = "845",
                [Constants.Products.OvSsl]            = "846",
                [Constants.Products.OvSslWildcard]    = "847",
                [Constants.Products.OvSslUcc]         = "848",
                [Constants.Products.OvSslWildcardUcc] = "849",
                [Constants.Products.EvSsl]            = "850",
                [Constants.Products.EvSslUcc]         = "851",
            };

        /// <summary>Both modes, in run order (pinned first).</summary>
        public static readonly V2PinMode[] AllModes = { V2PinMode.Pinned, V2PinMode.V2Template };

        /// <summary>
        /// The product code a pinned template would carry for <paramref name="productId"/>:
        /// <c>CERTINEXT_PRODUCT_CODE_MAP_JSON</c> entry, else (DV SSL only) <c>CERTINEXT_PRODUCT_CODE</c>,
        /// else the sandbox default. Reads the V2 env file via <see cref="V2EnvHelper"/> so a V2-file value
        /// wins over the V1 fixture's.
        /// </summary>
        public static string CodeFor(string productId)
        {
            var env = V2EnvHelper.LoadAndPromote();

            string mapJson = V2EnvHelper.GetEnv(env, "CERTINEXT_PRODUCT_CODE_MAP_JSON");
            if (!string.IsNullOrWhiteSpace(mapJson))
            {
                var map = JsonSerializer.Deserialize<Dictionary<string, string>>(mapJson)
                          ?? new Dictionary<string, string>();
                var hit = map.FirstOrDefault(kv => string.Equals(kv.Key, productId, StringComparison.OrdinalIgnoreCase));
                if (!string.IsNullOrWhiteSpace(hit.Value))
                    return hit.Value;
            }

            if (string.Equals(productId, Constants.Products.DvSsl, StringComparison.OrdinalIgnoreCase))
                return V2EnvHelper.GetEnv(env, "CERTINEXT_PRODUCT_CODE", SandboxCodes[Constants.Products.DvSsl]);

            if (SandboxCodes.TryGetValue(productId, out string code))
                return code;

            throw new ArgumentException(
                $"No sandbox product code known for ProductID '{productId}'; add it to CERTINEXT_PRODUCT_CODE_MAP_JSON.",
                nameof(productId));
        }

        /// <summary>
        /// The <c>ProductCode</c> a template in <paramref name="mode"/> carries: the pinned code, or
        /// <c>null</c> for a V2 template (the parameter is absent entirely).
        /// </summary>
        public static string CodeSent(string productId, V2PinMode mode) =>
            mode == V2PinMode.Pinned ? CodeFor(productId) : null;

        /// <summary>
        /// Product info as the gateway would deliver it for the template in <paramref name="mode"/>:
        /// <c>ProductID</c> = product name, <c>ValidityYears</c> = 1 (as on the lab templates), plus
        /// <c>ProductCode</c> only when pinned. <paramref name="extraParameters"/> (e.g. PriorCertSN) are added last.
        /// </summary>
        public static EnrollmentProductInfo Info(
            string productId, V2PinMode mode, IDictionary<string, string> extraParameters = null)
        {
            var parameters = new Dictionary<string, string>
            {
                [Constants.EnrollmentParam.ValidityYears] = "1",
            };

            string code = CodeSent(productId, mode);
            if (code != null)
                parameters[Constants.EnrollmentParam.ProductCode] = code;

            if (extraParameters != null)
                foreach (var kv in extraParameters)
                    parameters[kv.Key] = kv.Value;

            return new EnrollmentProductInfo { ProductID = productId, ProductParameters = parameters };
        }

        /// <summary>Short label for test output, e.g. <c>[pinned DV SSL ProductCode=842]</c>.</summary>
        public static string Label(string productId, V2PinMode mode) =>
            mode == V2PinMode.Pinned
                ? $"[pinned {productId} ProductCode={CodeFor(productId)}]"
                : $"[V2 template (unpinned) {productId} no ProductCode]";

        /// <summary>
        /// Logs which mode a test row runs in plus, when the response exposes it (raw-client order
        /// create), the product CERTInext actually resolved.
        /// </summary>
        public static void Log(
            Xunit.Abstractions.ITestOutputHelper output, string productId, V2PinMode mode, string resolvedProductCode = null)
        {
            output.WriteLine(Label(productId, mode)
                + (resolvedProductCode == null ? string.Empty : $" ResolvedProductCode={resolvedProductCode}"));
        }

        /// <summary>
        /// A V2-template (unpinned) row does not exercise pinning when the test is handed a pre-existing
        /// order via an env var instead of enrolling: skip it so the same order is not reused twice.
        /// </summary>
        public static void SkipUnpinnedWhenOrderSuppliedByEnv(V2PinMode mode, string envOrderId, string envVarName)
        {
            Xunit.Skip.If(mode == V2PinMode.V2Template && !string.IsNullOrWhiteSpace(envOrderId),
                $"{envVarName} is set: the test uses that existing order and does not enroll, so the pin mode is " +
                "irrelevant. Only the pinned row runs.");
        }
    }

    /// <summary>
    /// xUnit data source: one row per <see cref="V2PinMode"/> (<c>mode</c> as the sole argument).
    /// Rows display as <c>Test(mode: Pinned)</c> / <c>Test(mode: V2Template)</c>, so
    /// <c>--filter "DisplayName~V2Template"</c> or <c>"DisplayName~Pinned"</c> selects one set.
    /// </summary>
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    internal sealed class V2PinModesAttribute : DataAttribute
    {
        public override IEnumerable<object[]> GetData(MethodInfo testMethod) =>
            V2ProductPinning.AllModes.Select(m => new object[] { m });
    }

    /// <summary>
    /// xUnit data source: the cross product of <see cref="KeyAlgorithms"/> tags and
    /// <see cref="V2PinMode"/>, as <c>(string tag, V2PinMode mode)</c>.
    /// </summary>
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    internal sealed class V2PinModesWithKeyAlgorithmsAttribute : DataAttribute
    {
        public override IEnumerable<object[]> GetData(MethodInfo testMethod) =>
            KeyAlgorithms.AsMemberData.SelectMany(
                row => V2ProductPinning.AllModes.Select(m => new object[] { row[0], m }));
    }
}
