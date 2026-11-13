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
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Moq;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// The V2 spec's <c>Agreement</c> schema (SSL create and signature create alike) is exactly
    /// <c>signerName</c> / <c>signerPlace</c> / <c>accepted</c>: there is no <c>signerIp</c>, so the
    /// connector and template <c>SignerIp</c> settings are V1-only and must never reach a V2 body.
    /// </summary>
    public class V2AgreementSignerIpTests
    {
        private const string OrderId = "ord_sip_001";

        [Fact]
        public void V2AgreementParams_HasNoSignerIpMember_AndSerializesToTheSpecShape()
        {
            typeof(V2AgreementParams).GetProperties().Select(p => p.Name)
                .Should().NotContain("SignerIp");

            var json = JsonSerializer.Serialize(
                new V2AgreementParams { SignerName = "A", SignerPlace = "B", Accepted = true },
                new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull });

            json.Should().NotContain("signerIp");
            json.Should().Be("{\"signerName\":\"A\",\"signerPlace\":\"B\",\"accepted\":true}");
        }

        [Fact]
        public async Task EnrollV2_WithConnectorAndTemplateSignerIp_NeverPutsSignerIpOnTheWire()
        {
            var mock = new Mock<ICERTInextClient>(MockBehavior.Strict);
            V2CreateSslOrderRequest captured = null;
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .Callback<string, string, V2CreateSslOrderRequest, CancellationToken>((_, __, req, ___) => captured = req)
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = OrderId, Status = "pending-dcv" });
            mock.Setup(c => c.SubmitCsrV2Async(It.IsAny<string>(), OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            mock.Setup(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = "pending-dcv" });

            var plugin = new CERTInextCAPlugin(mock.Object, new CERTInextConfig
            {
                UseV2Api          = true,
                ApiUrl            = "https://v2.certinext.io",
                OAuthClientId     = "my-client",
                OAuthClientSecret = "my-secret",
                RequestorName     = "Test User",
                RequestorEmail    = "test@example.com",
                SignerPlace       = "New York",
                SignerIp          = "203.0.113.10",
                PickupRetries     = 0
            });
            var productInfo = new EnrollmentProductInfo
            {
                ProductID = Constants.Products.DvSsl,
                ProductParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["ProductFamily"] = "ssl",
                    ["DomainName"]    = "example.com",
                    ["SignerIp"]      = "198.51.100.7"
                }
            };

            await plugin.Enroll(MockCertificateData.FakeCsrPem, "CN=example.com",
                new Dictionary<string, string[]>(), productInfo, RequestFormat.PKCS10,
                EnrollmentType.New);

            captured.Should().NotBeNull();
            string body = JsonSerializer.Serialize(captured,
                new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull });
            body.Should().Contain("\"agreement\":{\"signerName\":\"Test User\",\"signerPlace\":\"New York\",\"accepted\":true}");
            body.ToLowerInvariant().Should().NotContain("signerip");
            body.Should().NotContain("203.0.113.10").And.NotContain("198.51.100.7");
        }
    }
}
