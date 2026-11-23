// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.Extensions.CAPlugin.CERTInext.Models;
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// V2 OV Organization Representative (<c>organization.useNewOrgRepresentative</c> +
    /// <c>organizationRepresentative</c>), driven by the <c>OrgRepresentative*</c> template parameters:
    /// validation mirrors the CA's EMS-1315/1316/1319/1320/1321 rules before any CA call, the wire body
    /// carries the block only when Name and Email are set, and the representative's details never reach
    /// a plugin log line. All data is synthetic.
    /// </summary>
    [Collection(LoggingStateCollection.Name)]
    public class V2OrgRepresentativeTests
    {
        private const string OrderId = "ord_rep_001";
        private const string RepName = "Rita Representative";
        private const string RepEmail = "rita.rep@example.com";
        private const string RepPhone = "+1 (555) 010-0199";
        private const string RepDesignation = "Chief Security Officer";
        private const string RepEmployeeId = "EMP-77231";

        private static Dictionary<string, string> Rep(
            string name = RepName, string email = RepEmail, string phone = null, string designation = null, string employeeId = null)
        {
            var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (name != null) d[Constants.EnrollmentParam.OrgRepresentativeName] = name;
            if (email != null) d[Constants.EnrollmentParam.OrgRepresentativeEmail] = email;
            if (phone != null) d[Constants.EnrollmentParam.OrgRepresentativePhone] = phone;
            if (designation != null) d[Constants.EnrollmentParam.OrgRepresentativeDesignation] = designation;
            if (employeeId != null) d[Constants.EnrollmentParam.OrgRepresentativeEmployeeId] = employeeId;
            return d;
        }

        private static EnrollmentProductInfo ProductInfo(string productId, Dictionary<string, string> extra = null)
        {
            var p = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ProductFamily"] = "ssl", ["DomainName"] = "example.com"
            };
            foreach (var kv in extra ?? new Dictionary<string, string>()) p[kv.Key] = kv.Value;
            return new EnrollmentProductInfo { ProductID = productId, ProductParameters = p };
        }

        private static string Validate(EnrollmentProductInfo pi, string organizationNumber, out V2OrganizationRepresentative rep)
        {
            var ep = new EnrollmentParams(pi);
            CERTInextCAPlugin.ResolveSslProductVariant(ep, out string variant).Should().BeNull();
            return CERTInextCAPlugin.ValidateOrgRepresentativeParams(ep, true, variant, organizationNumber, out rep);
        }

        // ---------------------------------------------------------------------------
        // ValidateOrgRepresentativeParams
        // ---------------------------------------------------------------------------

        [Fact]
        public void Validate_NoParameters_NoBlock_NoError()
        {
            Validate(ProductInfo(Constants.Products.DvSsl), "", out var rep).Should().BeNull();
            rep.Should().BeNull();
        }

        [Theory]
        [InlineData(Constants.Products.DvSsl)]
        [InlineData(Constants.Products.EvSsl)]
        [InlineData(Constants.Products.DvSslUcc)]
        public void Validate_NotOv_Rejected_Ems1315(string productId)
        {
            Validate(ProductInfo(productId, Rep()), "ORG-1", out var rep).Should().Contain("OV").And.Contain("EMS-1315");
            rep.Should().BeNull();
        }

        [Fact]
        public void Validate_NotSslFamily_Rejected()
        {
            var ep = new EnrollmentParams(ProductInfo(Constants.Products.OvSsl, Rep()));
            CERTInextCAPlugin.ValidateOrgRepresentativeParams(ep, false, "ov", "ORG-1", out _).Should().Contain("EMS-1315");
        }

        [Fact]
        public void Validate_NoOrganizationNumber_Rejected_Ems1316()
        {
            Validate(ProductInfo(Constants.Products.OvSsl, Rep()), " ", out _).Should().Contain("EMS-1316");
        }

        [Theory]
        [InlineData(RepName, null, null)]
        [InlineData(null, RepEmail, null)]
        [InlineData(null, null, "+15550100199")]   // optional field alone would be dropped silently
        public void Validate_NameAndEmailNotBothSet_Rejected(string name, string email, string phone)
        {
            Validate(ProductInfo(Constants.Products.OvSsl, Rep(name, email, phone)), "ORG-1", out _)
                .Should().Contain("OrgRepresentativeName").And.Contain("OrgRepresentativeEmail");
        }

        [Theory]
        [InlineData("not-an-email")]
        [InlineData("a@b@example.com")]
        [InlineData("rita rep@example.com")]
        public void Validate_BadEmail_Rejected_WithoutEchoingIt(string email)
        {
            string error = Validate(ProductInfo(Constants.Products.OvSsl, Rep(email: email)), "ORG-1", out _);
            error.Should().Contain("OrgRepresentativeEmail").And.NotContain(email);
        }

        [Theory]
        [InlineData("12345", false)]             // 5 digits
        [InlineData("1234567890123456", false)]  // 16 digits
        [InlineData("555-CALL-NOW", false)]
        [InlineData("++15550100199", false)]
        [InlineData("123456", true)]
        [InlineData("+1 (555) 010-0199", true)]
        [InlineData("555.010.0199", true)]
        [InlineData("123456789012345", true)]    // 15 digits
        public void Phone_Ems1321Rule(string phone, bool valid)
        {
            CERTInextCAPlugin.IsValidRepresentativePhone(phone).Should().Be(valid);
            string error = Validate(ProductInfo(Constants.Products.OvSsl, Rep(phone: phone)), "ORG-1", out _);
            if (valid) error.Should().BeNull();
            else error.Should().Contain("EMS-1321").And.NotContain(phone);
        }

        [Fact]
        public void Validate_Ov_BuildsBlock_OptionalFieldsOnlyWhenSet()
        {
            Validate(ProductInfo(Constants.Products.OvSslWildcard, Rep()), "ORG-1", out var rep).Should().BeNull();
            rep.Should().BeEquivalentTo(new V2OrganizationRepresentative { Name = RepName, Email = RepEmail });

            Validate(ProductInfo(Constants.Products.OvSsl, Rep(phone: RepPhone, designation: RepDesignation, employeeId: RepEmployeeId)),
                "ORG-1", out rep).Should().BeNull();
            rep.Should().BeEquivalentTo(new V2OrganizationRepresentative
            {
                Name = RepName, Email = RepEmail, Phone = RepPhone, Designation = RepDesignation, EmployeeId = RepEmployeeId
            });
        }

        // ---------------------------------------------------------------------------
        // Enroll: wire body, fail-fast, response logging
        // ---------------------------------------------------------------------------

        private static readonly JsonSerializerOptions ClientEquivalentJsonOptions = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        private static CERTInextConfig Config() => new CERTInextConfig
        {
            UseV2Api = true, ApiUrl = "https://v2.certinext.io", OAuthClientId = "id", OAuthClientSecret = "s",
            RequestorName = "Test User", RequestorEmail = "test@example.com", SignerPlace = "New York",
            OrganizationNumber = "ORG-001", PickupRetries = 0
        };

        private static (Mock<ICERTInextClient> Mock, Func<V2CreateSslOrderRequest> Captured) OvMock(V2CreateOrderResponse response)
        {
            var mock = new Mock<ICERTInextClient>();
            V2CreateSslOrderRequest captured = null;
            mock.Setup(c => c.PlaceOrderV2Async(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .Callback<string, string, V2CreateSslOrderRequest, CancellationToken>((_, __, req, ___) => captured = req)
                .ReturnsAsync(response);
            mock.Setup(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = "pending-organization-verification" });
            return (mock, () => captured);
        }

        private static Task<EnrollmentResult> Enroll(CERTInextCAPlugin plugin, EnrollmentProductInfo pi) =>
            plugin.Enroll(MockCertificateData.FakeCsrPem, "CN=example.com", null, pi, RequestFormat.PKCS10, EnrollmentType.New);

        [Fact]
        public async Task Enroll_Ov_WithRepresentative_SendsFlagAndBlock()
        {
            var (mock, captured) = OvMock(new V2CreateOrderResponse { OrderId = OrderId, Status = "pending-organization-verification" });
            var plugin = new CERTInextCAPlugin(mock.Object, Config());

            await Enroll(plugin, ProductInfo(Constants.Products.OvSsl,
                Rep(phone: "+15550100199", designation: "CSO", employeeId: "E-42")));

            JsonSerializer.Serialize(captured().Organization, ClientEquivalentJsonOptions).Should().Be(
                "{\"organizationNumber\":\"ORG-001\",\"preVetted\":true,\"useNewOrgRepresentative\":true," +
                "\"organizationRepresentative\":{\"name\":\"Rita Representative\",\"email\":\"rita.rep@example.com\"," +
                "\"phone\":\"\\u002B15550100199\",\"designation\":\"CSO\",\"employeeId\":\"E-42\"}}");
        }

        [Fact]
        public async Task Enroll_Ov_NameAndEmailOnly_OmitsOptionalKeys_NeverSendsEmpty()
        {
            var (mock, captured) = OvMock(new V2CreateOrderResponse { OrderId = OrderId, Status = "pending-organization-verification" });

            await Enroll(new CERTInextCAPlugin(mock.Object, Config()), ProductInfo(Constants.Products.OvSsl, Rep()));

            JsonSerializer.Serialize(captured().Organization.OrganizationRepresentative, ClientEquivalentJsonOptions)
                .Should().Be("{\"name\":\"Rita Representative\",\"email\":\"rita.rep@example.com\"}");
        }

        [Fact]
        public async Task Enroll_Ov_WithoutRepresentative_OrganizationBlockUnchanged()
        {
            var (mock, captured) = OvMock(new V2CreateOrderResponse { OrderId = OrderId, Status = "pending-organization-verification" });

            await Enroll(new CERTInextCAPlugin(mock.Object, Config()), ProductInfo(Constants.Products.OvSsl));

            JsonSerializer.Serialize(captured().Organization, ClientEquivalentJsonOptions)
                .Should().Be("{\"organizationNumber\":\"ORG-001\",\"preVetted\":true}");
        }

        [Theory]
        [InlineData(Constants.Products.DvSsl)]
        [InlineData(Constants.Products.EvSsl)]
        public async Task Enroll_DvOrEv_WithRepresentative_FailsBeforeAnyCaCall(string productId)
        {
            var mock = new Mock<ICERTInextClient>(MockBehavior.Strict);

            var result = await Enroll(new CERTInextCAPlugin(mock.Object, Config()), ProductInfo(productId, Rep()));

            result.Status.Should().Be((int)EndEntityStatus.FAILED);
            result.StatusMessage.Should().Contain("EMS-1315").And.NotContain(RepName).And.NotContain(RepEmail);
            mock.Invocations.Should().BeEmpty();
        }

        [Fact]
        public async Task Enroll_Ov_PendingApproval_LogsStatusAndPresence_NeverTheRepresentative()
        {
            using var capture = new PluginLogCapture();
            var pending = JsonDocument.Parse(
                "{\"name\":\"" + RepName + "\",\"email\":\"" + RepEmail + "\",\"employeeId\":\"" + RepEmployeeId + "\"}").RootElement.Clone();
            var (mock, _) = OvMock(new V2CreateOrderResponse
            {
                OrderId = OrderId, Status = "pending-organization-verification",
                OrganizationRepresentativeStatus = "pending-approval", PendingOrganizationRepresentative = pending
            });

            await Enroll(new CERTInextCAPlugin(mock.Object, Config()),
                ProductInfo(Constants.Products.OvSsl, Rep(phone: RepPhone, designation: RepDesignation, employeeId: RepEmployeeId)));

            capture.Lines(LogLevel.Information, "new organization representative requested").Should().ContainSingle()
                .Which.Should().Contain("OrganizationRepresentativeStatus=pending-approval")
                .And.Contain("PendingOrganizationRepresentativeReturned=True");
            capture.Lines(LogLevel.Trace, "").Concat(capture.Lines(LogLevel.Debug, "")).Concat(capture.Lines(LogLevel.Information, ""))
                .Concat(capture.Lines(LogLevel.Warning, "")).Concat(capture.Lines(LogLevel.Error, ""))
                .Should().NotContain(l => l.Contains(RepName) || l.Contains(RepEmail) || l.Contains(RepDesignation)
                    || l.Contains(RepEmployeeId) || l.Contains("010-0199"));
        }

        [Fact]
        public void CreateResponse_DeserializesStatusAndRawPendingBlock()
        {
            var resp = JsonSerializer.Deserialize<V2CreateOrderResponse>(
                "{\"orderId\":\"1\",\"organizationRepresentativeStatus\":\"applied\"}", ClientEquivalentJsonOptions);
            resp!.OrganizationRepresentativeStatus.Should().Be("applied");
            resp.PendingOrganizationRepresentative.Should().BeNull();

            resp = JsonSerializer.Deserialize<V2CreateOrderResponse>(
                "{\"orderId\":\"1\",\"organizationRepresentativeStatus\":\"pending-approval\"," +
                "\"pendingOrganizationRepresentative\":{\"name\":\"x\",\"nested\":{\"any\":[1,2]}}}", ClientEquivalentJsonOptions);
            resp!.PendingOrganizationRepresentative.Should().NotBeNull("an undocumented shape must not fail deserialization");
        }

        // ---------------------------------------------------------------------------
        // ValidateProductInfo (template save)
        // ---------------------------------------------------------------------------

        private static Dictionary<string, object> ConnectionInfo(bool v2, string organizationNumber = "ORG-001") => new Dictionary<string, object>
        {
            ["UseV2Api"] = v2, ["ApiUrl"] = "https://v2.certinext.io", ["OAuthClientId"] = "id", ["OAuthClientSecret"] = "s",
            ["OrganizationNumber"] = organizationNumber
        };

        [Theory]
        [InlineData(Constants.Products.DvSsl, "ORG-001", "EMS-1315")]
        [InlineData(Constants.Products.OvSsl, "", "EMS-1316")]
        public async Task ValidateProductInfo_V2_InvalidRepresentative_RejectedAtSave(string productId, string orgNumber, string expected)
        {
            var plugin = new CERTInextCAPlugin(new Mock<ICERTInextClient>().Object, Config());

            Func<Task> act = () => plugin.ValidateProductInfo(ProductInfo(productId, Rep()), ConnectionInfo(true, orgNumber));

            (await act.Should().ThrowAsync<AnyCAValidationException>()).Which.Message.Should().Contain(expected)
                .And.NotContain(RepEmail);
        }

        [Fact]
        public async Task ValidateProductInfo_V2_ValidOvRepresentative_Accepted()
        {
            var plugin = new CERTInextCAPlugin(new Mock<ICERTInextClient>().Object, Config());

            Func<Task> act = () => plugin.ValidateProductInfo(
                ProductInfo(Constants.Products.OvSsl, Rep(phone: RepPhone)), ConnectionInfo(true));

            await act.Should().NotThrowAsync();
        }
    }
}
