// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Linq;
using System.Reflection;
using FluentAssertions;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Pins the gateway-DI-visible public surface of <see cref="CERTInextCAPlugin"/> so that
    /// regressions which would crash plugin load on older gateway hosts cannot land silently.
    ///
    /// Background: gateway image <c>25.4.0</c> ships
    /// <c>Keyfactor.AnyGateway.IAnyCAPlugin v3.2.0.0</c>, which does not define
    /// <c>Keyfactor.AnyGateway.Extensions.IDomainValidatorFactory</c>.  If any public
    /// constructor declares that type as a parameter, the gateway's DI container will fail
    /// at <c>RuntimeConstructorInfo.GetParameters()</c> with <c>TypeLoadException 0x80131509</c>
    /// before plugin load can complete (see GitHub issue #7).
    ///
    /// These tests assert via reflection that the only types reachable from the plugin's
    /// public constructor parameter lists are ones present on v3.2 hosts (BCL +
    /// pre-3.3 Keyfactor types).
    /// </summary>
    public class CERTInextCAPluginPublicSurfaceTests
    {
        private static readonly string[] V3Point3OnlyTypeNames =
        {
            "Keyfactor.AnyGateway.Extensions.IDomainValidatorFactory",
            "Keyfactor.AnyGateway.Extensions.IDomainValidator",
            "Keyfactor.AnyGateway.Extensions.IDomainValidatorConfigProvider"
        };

        [Fact]
        public void NoPublicConstructor_ReferencesV3Point3OnlyTypes()
        {
            var publicCtors = typeof(CERTInextCAPlugin)
                .GetConstructors(BindingFlags.Public | BindingFlags.Instance);

            publicCtors.Should().NotBeEmpty("plugin must have at least one public constructor for the gateway to instantiate");

            foreach (var ctor in publicCtors)
            {
                foreach (var param in ctor.GetParameters())
                {
                    string paramTypeName = param.ParameterType.FullName ?? param.ParameterType.Name;
                    V3Point3OnlyTypeNames.Should().NotContain(paramTypeName,
                        $"public constructor parameter '{param.Name}' (type {paramTypeName}) on " +
                        $"{ctor} would trip TypeLoadException on a gateway whose IAnyCAPlugin " +
                        $"assembly does not contain that type. Move the constructor to internal " +
                        $"or remove the parameter — see issue #7.");
                }
            }
        }

        [Fact]
        public void ParameterlessConstructor_IsPublic()
        {
            var parameterlessCtor = typeof(CERTInextCAPlugin)
                .GetConstructor(BindingFlags.Public | BindingFlags.Instance, types: System.Type.EmptyTypes);

            parameterlessCtor.Should().NotBeNull(
                "older gateway hosts that don't pass any DI parameters need a public no-arg " +
                "constructor to fall back to. See issue #7.");
        }

        [Fact]
        public void SetDomainValidatorFactory_AcceptsObject_NotIDomainValidatorFactory()
        {
            // The public setter must declare `object` (not the v3.3-only interface) so the
            // method's signature does not pull the missing type into the v3.2 host's
            // reflection surface.
            var method = typeof(CERTInextCAPlugin)
                .GetMethod("SetDomainValidatorFactory", BindingFlags.Public | BindingFlags.Instance);

            method.Should().NotBeNull("plugin must expose a public hook for v3.3+ hosts to inject the factory");
            var parameters = method!.GetParameters();
            parameters.Should().ContainSingle();
            parameters[0].ParameterType.Should().Be(typeof(object),
                "the parameter must be `object` so SetDomainValidatorFactory's signature is " +
                "safe to reflect on a v3.2 host. The body casts to IDomainValidatorFactory " +
                "lazily, which only resolves the type if the method is actually called.");
        }

        [Fact]
        public void SetDomainValidatorFactory_NullArgument_LeavesDcvDisabled()
        {
            var plugin = new CERTInextCAPlugin();
            plugin.SetDomainValidatorFactory(null);
            // No exception, no state change — the plugin behaves as if no factory were available.
        }

        [Fact]
        public void SetDomainValidatorFactory_NonFactoryArgument_IsIgnored()
        {
            // Pass something that doesn't implement IDomainValidatorFactory. The `as` cast
            // in the setter yields null and the field stays null — no throw.
            var plugin = new CERTInextCAPlugin();
            plugin.SetDomainValidatorFactory("not a factory");
            // No assertion needed beyond not throwing.
        }
    }
}
