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
        public void NoInstanceField_DeclaredTypeReferencesV3Point3OnlyTypes()
        {
            // The .NET JIT eagerly resolves the declared types of all instance fields
            // when it first compiles ANY method on a class. If an instance field is
            // declared with a missing-type-on-this-host type, TypeLoadException fires
            // the very first time Initialize / Enroll / Synchronize / anything is
            // invoked — independent of whether the field is read on that code path.
            //
            // Issue #7's original fix patched constructor-signature reflection (the
            // DI-container surface). The follow-up comment showed a separate failure
            // path where Enroll trips on field-type loading. This test guards against
            // a regression of either: field types must use only types the v3.2 host
            // ships, with `object` as the typical neutral-typed storage and an `as`
            // cast inside method bodies (JIT-lazy) for actual use.
            // DeclaredOnly added for symmetry with the nested-type / method tests below
            // and to make the "we only check this type, not its base classes" intent
            // explicit in the reflection-query shape.
            var fields = typeof(CERTInextCAPlugin)
                .GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.DeclaredOnly);

            foreach (var field in fields)
            {
                string fieldTypeName = field.FieldType.FullName ?? field.FieldType.Name;
                V3Point3OnlyTypeNames.Should().NotContain(fieldTypeName,
                    $"instance field '{field.Name}' (declared type {fieldTypeName}) on " +
                    $"{field.DeclaringType?.FullName} would trigger TypeLoadException when the JIT " +
                    $"first compiles any method on the class on a v3.2 gateway host. " +
                    $"Re-type the field as `object` and cast to the v3.3 type inside method " +
                    $"bodies — see issue #7 follow-up.");
            }
        }

        [Fact]
        public void NoNestedType_ImplementsV3Point3OnlyInterface()
        {
            // Nested types declared with a base/interface reference to a v3.3-only
            // interface put that interface in the containing class's nested-type
            // metadata. CLR class-load behaviour around nested-type interface
            // resolution is fragile across .NET versions, so we forbid it outright
            // as a belt-and-braces measure.
            var nestedTypes = typeof(CERTInextCAPlugin)
                .GetNestedTypes(BindingFlags.Public | BindingFlags.NonPublic);

            foreach (var nested in nestedTypes)
            {
                foreach (var iface in nested.GetInterfaces())
                {
                    string ifaceName = iface.FullName ?? iface.Name;
                    V3Point3OnlyTypeNames.Should().NotContain(ifaceName,
                        $"nested type '{nested.FullName}' implements v3.3-only interface " +
                        $"'{ifaceName}', which would leak into the containing class's " +
                        $"reflection surface on a v3.2 host. Delete the nested type or " +
                        $"refactor it to not declare the v3.3 interface in its base list.");
                }
            }
        }

        [Fact]
        public void NoPublicMethod_SignatureReferencesV3Point3OnlyTypes()
        {
            // Reflection-driven hosts (anything calling Type.GetMethods()) eagerly
            // resolve return-type and parameter-type metadata on each method. Public
            // method signatures must therefore avoid v3.3-only types the same way
            // public constructors do. SetDomainValidatorFactory's `object` parameter
            // is the safe pattern.
            var publicInstanceMethods = typeof(CERTInextCAPlugin)
                .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);

            foreach (var method in publicInstanceMethods)
            {
                // Property accessors get caught here too — that's intentional.
                string returnTypeName = method.ReturnType.FullName ?? method.ReturnType.Name;
                V3Point3OnlyTypeNames.Should().NotContain(returnTypeName,
                    $"public method '{method.Name}' returns v3.3-only type '{returnTypeName}'. " +
                    $"Change the return type to `object` and have callers cast at the use site.");

                foreach (var param in method.GetParameters())
                {
                    string paramTypeName = param.ParameterType.FullName ?? param.ParameterType.Name;
                    V3Point3OnlyTypeNames.Should().NotContain(paramTypeName,
                        $"public method '{method.Name}' parameter '{param.Name}' is " +
                        $"v3.3-only type '{paramTypeName}'. Change the parameter to `object` " +
                        $"and cast inside the method body — see SetDomainValidatorFactory.");
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
