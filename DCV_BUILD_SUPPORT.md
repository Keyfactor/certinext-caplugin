# DNS-01 DCV: build and code layout

DNS-01 domain control validation (DCV) is part of the standard build of the plugin. This page describes how the build is configured and where the DCV code lives. For how the DCV flow behaves, see [docsource/architecture.md](docsource/architecture.md#domain-control-validation); for the connector settings, see the `Dcv*` rows in [docsource/configuration.md](docsource/configuration.md#ca-configuration).

## Build

- The plugin compiles against `Keyfactor.AnyGateway.IAnyCAPlugin` **3.3.0**, which provides `IDomainValidatorFactory`, and targets AnyCA Gateway REST **26.2.0** and later.
- `CERTInext/CERTInext.csproj` sets the `DcvSupport` MSBuild property to `true` by default. That one property selects the IAnyCAPlugin package version, defines the `SUPPORTS_DCV` compile constant, and includes the DCV test files in the two test projects. Plain `dotnet build` and `make build` therefore produce the DCV build; no flag is needed.
- The project targets both **`net8.0`** and **`net10.0`**.
- The test projects mirror the property so the DCV test files compile with it: `CERTInext.Tests/CERTInext.Tests.csproj` and `CERTInext.IntegrationTests/CERTInext.IntegrationTests.csproj`.

```
dotnet build
```

## Where the DCV code lives

The DCV code is in `CERTInext/CERTInextCAPlugin.cs`, compiled under `#if SUPPORTS_DCV`:

| Member | What it does |
|---|---|
| `using` alias and `DomainValidatorFactory` property | Name the `IDomainValidatorFactory` type and cast the stored factory to it |
| Internal test constructor taking an `IDomainValidatorFactory` | Lets unit and integration tests inject a fake or real DNS validator |
| `SetDomainValidatorFactory(object)` | Receives the gateway's DNS provider factory and logs which type was offered |
| `EnrollNewAsync` (V1) | Runs DCV right after a new order is placed, then waits for issuance |
| `EnrollV2Async` (V2) | Runs DCV when the new order is pending, then re-checks its status |
| `Synchronize` / `SynchronizeV2Async` | Drive recently placed pending orders through DCV, bounded by `DcvSyncMaxOrderAgeHours` and `DcvSyncMaxPerPass` |
| `GetSingleRecord` / `GetSingleRecordV2Async` | Drive a pending order through DCV on a manual refresh |
| `TryRunDcvDuringSyncAsync` | The sync and single-record retry wrapper for V1: in-flight guard, bounded timeout, swallows non-cancellation errors |
| `PerformDcvIfNeededAsync` | The V1 DCV flow: wait for the challenge, `GetDcv`, publish TXT, `VerifyDcv`, poll, clean up |
| `PerformDcvV2IfNeededAsync` | The V2 entry point; dispatches to the single-domain or multi-domain V2 flow |

The stored factory is held as `object` and cast inside method bodies, so the plugin class loads even when the host doesn't supply `IDomainValidatorFactory`. In that case DCV is simply inactive: when `DcvEnabled` is `true`, the plugin logs a warning at startup, and orders that need validation stay pending until a DNS provider is available or `DcvEnabled` is set to `false`.

The DNS provider side is a separate gateway plugin that implements `IDomainValidator` (for example `azure-azuredns-dnsplugin`). The integration tests include a Cloudflare-backed validator (`CloudflareDomainValidator`) and a recording wrapper for exercising the flow against the live sandbox.
