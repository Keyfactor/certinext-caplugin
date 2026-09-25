# DNS-01 DCV: build flag and code fencing

## Build flag

DNS-01 DCV support is gated behind a single MSBuild property, **`DcvSupport`**, default `true`. It's defined in `CERTInext/CERTInext.csproj`:

```
dotnet build -p:DcvSupport=false
```

- `DcvSupport=true` (default): compiles against `Keyfactor.AnyGateway.IAnyCAPlugin` **3.3.0** (stable release), defines `SUPPORTS_DCV` — this is what CI ships, targeting 26.x/DCV-capable gateway hosts.
- `DcvSupport=false`: compiles against **3.2.0**, no `SUPPORTS_DCV` constant, targeting GA gateway hosts (AnyCA Gateway 25.5.x, see issue 0003).

The project also only targets **`net10.0`** (single TFM, no more `net8.0`/`net10.0` multi-targeting).

Relevant lines: [`CERTInext.csproj#L18-L19`](https://github.com/Keyfactor/certinext-caplugin/blob/fb6e414956f708f0bef417bd8a8ddf52854ab11e/CERTInext/CERTInext.csproj#L18-L19) (the flag → `SUPPORTS_DCV` define) and [`#L29-L30`](https://github.com/Keyfactor/certinext-caplugin/blob/fb6e414956f708f0bef417bd8a8ddf52854ab11e/CERTInext/CERTInext.csproj#L29-L30) (the package-version swap).

The two test projects mirror this flag so DCV test files only compile in when asked:
- [`CERTInext.Tests.csproj#L11-L12`](https://github.com/Keyfactor/certinext-caplugin/blob/fb6e414956f708f0bef417bd8a8ddf52854ab11e/CERTInext.Tests/CERTInext.Tests.csproj#L11-L12)
- [`CERTInext.IntegrationTests.csproj#L11-L12`](https://github.com/Keyfactor/certinext-caplugin/blob/fb6e414956f708f0bef417bd8a8ddf52854ab11e/CERTInext.IntegrationTests/CERTInext.IntegrationTests.csproj#L11-L12)

## Where `#if SUPPORTS_DCV` fences the feature

All in `CERTInext/CERTInextCAPlugin.cs`:

| Lines | What's fenced |
|---|---|
| [22–24](https://github.com/Keyfactor/certinext-caplugin/blob/fb6e414956f708f0bef417bd8a8ddf52854ab11e/CERTInext/CERTInextCAPlugin.cs#L22-L24) | `using` alias for `IDomainValidatorFactory` |
| [72–75](https://github.com/Keyfactor/certinext-caplugin/blob/fb6e414956f708f0bef417bd8a8ddf52854ab11e/CERTInext/CERTInextCAPlugin.cs#L72-L75) | typed `DomainValidatorFactory` property (casts the untyped `_domainValidatorFactory` field) |
| [155–163](https://github.com/Keyfactor/certinext-caplugin/blob/fb6e414956f708f0bef417bd8a8ddf52854ab11e/CERTInext/CERTInextCAPlugin.cs#L155-L163) | internal test constructor that injects an `IDomainValidatorFactory` |
| [178–197](https://github.com/Keyfactor/certinext-caplugin/blob/fb6e414956f708f0bef417bd8a8ddf52854ab11e/CERTInext/CERTInextCAPlugin.cs#L178-L197) | `SetDomainValidatorFactory` — real assignment vs. `#else` no-op log |
| [789–798](https://github.com/Keyfactor/certinext-caplugin/blob/fb6e414956f708f0bef417bd8a8ddf52854ab11e/CERTInext/CERTInextCAPlugin.cs#L789-L798) | `Synchronize`: DCV-during-sync bookkeeping vars (age window, per-pass cap, counters) |
| [849–897](https://github.com/Keyfactor/certinext-caplugin/blob/fb6e414956f708f0bef417bd8a8ddf52854ab11e/CERTInext/CERTInextCAPlugin.cs#L849-L897) | `Synchronize`: the actual per-order DCV-during-sync gate/attempt/refetch logic |
| [1014–1021](https://github.com/Keyfactor/certinext-caplugin/blob/fb6e414956f708f0bef417bd8a8ddf52854ab11e/CERTInext/CERTInextCAPlugin.cs#L1014-L1021) | `Synchronize`: builds the DCV summary log clause — real stats vs. `#else` "not supported on this build" |
| [1108–1171](https://github.com/Keyfactor/certinext-caplugin/blob/fb6e414956f708f0bef417bd8a8ddf52854ab11e/CERTInext/CERTInextCAPlugin.cs#L1108-L1171) | `EnrollNewAsync`: runs DCV right after a fresh order is placed, then polls for issuance |
| [1373–1424](https://github.com/Keyfactor/certinext-caplugin/blob/fb6e414956f708f0bef417bd8a8ddf52854ab11e/CERTInext/CERTInextCAPlugin.cs#L1373-L1424) | `TryRunDcvDuringSyncAsync` — full retry-path body vs. `#else` `return false` no-op |
| [1442–1704](https://github.com/Keyfactor/certinext-caplugin/blob/fb6e414956f708f0bef417bd8a8ddf52854ab11e/CERTInext/CERTInextCAPlugin.cs#L1442-L1704) | `PerformDcvIfNeededAsync` itself — the whole method only exists in the DCV build |

Design note baked into the comments: `_domainValidatorFactory` is deliberately typed as `object` (not `IDomainValidatorFactory`) so the JIT never needs to resolve the 3.3-only type when `SUPPORTS_DCV` is off — casts only happen inside method bodies fenced by `#if`, which is what lets the no-DCV build load cleanly on a 3.2.0 gateway host (see the field comment at [L40-L60](https://github.com/Keyfactor/certinext-caplugin/blob/fb6e414956f708f0bef417bd8a8ddf52854ab11e/CERTInext/CERTInextCAPlugin.cs#L40-L60), issue #7).

Reminder: DCV is now the default build — `-p:DcvSupport=false` is the opt-out for GA/no-DCV hosts. Without it, the build targets 26.x hosts and depends on the stable `3.3.0` package.
