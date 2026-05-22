# Changelog

## [1.0.0] - Unreleased

### Added

- Initial release of the CERTInext AnyCA REST Gateway plugin
- Certificate enrollment for DV SSL (838), DV Wildcard (839), DV UCC (840), OV SSL (842), and EV SSL (846) product types
- Certificate revocation via `RevokeOrder` with RFC 5280 reason code mapping
- Full and incremental CA synchronization via paginated `GetOrderReport`
- AccessKey (HMAC-SHA256) and OAuth client credentials authentication modes
- `IgnoreExpired` flag to exclude expired certificates from synchronization
- Live integration tests covering all supported SSL/TLS product types (draft order mode)
