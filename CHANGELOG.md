# Changelog

## v0.1.0 (2026-04-26)

- Initial release. Conformance against `Agent Trust Verification Provider Pattern v0.1`.
- Implements `before_install`, `before_tool_call`, `gateway_start` hooks.
- Implements `aps.checkGrade`, `aps.verifyDelegation`, `aps.signMessage` RPC methods.
- `inbound_claim` and `before_dispatch` deferred to v0.2.
