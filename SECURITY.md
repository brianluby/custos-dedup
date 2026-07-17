# Security policy

## Supported versions

Security fixes are provided for the latest released minor line.

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |
| Earlier versions | No |

Until 1.0, a security fix may require a compatibility change when preserving
existing behavior would leave users exposed. Such changes will be documented in
the changelog.

## Reporting a vulnerability

Do not publish suspected vulnerabilities, proof-of-concept inputs, or affected
deployment details in a public issue.

Use a private contact method advertised by the current maintainers in the
package metadata or maintainer profiles. Include:

- the affected version and enabled features;
- the impact and realistic attack scenario;
- the smallest input or steps that reproduce the problem;
- whether the issue affects parsing, normalization, keys, comparison,
  clustering, serialization, or resource use;
- any suggested fix or disclosure constraints.

If no private channel is available, open only a minimal public request asking a
maintainer to establish secure contact. Do not include vulnerability details in
that request.

Maintainers will acknowledge the report, validate its scope, prepare a fix, and
coordinate disclosure with the reporter. Response and release timing depends on
severity and maintainer availability; this project does not promise a fixed
service-level deadline.

## Security boundaries

`custos-dedup` processes caller-supplied identity and text fields and returns
correlation evidence. Callers should treat all input as untrusted and retain
their own limits for record count and field length. `max_block_size` limits
fuzzy work per eligible batch block, but it is not a complete input-size or
memory quota.

Correlation decisions are not authorization or vulnerability-validation
decisions. In particular:

- a `Duplicate` result does not prove that either source record is true;
- a `Distinct` result does not prove that records are unrelated outside the
  supplied evidence;
- fuzzy scores are evidence rankings, not probabilities;
- BLAKE3 keys identify canonical inputs but do not authenticate source data;
- the crate does not merge payloads or sanitize source payloads for display;
- normalization performs no network alias lookup or external verification.

Downstream systems remain responsible for access control, tenant isolation,
input-size limits, secret handling, audit logging, and safe rendering of source
payloads.
