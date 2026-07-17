# Contributing to custos-dedup

Contributions that improve correctness, interoperability, documentation, or
performance are welcome. This crate is deliberately narrow: it correlates
atomic security finding occurrences while preserving provenance. Source-specific
ingestion, payload merging, persistence, and network-backed alias resolution
belong in downstream adapters or separate crates.

## Before making a change

For behavior changes, describe the input model, expected decision, and why the
existing policy is insufficient. Changes to normalization, key material, or
threshold semantics may affect stored identities and existing clusters, so call
out compatibility consequences explicitly.

For larger design changes, start a discussion before implementation. Keep
patches focused and avoid combining unrelated refactors with behavior changes.

## Local setup

Install Rust 1.85 or newer with Rustfmt and Clippy. The repository keeps
`Cargo.lock` so the same dependency resolution can be checked in CI.
Install the pinned supply-chain tools with a current stable toolchain:

```console
cargo +stable install cargo-audit --version 0.22.2 --locked --no-default-features
cargo +stable install cargo-deny --version 0.20.2 --locked
```

Run the complete local verification set from the repository root:

```console
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps --locked
cargo audit --deny warnings
cargo deny --all-features --locked check bans licenses sources
cargo package --locked
```

To check the minimum supported Rust version as well:

```console
rustup toolchain install 1.85.0 --profile minimal
cargo +1.85.0 test --all-targets --all-features --locked
```

## Tests

Add focused tests for every behavior change. Correlation tests should cover both
argument orders because pairwise comparison is symmetric. Where applicable,
include:

- canonical and non-canonical PURL or CPE input;
- partition, finding-kind, or source-policy boundaries;
- missing, matching, and conflicting structured evidence;
- the returned decision, method, score, and signals;
- deterministic output under reordered batch input;
- complete-link behavior rather than connected-component behavior;
- oversized-block warning and error policies.

Use synthetic identifiers and payload fragments. Do not commit real scanner
records, credentials, private paths, customer names, or unpublished
vulnerability details.

## Compatibility expectations

Treat these surfaces as compatibility-sensitive:

- accepted and rejected identity syntax;
- canonical PURL and CPE rendering;
- occurrence and correlation key inputs, prefixes, and versions;
- default thresholds and hard-boundary behavior;
- ordering of deterministic output;
- serialized representations behind the `serde` feature.

If key material must change, introduce a new key version instead of silently
changing the digest produced by an existing version. Document user-visible
changes in `CHANGELOG.md`.

## Documentation

Public behavior needs Rustdoc. User-facing workflows, policy changes, and
limitations also need corresponding README updates. Examples must compile and
should use conservative settings unless they are specifically demonstrating
configuration.

## Submitting a change

Before submitting, make sure the verification commands pass with no warnings.
In the change description, summarize:

- the problem and intended scope;
- the behavior and compatibility impact;
- the tests or benchmarks run;
- any follow-up work intentionally left out.

By contributing, you agree that your contribution is licensed under the
project's MIT OR Apache-2.0 terms.
