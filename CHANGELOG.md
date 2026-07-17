# Changelog

All notable changes to this project are documented in this file.

The format is based on Keep a Changelog, and this project follows Semantic
Versioning.

## [Unreleased]

### Changed

- Reject unknown fields when deserializing structured crate values.
- Reuse prepared occurrence and correlation keys throughout batch clustering.
- Add repository metadata and dependency advisory, license, and source checks.

### Fixed

- Normalize Unicode titlecase characters consistently in fuzzy text evidence.
- Make README examples directly compilable outside rustdoc.

## [0.1.0] - 2026-07-16

### Added

- Source-agnostic security finding candidates with caller-defined hard
  partitions and preserved source identity.
- Canonical PURL and CPE 2.3 subject identities, including legacy CPE URI
  normalization.
- Versioned BLAKE3 occurrence and correlation keys.
- Explainable pairwise `Duplicate`, `Review`, `Distinct`, and `NotComparable`
  decisions with structured signals.
- Conservative, validated comparison and fuzzy-block configuration.
- Deterministic complete-link clustering with review pairs, warnings, and run
  statistics.
- Optional Serde support.
