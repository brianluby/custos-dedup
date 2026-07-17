# custos-dedup

`custos-dedup` is a lightweight, source-agnostic Rust library for correlating
security finding occurrences reported by different tools. It combines
canonical Package URL (PURL) and CPE identities, versioned BLAKE3 keys, and
RapidFuzz text similarity to produce deterministic, explainable decisions.

The crate correlates occurrences; it does not ingest scanner formats, choose a
winning payload, or persist results. Adapters remain responsible for mapping
source records into atomic `Candidate` values, and callers retain every source's
provenance and payload.

## Features

- Hard, caller-defined partitions that prevent correlation across trust or
  asset boundaries.
- Separate occurrence and correlation keys with versioned encodings.
- Canonical PURL and CPE 2.3 identities, including normalization of legacy CPE
  URI bindings.
- Explainable `Duplicate`, `Review`, `Distinct`, and `NotComparable` decisions.
- Conservative defaults for cross-source matching and issue-only evidence.
- Deterministic, complete-link batch clustering with bounded fuzzy blocks.
- Optional `serde` support for the core model and result types.

The minimum supported Rust version is 1.85.

## Quick start

Add the crate to your manifest:

```toml
[dependencies]
custos-dedup = "0.1"
```

Map two source records into candidates and compare them:

```rust
use custos_dedup::{Candidate, Decision, Deduplicator};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let first = Candidate::builder("scanner-a", "finding-17")
        .partition("repository:acme/api")
        .issue("CVE-2024-3094")
        .purl("pkg:deb/debian/xz-utils@5.6.1?arch=amd64")?
        .title("Backdoored xz package")
        .build()?;

    let second = Candidate::builder("scanner-b", "alert-91")
        .partition("repository:acme/api")
        .issue("cve-2024-3094")
        .purl("pkg:deb/debian/xz-utils@5.6.1?arch=amd64")?
        .title("xz-utils backdoor")
        .build()?;

    let engine = Deduplicator::default();
    let comparison = engine.compare(&first, &second);

    assert_eq!(comparison.decision(), Decision::Duplicate);
    assert!(!comparison.signals().is_empty());
    Ok(())
}
```

See [`examples/basic.rs`](examples/basic.rs) for pairwise comparison and batch
clustering in one executable example.

## Model each occurrence atomically

A `Candidate` represents one issue on one subject as observed by one source.
Split compound source rows before constructing candidates. Multiple issue IDs
must be aliases for the same issue, and multiple PURL or CPE values must identify
the same subject.

Each candidate contains:

- an origin: source, optional subtype, and source-native ID;
- a required partition and finding kind;
- zero or more issue identifiers and aliases;
- zero or more normalized PURL or CPE subject identifiers;
- optional subject names, title, location, and affected version.

At least one issue, structured subject, subject name, or title is required.
Source adapters should preserve their original record separately; candidate
fields are correlation evidence, not a replacement payload.

## Treat partitions as hard boundaries

Partitions are exact, caller-defined correlation boundaries. Candidates in
different partitions produce `NotComparable`, even when every other field
matches. Finding kind is also a hard boundary.

Choose a partition that reflects the scope in which two reports may describe
the same occurrence: for example, a repository, deployed workload, tenant, or
asset. Use a literal such as `global` only when correlation across all assets is
intentional. Normalize partition values in the adapter before building
candidates; the crate does not reinterpret them.

By default, two different native findings from the same source are also
`NotComparable`. Set `ConfigBuilder::cross_source_only(false)` only when the
source's own findings may legitimately duplicate one another.

## Occurrence keys and correlation keys

The two key types serve different purposes:

| Key | Inputs | Purpose |
| --- | --- | --- |
| `OccurrenceKey` | partition, finding kind, source, optional subtype, native ID | Stable identity for one source-local record within hard boundaries |
| `CorrelationKey` | partition, finding kind, one issue alias, one full structured subject | Exact cross-source correlation evidence |

Keys use domain-separated BLAKE3 hashing and versioned string prefixes. An
occurrence key deliberately includes hard boundaries and source provenance; a
correlation key includes the same hard boundaries but deliberately excludes
source provenance. Do not substitute one for the other.

A candidate can produce several correlation keys when it carries issue aliases
or multiple equivalent subject identifiers. With the default policy, an issue
without a structured subject does not create an exact correlation key. Enabling
`issue_only_exact` makes that behavior explicit and should be limited to
partitions where a shared issue alone uniquely identifies a finding.

Serialized key versions are part of their interpretation. Store the complete
prefixed string, not only the hexadecimal digest.

## Understand decisions

`Deduplicator::compare` returns a `Comparison` rather than a bare boolean:

| Decision | Meaning |
| --- | --- |
| `Duplicate` | Exact correlation or sufficiently strong, anchored evidence permits automatic correlation. |
| `Review` | The pair is plausible but does not meet the automatic-correlation policy. |
| `Distinct` | Comparable evidence conflicts or the evidence score is below the review threshold. |
| `NotComparable` | A partition, finding-kind, or source policy prevents comparison. |

The result includes a `MatchMethod`, a basis-point `Score` when comparison was
possible, and ordered `Signal` values describing the evaluated fields. Signals
report relationships such as exact, similar, different, missing, or
incomparable without copying raw titles, paths, or identifiers into the result.

Fuzzy scores rank evidence on a `0..=10_000` scale. They are not calibrated
probabilities and should not be presented as confidence percentages.
Automatic fuzzy correlation also requires a shared issue, a compatible subject
anchor, and no conflicting concrete structured details such as versions, PURL
qualifiers, subpaths, or CPE attributes. A detail conflict can still be surfaced
for review, but it is never auto-merged.

## Conservative defaults

`Config::default()` uses:

| Setting | Default |
| --- | ---: |
| Duplicate threshold | 8,500 |
| Review threshold | 6,500 |
| Strong subject-name similarity | 9,000 |
| Cross-source only | `true` |
| Issue-only exact keys | `false` |
| Maximum fuzzy block size | 1,000 |
| Oversized block policy | exact matches only, with a warning |

Tune policy with validated basis-point values:

```rust
use custos_dedup::{Config, Deduplicator, OversizedBlockPolicy};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .duplicate_threshold(9_000)
        .review_threshold(7_000)
        .subject_similarity_threshold(9_200)
        .max_block_size(500)
        .oversized_block_policy(OversizedBlockPolicy::ExactOnlyAndWarn)
        .build()?;

    let _engine = Deduplicator::new(config);
    Ok(())
}
```

Evaluate threshold changes against representative labeled data. Lowering a
threshold changes correlation policy; it does not make a fuzzy score more
probabilistic.

## PURL and CPE normalization

PURLs are parsed and rendered canonically before they participate in keys or
structured comparison. CPE names accept CPE 2.3 formatted bindings and legacy
`cpe:/...` URI bindings, then normalize them into a consistent CPE 2.3
representation.

Full structured identity, including version where present, contributes to exact
correlation. Version-independent package or product coordinates are also used
to build bounded candidate blocks and support fuzzy comparison. PURL coordinates
omit qualifiers and subpaths; CPE coordinates retain part, vendor, and product.
PURL and CPE remain different identifier kinds: the crate does not infer that a
PURL and a CPE name describe the same package.

Normalization is local and deterministic. It does not query registries,
vulnerability databases, package indexes, or vendor alias services.

## Batch clustering

`Deduplicator::cluster` returns all clusters, including singletons, plus review
pairs, warnings, and run statistics. Exact correlation keys are merged first.
Fuzzy merges then use complete-link semantics: every cross-pair between two
existing groups must independently be `Duplicate` before the groups merge.
This prevents a chain of individually similar findings from joining candidates
whose endpoints would not correlate directly.

Batch fuzzy candidates are blocked by a shared normalized issue or a shared
structured-subject package or product coordinate. Unrestricted text-only pairs
are not generated. A block larger than `max_block_size` either keeps exact
matches and returns `ClusterWarning::OversizedBlock`, or returns an error,
according to the configured `OversizedBlockPolicy`.

With the default cross-source-only policy, a cluster contains at most one
occurrence from any source. This constraint is preserved during exact alias
merges as well as fuzzy complete-link merges, so transitive edges cannot bypass
the source boundary.

Clusters contain sorted occurrence keys, not merged findings. Use those keys to
retrieve each source record and apply a domain-specific merge or presentation
policy.

## Optional serialization

Enable the `serde` feature when candidates, comparisons, or cluster results must
cross a serialization boundary:

```toml
[dependencies]
custos-dedup = { version = "0.1", features = ["serde"] }
```

Deserialization is strict for structured values: unknown object fields are
rejected instead of ignored. Treat serialized field names as part of the wire
contract, and version surrounding envelopes when adding application-specific
metadata.

## Limitations

- The crate does not merge payloads, select canonical field values, or resolve
  lifecycle conflicts between sources.
- It does not provide a PURL-to-CPE crosswalk. Cross-kind structured identifiers
  remain incomparable unless callers add other shared evidence.
- CPE wildcard syntax is preserved, but wildcard pattern matching is not used to
  infer that two different product coordinates are equivalent.
- Fuzzy scores are deterministic evidence rankings, not probabilities.
- It performs no network lookup for aliases, vendor names, package metadata, or
  vulnerability records.
- Text normalization is intentionally general-purpose and does not understand
  every vendor or product naming convention.
- Batch matching is bounded, but work inside an eligible block can still grow
  quadratically up to the configured block limit.
- Stable keys preserve equality within a key version; they are identifiers, not
  signatures or authentication tokens.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
