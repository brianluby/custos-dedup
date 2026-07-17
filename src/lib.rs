//! Deterministic, explainable deduplication of security findings across sources.
//!
//! `custos-dedup` keeps correlation separate from payload merging. It normalizes
//! Package URLs and CPE names, creates versioned BLAKE3 keys, compares candidates
//! using structured and fuzzy evidence, and returns provenance-preserving clusters.
//! Callers retain control over which fields win when a cluster is rendered or stored.
//!
//! # Quick start
//!
//! ```
//! use custos_dedup::{Candidate, Decision, Deduplicator};
//!
//! let left = Candidate::builder("scanner-a", "finding-17")
//!     .partition("repository:acme/api")
//!     .issue("CVE-2024-3094")
//!     .purl("pkg:deb/debian/xz-utils@5.6.1?arch=amd64")?
//!     .title("Backdoored xz package")
//!     .build()?;
//!
//! let right = Candidate::builder("scanner-b", "alert-91")
//!     .partition("repository:acme/api")
//!     .issue("cve-2024-3094")
//!     .purl("pkg:deb/debian/xz-utils@5.6.1?arch=amd64")?
//!     .title("xz-utils backdoor")
//!     .build()?;
//!
//! let comparison = Deduplicator::default().compare(&left, &right);
//! assert_eq!(comparison.decision(), Decision::Duplicate);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![forbid(unsafe_code)]

mod cluster;
mod compare;
mod config;
mod fingerprint;
mod identity;
mod model;
mod normalize;

pub use cluster::{BlockKind, Cluster, ClusterError, ClusterResult, ClusterStats, ClusterWarning};
pub use compare::{
    Comparison, Decision, Deduplicator, MatchMethod, Score, ScoreError, Signal, SignalField,
    SignalKind,
};
pub use config::{Config, ConfigBuilder, ConfigError, OversizedBlockPolicy};
pub use fingerprint::{CorrelationKey, KeyParseError, OccurrenceKey};
pub use identity::{IdentityError, NormalizedCpe, NormalizedPurl, SubjectId};
pub use model::{Candidate, CandidateBuilder, CandidateError, FindingKind, IssueId, Origin};
