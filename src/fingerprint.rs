use std::fmt;
use std::str::FromStr;

use crate::{Candidate, FindingKind, IssueId, SubjectId};

const OCCURRENCE_CONTEXT: &str = "custos-dedup/occurrence/v1";
const CORRELATION_CONTEXT: &str = "custos-dedup/correlation/v1";
const OCCURRENCE_PREFIX: &str = "occ:v1:";
const CORRELATION_PREFIX: &str = "corr:v1:";

/// A versioned BLAKE3 key for one source-local occurrence.
///
/// The key hashes the hard partition and finding kind together with the source,
/// optional subtype, and native source ID. It remains separate from
/// [`CorrelationKey`], which deliberately excludes source provenance.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OccurrenceKey([u8; 32]);

impl OccurrenceKey {
    /// Computes a source-local occurrence key.
    #[must_use]
    pub fn for_candidate(candidate: &Candidate) -> Self {
        let origin = candidate.origin();
        let mut hasher = CanonicalHasher::new(OCCURRENCE_CONTEXT);
        hasher.field("partition", candidate.partition());
        hasher.finding_kind(candidate.kind());
        hasher.field("source", origin.source());
        hasher.optional_field("subtype", origin.subtype());
        hasher.field("native_id", origin.native_id());
        Self(hasher.finish())
    }

    /// Returns the raw 256-bit digest.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for OccurrenceKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{OCCURRENCE_PREFIX}{}",
            blake3::Hash::from(self.0).to_hex()
        )
    }
}

impl FromStr for OccurrenceKey {
    type Err = KeyParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse_key(value, OCCURRENCE_PREFIX).map(Self)
    }
}

/// A versioned BLAKE3 key for exact cross-source correlation.
///
/// A key contains the hard partition, finding kind, one normalized issue alias,
/// and one full normalized subject identifier. A candidate can therefore have
/// several keys when it carries multiple aliases for the same atomic issue.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CorrelationKey([u8; 32]);

impl CorrelationKey {
    pub(crate) fn for_issue_subject(
        partition: &str,
        kind: &FindingKind,
        issue: &IssueId,
        subject: &SubjectId,
    ) -> Self {
        let mut hasher = CanonicalHasher::new(CORRELATION_CONTEXT);
        hasher.field("partition", partition);
        hasher.finding_kind(kind);
        hasher.field("issue", issue.as_str());
        hasher.field("subject", subject.full_identity());
        Self(hasher.finish())
    }

    pub(crate) fn for_issue_only(partition: &str, kind: &FindingKind, issue: &IssueId) -> Self {
        let mut hasher = CanonicalHasher::new(CORRELATION_CONTEXT);
        hasher.field("partition", partition);
        hasher.finding_kind(kind);
        hasher.field("issue", issue.as_str());
        hasher.absent_field("subject");
        Self(hasher.finish())
    }

    /// Returns the raw 256-bit digest.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for CorrelationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{CORRELATION_PREFIX}{}",
            blake3::Hash::from(self.0).to_hex()
        )
    }
}

impl FromStr for CorrelationKey {
    type Err = KeyParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse_key(value, CORRELATION_PREFIX).map(Self)
    }
}

/// An invalid serialized occurrence or correlation key.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum KeyParseError {
    /// The versioned type prefix did not match the target key type.
    #[error("key must start with `{expected}`")]
    Prefix {
        /// The required prefix.
        expected: &'static str,
    },
    /// The digest was not exactly 64 hexadecimal characters.
    #[error("key digest must contain exactly 64 hexadecimal characters")]
    Digest,
}

struct CanonicalHasher(blake3::Hasher);

impl CanonicalHasher {
    fn new(context: &'static str) -> Self {
        Self(blake3::Hasher::new_derive_key(context))
    }

    fn field(&mut self, tag: &str, value: &str) {
        self.bytes(tag.as_bytes());
        self.0.update(&[1]);
        self.bytes(value.as_bytes());
    }

    fn optional_field(&mut self, tag: &str, value: Option<&str>) {
        match value {
            Some(value) => self.field(tag, value),
            None => self.absent_field(tag),
        }
    }

    fn finding_kind(&mut self, kind: &FindingKind) {
        self.field("kind", kind.key_tag());
        self.optional_field("kind_value", kind.custom_key());
    }

    fn absent_field(&mut self, tag: &str) {
        self.bytes(tag.as_bytes());
        self.0.update(&[0]);
    }

    fn bytes(&mut self, value: &[u8]) {
        self.0.update(&(value.len() as u64).to_be_bytes());
        self.0.update(value);
    }

    fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

fn parse_key(value: &str, prefix: &'static str) -> Result<[u8; 32], KeyParseError> {
    let digest = value
        .strip_prefix(prefix)
        .ok_or(KeyParseError::Prefix { expected: prefix })?;
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(KeyParseError::Digest);
    }
    let mut output = [0_u8; 32];
    for (index, pair) in digest.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or(KeyParseError::Digest)?;
        let low = hex_nibble(pair[1]).ok_or(KeyParseError::Digest)?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(feature = "serde")]
macro_rules! serde_key {
    ($type:ty) => {
        impl serde::Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.collect_str(self)
            }
        }

        impl<'de> serde::Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = <String as serde::Deserialize>::deserialize(deserializer)?;
                value.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

#[cfg(feature = "serde")]
serde_key!(OccurrenceKey);
#[cfg(feature = "serde")]
serde_key!(CorrelationKey);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Candidate;

    #[test]
    fn occurrence_key_is_domain_separated_and_stable() {
        let candidate = Candidate::builder("scanner", "42")
            .partition("global")
            .issue("CVE-2024-1")
            .build()
            .unwrap();

        assert_eq!(
            OccurrenceKey::for_candidate(&candidate).to_string(),
            "occ:v1:450c326009b8cd7997128cb8dec1198ffc90c42a71bb588b31d598ed08cd17a4"
        );
    }

    #[test]
    fn occurrence_key_changes_with_source_identity() {
        let left = Candidate::builder("one", "42")
            .partition("global")
            .issue("CVE-2024-1")
            .build()
            .unwrap();
        let right = Candidate::builder("two", "42")
            .partition("global")
            .issue("CVE-2024-1")
            .build()
            .unwrap();

        assert_ne!(
            OccurrenceKey::for_candidate(&left),
            OccurrenceKey::for_candidate(&right)
        );
    }

    #[test]
    fn correlation_key_is_domain_separated_and_stable() {
        let candidate = Candidate::builder("scanner", "42")
            .partition("global")
            .issue("CVE-2024-1")
            .purl("pkg:cargo/widget@1.0.0")
            .unwrap()
            .build()
            .unwrap();
        let key = CorrelationKey::for_issue_subject(
            candidate.partition(),
            candidate.kind(),
            &candidate.issue_ids()[0],
            &candidate.subject_ids()[0],
        );

        assert_eq!(
            key.to_string(),
            "corr:v1:424a766e50abab734784726f6e678f9d4b938cc9fcaa8c6e8fec562637698ae2"
        );
        assert_eq!(key.to_string().parse::<CorrelationKey>().unwrap(), key);
    }

    #[test]
    fn occurrence_key_respects_hard_boundaries() {
        let first = Candidate::builder("one", "42")
            .partition("asset:a")
            .issue("CVE-2024-1")
            .build()
            .unwrap();
        let second = Candidate::builder("one", "42")
            .partition("asset:b")
            .issue("CVE-2024-1")
            .build()
            .unwrap();

        assert_ne!(
            OccurrenceKey::for_candidate(&first),
            OccurrenceKey::for_candidate(&second)
        );
    }

    #[test]
    fn built_in_and_custom_finding_kinds_are_domain_separated() {
        let built_in = Candidate::builder("one", "42")
            .partition("global")
            .kind(FindingKind::Vulnerability)
            .issue("CVE-2024-1")
            .build()
            .unwrap();
        let custom = Candidate::builder("one", "42")
            .partition("global")
            .kind(FindingKind::Other("vulnerability".to_owned()))
            .issue("CVE-2024-1")
            .build()
            .unwrap();

        assert_ne!(
            OccurrenceKey::for_candidate(&built_in),
            OccurrenceKey::for_candidate(&custom)
        );
    }

    #[test]
    fn occurrence_key_round_trips_through_display() {
        let candidate = Candidate::builder("one", "42")
            .partition("global")
            .issue("CVE-2024-1")
            .build()
            .unwrap();
        let key = OccurrenceKey::for_candidate(&candidate);

        assert_eq!(key.to_string().parse::<OccurrenceKey>().unwrap(), key);
    }
}
