use std::fmt;

use crate::{IdentityError, NormalizedCpe, NormalizedPurl, SubjectId};

/// The source-local identity of one finding occurrence.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Origin {
    source: String,
    subtype: Option<String>,
    native_id: String,
}

impl Origin {
    /// Returns the source name, such as a scanner or ingestion adapter.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Returns the optional source subtype.
    #[must_use]
    pub fn subtype(&self) -> Option<&str> {
        self.subtype.as_deref()
    }

    /// Returns the source's native identifier for this occurrence.
    #[must_use]
    pub fn native_id(&self) -> &str {
        &self.native_id
    }
}

/// A normalized vulnerability, advisory, rule, or weakness identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IssueId(String);

impl IssueId {
    /// Normalizes a non-empty issue identifier.
    ///
    /// Well-known case-insensitive identifiers (`CVE`, `CWE`, `GHSA`, and
    /// `RUSTSEC`) are uppercased. Other namespaces retain their case.
    ///
    /// # Errors
    ///
    /// Returns [`CandidateError::EmptyIssueId`] for blank input and
    /// [`CandidateError::ControlCharacter`] for control characters.
    pub fn new(value: impl Into<String>) -> Result<Self, CandidateError> {
        let value = value.into();
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(CandidateError::EmptyIssueId);
        }
        if trimmed.chars().any(char::is_control) {
            return Err(CandidateError::ControlCharacter { field: "issue_id" });
        }

        const CASE_INSENSITIVE_PREFIXES: [&str; 4] = ["CVE-", "CWE-", "GHSA-", "RUSTSEC-"];
        let canonical = if CASE_INSENSITIVE_PREFIXES
            .iter()
            .any(|prefix| starts_with_ignore_ascii_case(trimmed, prefix))
        {
            trimmed.to_ascii_uppercase()
        } else {
            trimmed.to_owned()
        };
        Ok(Self(canonical))
    }

    /// Returns the normalized identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IssueId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The broad class of a finding.
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum FindingKind {
    /// A software or hardware vulnerability.
    #[default]
    Vulnerability,
    /// An insecure configuration or policy violation.
    Misconfiguration,
    /// An exposed credential or secret.
    Secret,
    /// A source-code or static-analysis finding.
    Code,
    /// A caller-defined finding class.
    Other(String),
}

impl FindingKind {
    pub(crate) const fn key_tag(&self) -> &'static str {
        match self {
            Self::Vulnerability => "vulnerability",
            Self::Misconfiguration => "misconfiguration",
            Self::Secret => "secret",
            Self::Code => "code",
            Self::Other(_) => "other",
        }
    }

    pub(crate) fn custom_key(&self) -> Option<&str> {
        match self {
            Self::Other(value) => Some(value),
            Self::Vulnerability | Self::Misconfiguration | Self::Secret | Self::Code => None,
        }
    }
}

/// One source occurrence prepared for correlation.
///
/// A candidate must be atomic: it represents one issue on one subject in one
/// caller-defined partition. Issue aliases must identify the same issue, and
/// multiple subject identifiers must identify the same subject. Compound rows
/// should be split before creating candidates.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Candidate {
    origin: Origin,
    partition: String,
    kind: FindingKind,
    issue_ids: Box<[IssueId]>,
    subject_ids: Box<[SubjectId]>,
    subject_names: Box<[String]>,
    title: Option<String>,
    location: Option<String>,
    affected_version: Option<String>,
}

impl Candidate {
    /// Starts a candidate builder with source-local identity.
    #[must_use]
    pub fn builder(source: impl Into<String>, native_id: impl Into<String>) -> CandidateBuilder {
        CandidateBuilder {
            source: source.into(),
            native_id: native_id.into(),
            ..CandidateBuilder::default()
        }
    }

    /// Returns the source-local origin.
    #[must_use]
    pub fn origin(&self) -> &Origin {
        &self.origin
    }

    /// Returns the caller-defined hard correlation boundary.
    #[must_use]
    pub fn partition(&self) -> &str {
        &self.partition
    }

    /// Returns the finding class.
    #[must_use]
    pub fn kind(&self) -> &FindingKind {
        &self.kind
    }

    /// Returns normalized issue identifiers and aliases.
    #[must_use]
    pub fn issue_ids(&self) -> &[IssueId] {
        &self.issue_ids
    }

    /// Returns normalized structured subject identifiers.
    #[must_use]
    pub fn subject_ids(&self) -> &[SubjectId] {
        &self.subject_ids
    }

    /// Returns caller-provided subject names used for fuzzy evidence.
    #[must_use]
    pub fn subject_names(&self) -> &[String] {
        &self.subject_names
    }

    /// Returns the optional finding title.
    #[must_use]
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    /// Returns the optional location, such as a path, repository, or image.
    #[must_use]
    pub fn location(&self) -> Option<&str> {
        self.location.as_deref()
    }

    /// Returns the optional affected version supplied separately from subject identifiers.
    #[must_use]
    pub fn affected_version(&self) -> Option<&str> {
        self.affected_version.as_deref()
    }
}

/// Builds and validates a [`Candidate`].
#[derive(Debug, Default)]
pub struct CandidateBuilder {
    source: String,
    subtype: Option<String>,
    native_id: String,
    partition: Option<String>,
    kind: FindingKind,
    issue_ids: Vec<String>,
    subject_ids: Vec<SubjectId>,
    subject_names: Vec<String>,
    title: Option<String>,
    location: Option<String>,
    affected_version: Option<String>,
}

impl CandidateBuilder {
    /// Sets an optional subtype within the source.
    #[must_use]
    pub fn subtype(mut self, subtype: impl Into<String>) -> Self {
        self.subtype = Some(subtype.into());
        self
    }

    /// Sets the hard correlation boundary.
    ///
    /// Candidates in different partitions are never comparable. Use a literal
    /// value such as `"global"` only when cross-asset correlation is intended.
    #[must_use]
    pub fn partition(mut self, partition: impl Into<String>) -> Self {
        self.partition = Some(partition.into());
        self
    }

    /// Sets the finding class.
    #[must_use]
    pub fn kind(mut self, kind: FindingKind) -> Self {
        self.kind = kind;
        self
    }

    /// Adds an issue identifier or alias.
    #[must_use]
    pub fn issue(mut self, issue_id: impl Into<String>) -> Self {
        self.issue_ids.push(issue_id.into());
        self
    }

    /// Adds another alias for the same atomic issue.
    #[must_use]
    pub fn issue_alias(self, issue_id: impl Into<String>) -> Self {
        self.issue(issue_id)
    }

    /// Adds a parsed Package URL subject identifier.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError`] when `value` is not a valid, canonicalizable PURL.
    pub fn purl(mut self, value: &str) -> Result<Self, IdentityError> {
        self.subject_ids
            .push(SubjectId::Purl(NormalizedPurl::parse(value)?));
        Ok(self)
    }

    /// Adds a parsed CPE subject identifier.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError`] when `value` is not a supported valid CPE binding.
    pub fn cpe(mut self, value: &str) -> Result<Self, IdentityError> {
        self.subject_ids
            .push(SubjectId::Cpe(NormalizedCpe::parse(value)?));
        Ok(self)
    }

    /// Adds an already normalized subject identifier.
    #[must_use]
    pub fn subject(mut self, subject: SubjectId) -> Self {
        self.subject_ids.push(subject);
        self
    }

    /// Adds a human-readable subject name for fuzzy comparison.
    #[must_use]
    pub fn subject_name(mut self, name: impl Into<String>) -> Self {
        self.subject_names.push(name.into());
        self
    }

    /// Sets a title used as fuzzy supporting evidence.
    #[must_use]
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Sets a location used as supporting evidence.
    #[must_use]
    pub fn location(mut self, location: impl Into<String>) -> Self {
        self.location = Some(location.into());
        self
    }

    /// Sets an affected version when it is not already encoded in the subject ID.
    #[must_use]
    pub fn affected_version(mut self, version: impl Into<String>) -> Self {
        self.affected_version = Some(version.into());
        self
    }

    /// Validates and builds the candidate.
    ///
    /// # Errors
    ///
    /// Returns [`CandidateError`] when required identity fields are empty, a
    /// control character is present, or no comparable evidence was supplied.
    pub fn build(self) -> Result<Candidate, CandidateError> {
        let source = required(self.source, "source")?;
        let native_id = required(self.native_id, "native_id")?;
        let partition = required(self.partition.unwrap_or_default(), "partition")?;
        let subtype = optional(self.subtype, "subtype")?;
        let title = optional(self.title, "title")?;
        let location = optional(self.location, "location")?;
        let affected_version = optional(self.affected_version, "affected_version")?;
        let kind = match self.kind {
            FindingKind::Other(value) => FindingKind::Other(required(value, "kind")?),
            known => known,
        };

        let mut issue_ids = self
            .issue_ids
            .into_iter()
            .map(IssueId::new)
            .collect::<Result<Vec<_>, _>>()?;
        issue_ids.sort_unstable();
        issue_ids.dedup();

        let mut subject_ids = self.subject_ids;
        subject_ids.sort_unstable();
        subject_ids.dedup();

        let mut subject_names = self
            .subject_names
            .into_iter()
            .map(|value| required(value, "subject_name"))
            .collect::<Result<Vec<_>, _>>()?;
        subject_names.sort_unstable();
        subject_names.dedup();

        if issue_ids.is_empty()
            && subject_ids.is_empty()
            && subject_names.is_empty()
            && title.is_none()
        {
            return Err(CandidateError::NoEvidence);
        }

        Ok(Candidate {
            origin: Origin {
                source,
                subtype,
                native_id,
            },
            partition,
            kind,
            issue_ids: issue_ids.into_boxed_slice(),
            subject_ids: subject_ids.into_boxed_slice(),
            subject_names: subject_names.into_boxed_slice(),
            title,
            location,
            affected_version,
        })
    }
}

/// A candidate construction error.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum CandidateError {
    /// A required field was blank.
    #[error("candidate field `{field}` must not be empty")]
    EmptyField {
        /// The invalid field name.
        field: &'static str,
    },
    /// An issue identifier was blank.
    #[error("issue identifier must not be empty")]
    EmptyIssueId,
    /// A text field contained a control character.
    #[error("candidate field `{field}` contains a control character")]
    ControlCharacter {
        /// The invalid field name.
        field: &'static str,
    },
    /// No structured or textual comparison evidence was supplied.
    #[error("candidate must contain an issue, subject, subject name, or title")]
    NoEvidence,
}

fn starts_with_ignore_ascii_case(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

fn validate_text(value: &str, field: &'static str) -> Result<(), CandidateError> {
    if value.trim().is_empty() {
        return Err(CandidateError::EmptyField { field });
    }
    if value.chars().any(char::is_control) {
        return Err(CandidateError::ControlCharacter { field });
    }
    Ok(())
}

fn required(value: String, field: &'static str) -> Result<String, CandidateError> {
    validate_text(&value, field)?;
    Ok(value.trim().to_owned())
}

fn optional(value: Option<String>, field: &'static str) -> Result<Option<String>, CandidateError> {
    value.map(|value| required(value, field)).transpose()
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Origin {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireOrigin {
            source: String,
            subtype: Option<String>,
            native_id: String,
        }

        let wire = <WireOrigin as serde::Deserialize>::deserialize(deserializer)?;
        Ok(Self {
            source: required(wire.source, "source").map_err(serde::de::Error::custom)?,
            subtype: optional(wire.subtype, "subtype").map_err(serde::de::Error::custom)?,
            native_id: required(wire.native_id, "native_id").map_err(serde::de::Error::custom)?,
        })
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for IssueId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for IssueId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Candidate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireCandidate {
            origin: Origin,
            partition: String,
            #[serde(default)]
            kind: FindingKind,
            #[serde(default)]
            issue_ids: Vec<String>,
            #[serde(default)]
            subject_ids: Vec<SubjectId>,
            #[serde(default)]
            subject_names: Vec<String>,
            title: Option<String>,
            location: Option<String>,
            affected_version: Option<String>,
        }

        let wire = <WireCandidate as serde::Deserialize>::deserialize(deserializer)?;
        let mut builder = Candidate::builder(wire.origin.source, wire.origin.native_id)
            .partition(wire.partition)
            .kind(wire.kind);
        if let Some(subtype) = wire.origin.subtype {
            builder = builder.subtype(subtype);
        }
        for issue in wire.issue_ids {
            builder = builder.issue(issue);
        }
        for subject in wire.subject_ids {
            builder = builder.subject(subject);
        }
        for name in wire.subject_names {
            builder = builder.subject_name(name);
        }
        if let Some(title) = wire.title {
            builder = builder.title(title);
        }
        if let Some(location) = wire.location {
            builder = builder.location(location);
        }
        if let Some(version) = wire.affected_version {
            builder = builder.affected_version(version);
        }
        builder.build().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_id_normalizes_known_identifier_case() {
        assert_eq!(
            IssueId::new(" cve-2024-3094 ").unwrap().as_str(),
            "CVE-2024-3094"
        );
    }

    #[test]
    fn issue_id_preserves_unknown_identifier_case() {
        assert_eq!(IssueId::new("Vendor-AbC").unwrap().as_str(), "Vendor-AbC");
    }

    #[test]
    fn build_sorts_and_deduplicates_aliases() {
        let candidate = Candidate::builder("one", "17")
            .partition("global")
            .issue("CVE-2024-2")
            .issue("cve-2024-1")
            .issue("CVE-2024-2")
            .build()
            .unwrap();

        let actual = candidate
            .issue_ids()
            .iter()
            .map(IssueId::as_str)
            .collect::<Vec<_>>();
        assert_eq!(actual, ["CVE-2024-1", "CVE-2024-2"]);
    }

    #[test]
    fn build_rejects_missing_partition() {
        let error = Candidate::builder("one", "17")
            .issue("CVE-2024-1")
            .build()
            .unwrap_err();
        assert_eq!(error, CandidateError::EmptyField { field: "partition" });
    }

    #[test]
    fn build_rejects_candidate_without_evidence() {
        let error = Candidate::builder("one", "17")
            .partition("global")
            .build()
            .unwrap_err();
        assert_eq!(error, CandidateError::NoEvidence);
    }

    #[test]
    fn custom_finding_kind_is_trimmed() {
        let candidate = Candidate::builder("one", "17")
            .partition("global")
            .kind(FindingKind::Other("  policy  ".to_owned()))
            .title("Finding")
            .build()
            .unwrap();

        assert_eq!(candidate.kind(), &FindingKind::Other("policy".to_owned()));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_revalidates_and_normalizes_candidates() {
        let json = r#"{
            "origin":{"source":" scanner ","subtype":null,"native_id":" 17 "},
            "partition":" global ",
            "kind":"vulnerability",
            "issue_ids":["cve-2024-1"],
            "subject_ids":[],
            "subject_names":[],
            "title":null,
            "location":null,
            "affected_version":null
        }"#;
        let candidate: Candidate = serde_json::from_str(json).unwrap();

        assert_eq!(candidate.origin().source(), "scanner");
        assert_eq!(candidate.partition(), "global");
        assert_eq!(candidate.issue_ids()[0].as_str(), "CVE-2024-1");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_rejects_invalid_candidate_state() {
        let json = r#"{
            "origin":{"source":"scanner","subtype":null,"native_id":"17"},
            "partition":"global",
            "kind":"vulnerability",
            "issue_ids":[],
            "subject_ids":[],
            "subject_names":[],
            "title":null,
            "location":null,
            "affected_version":null
        }"#;

        assert!(serde_json::from_str::<Candidate>(json).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_rejects_unknown_fields() {
        let candidate_json = r#"{
            "origin":{"source":"scanner","subtype":null,"native_id":"17"},
            "partition":"global",
            "issue_idz":["CVE-2024-1"],
            "title":"Finding"
        }"#;
        assert!(serde_json::from_str::<Candidate>(candidate_json).is_err());

        let origin_json = r#"{
            "source":"scanner",
            "subtype":null,
            "native_id":"17",
            "unexpected":true
        }"#;
        assert!(serde_json::from_str::<Origin>(origin_json).is_err());
    }

    #[test]
    fn issue_id_rejects_empty_value() {
        assert_eq!(IssueId::new("   ").unwrap_err(), CandidateError::EmptyIssueId);
    }

    #[test]
    fn issue_id_rejects_control_characters() {
        assert_eq!(
            IssueId::new("CVE-2024-1\u{0007}").unwrap_err(),
            CandidateError::ControlCharacter { field: "issue_id" }
        );
    }

    #[test]
    fn build_rejects_control_character_in_title() {
        let error = Candidate::builder("one", "17")
            .partition("global")
            .title("bad\u{0007}title")
            .build()
            .unwrap_err();
        assert_eq!(error, CandidateError::ControlCharacter { field: "title" });
    }

    #[test]
    fn build_rejects_blank_subject_name() {
        let error = Candidate::builder("one", "17")
            .partition("global")
            .title("Finding")
            .subject_name("   ")
            .build()
            .unwrap_err();
        assert_eq!(error, CandidateError::EmptyField { field: "subject_name" });
    }

    #[test]
    fn custom_finding_kind_rejects_blank_value() {
        let error = Candidate::builder("one", "17")
            .partition("global")
            .kind(FindingKind::Other("   ".to_owned()))
            .title("Finding")
            .build()
            .unwrap_err();
        assert_eq!(error, CandidateError::EmptyField { field: "kind" });
    }

    #[test]
    fn build_sorts_and_deduplicates_subject_ids_and_names() {
        let candidate = Candidate::builder("one", "17")
            .partition("global")
            .purl("pkg:generic/widget@2")
            .unwrap()
            .purl("pkg:generic/widget@1")
            .unwrap()
            .purl("pkg:generic/widget@1")
            .unwrap()
            .subject_name("Zeta")
            .subject_name("Alpha")
            .subject_name("Zeta")
            .build()
            .unwrap();

        assert_eq!(candidate.subject_ids().len(), 2);
        let names = candidate
            .subject_names()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        assert_eq!(names, ["Alpha", "Zeta"]);
    }

    #[test]
    fn builder_stores_optional_fields_trimmed() {
        let candidate = Candidate::builder("one", "17")
            .subtype(" agent ")
            .partition("global")
            .issue("CVE-2024-1")
            .location(" /etc/passwd ")
            .affected_version(" 1.2.3 ")
            .build()
            .unwrap();

        assert_eq!(candidate.origin().subtype(), Some("agent"));
        assert_eq!(candidate.location(), Some("/etc/passwd"));
        assert_eq!(candidate.affected_version(), Some("1.2.3"));
    }

    #[test]
    fn issue_id_display_matches_as_str() {
        let issue = IssueId::new("cve-2024-1").unwrap();
        assert_eq!(issue.to_string(), issue.as_str());
    }
}
