use crate::normalize;
use crate::{Candidate, Config, CorrelationKey, OccurrenceKey, SubjectId};

/// A deterministic similarity score in basis points (`0..=10_000`).
///
/// Scores are evidence rankings, not calibrated probabilities.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(try_from = "u16", into = "u16")
)]
pub struct Score(u16);

impl Score {
    /// The highest possible score.
    pub const MAX: Self = Self(10_000);

    /// Creates a validated score.
    ///
    /// # Errors
    ///
    /// Returns [`ScoreError`] when `value` is greater than 10,000.
    pub const fn new(value: u16) -> Result<Self, ScoreError> {
        if value <= Self::MAX.0 {
            Ok(Self(value))
        } else {
            Err(ScoreError(value))
        }
    }

    pub(crate) const fn from_valid(value: u16) -> Self {
        Self(value)
    }

    pub(crate) fn from_ratio(value: f64) -> Self {
        let basis_points = (value.clamp(0.0, 1.0) * f64::from(Self::MAX.0)).round() as u16;
        Self(basis_points)
    }

    /// Returns the basis-point value.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl From<Score> for u16 {
    fn from(value: Score) -> Self {
        value.get()
    }
}

impl TryFrom<u16> for Score {
    type Error = ScoreError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// A score outside the inclusive `0..=10_000` range.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("score must be at most 10000, got {0}")]
#[non_exhaustive]
pub struct ScoreError(pub(crate) u16);

impl ScoreError {
    /// Returns the rejected basis-point value.
    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }
}

/// The decision produced for a candidate pair.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Decision {
    /// The pair has enough anchored evidence to correlate automatically.
    Duplicate,
    /// The pair is plausible but requires a caller or operator decision.
    Review,
    /// Comparable evidence indicates separate findings.
    Distinct,
    /// A hard boundary or policy prevents comparison.
    NotComparable,
}

/// The primary path used to reach a comparison decision.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum MatchMethod {
    /// The source-local occurrence keys were identical.
    SameOccurrence,
    /// A versioned exact correlation key was shared.
    ExactCorrelation,
    /// Structured anchors and RapidFuzz text similarity were scored.
    Fuzzy,
    /// A partition, kind, source policy, or hard conflict stopped matching.
    Blocked,
}

/// A field evaluated during comparison.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum SignalField {
    /// Hard caller-defined partition.
    Partition,
    /// Broad finding class.
    Kind,
    /// Source provenance.
    Source,
    /// Vulnerability, advisory, rule, or weakness identifier.
    Issue,
    /// Full or versionless structured subject identity.
    Subject,
    /// Explicit affected or package version.
    Version,
    /// Human-readable subject name.
    SubjectName,
    /// Finding title.
    Title,
    /// Finding location.
    Location,
}

/// The observed relationship for a comparison signal.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum SignalKind {
    /// Canonical values matched exactly.
    Exact,
    /// Values were compatible or fuzzily similar without being exact.
    Similar,
    /// Comparable values differed.
    Different,
    /// One or both candidates lacked the field.
    Missing,
    /// Structured values used different identifier kinds.
    Incomparable,
    /// Cross-source-only policy excluded two occurrences from one source.
    SameSource,
}

/// One privacy-preserving piece of comparison evidence.
///
/// Signals identify fields and scores without copying raw titles, paths, or IDs.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Signal {
    field: SignalField,
    kind: SignalKind,
    score: Option<Score>,
}

impl Signal {
    fn new(field: SignalField, kind: SignalKind, score: Option<Score>) -> Self {
        Self { field, kind, score }
    }

    /// Returns the field that was compared.
    #[must_use]
    pub const fn field(&self) -> SignalField {
        self.field
    }

    /// Returns the relationship observed for the field.
    #[must_use]
    pub const fn kind(&self) -> SignalKind {
        self.kind
    }

    /// Returns a fuzzy field score when applicable.
    #[must_use]
    pub const fn score(&self) -> Option<Score> {
        self.score
    }
}

/// An explainable, symmetric comparison between two occurrences.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Comparison {
    left: OccurrenceKey,
    right: OccurrenceKey,
    decision: Decision,
    score: Option<Score>,
    method: MatchMethod,
    signals: Box<[Signal]>,
}

impl Comparison {
    /// Returns the lexicographically first occurrence key.
    #[must_use]
    pub const fn left(&self) -> OccurrenceKey {
        self.left
    }

    /// Returns the lexicographically second occurrence key.
    #[must_use]
    pub const fn right(&self) -> OccurrenceKey {
        self.right
    }

    /// Returns the correlation decision.
    #[must_use]
    pub const fn decision(&self) -> Decision {
        self.decision
    }

    /// Returns the evidence score, or `None` when a hard comparability boundary
    /// produced [`Decision::NotComparable`].
    #[must_use]
    pub const fn score(&self) -> Option<Score> {
        self.score
    }

    /// Returns the primary matching method.
    #[must_use]
    pub const fn method(&self) -> MatchMethod {
        self.method
    }

    /// Returns ordered, privacy-preserving field evidence.
    #[must_use]
    pub fn signals(&self) -> &[Signal] {
        &self.signals
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Signal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireSignal {
            field: SignalField,
            kind: SignalKind,
            score: Option<Score>,
        }

        let wire = <WireSignal as serde::Deserialize>::deserialize(deserializer)?;
        let valid_score = match (wire.field, wire.kind) {
            (_, SignalKind::Exact) => wire.score == Some(Score::MAX),
            (SignalField::Subject, SignalKind::Similar) => wire.score == Some(Score::MAX),
            (_, SignalKind::Similar) => wire.score.is_some_and(|score| score < Score::MAX),
            (
                _,
                SignalKind::Different
                | SignalKind::Missing
                | SignalKind::Incomparable
                | SignalKind::SameSource,
            ) => wire.score.is_none(),
        };
        if !valid_score {
            return Err(serde::de::Error::custom(
                "signal score is inconsistent with its relationship",
            ));
        }
        Ok(Self {
            field: wire.field,
            kind: wire.kind,
            score: wire.score,
        })
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Comparison {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireComparison {
            left: OccurrenceKey,
            right: OccurrenceKey,
            decision: Decision,
            score: Option<Score>,
            method: MatchMethod,
            signals: Vec<Signal>,
        }

        let wire = <WireComparison as serde::Deserialize>::deserialize(deserializer)?;
        if wire.left > wire.right {
            return Err(serde::de::Error::custom(
                "comparison occurrence keys must be sorted",
            ));
        }
        if wire.signals.is_empty()
            || wire
                .signals
                .windows(2)
                .any(|pair| pair[0].field() >= pair[1].field())
        {
            return Err(serde::de::Error::custom(
                "comparison signals must be non-empty, unique, and field-sorted",
            ));
        }

        let valid_state = match wire.method {
            MatchMethod::SameOccurrence => {
                wire.left == wire.right
                    && wire.decision == Decision::Duplicate
                    && wire.score == Some(Score::MAX)
            }
            MatchMethod::ExactCorrelation => {
                wire.left < wire.right
                    && wire.decision == Decision::Duplicate
                    && wire.score == Some(Score::MAX)
            }
            MatchMethod::Fuzzy => {
                wire.left < wire.right
                    && wire.decision != Decision::NotComparable
                    && wire.score.is_some_and(|score| score < Score::MAX)
            }
            MatchMethod::Blocked => {
                wire.left < wire.right
                    && ((wire.decision == Decision::NotComparable && wire.score.is_none())
                        || (wire.decision == Decision::Distinct
                            && wire.score == Some(Score::from_valid(0))))
            }
        };
        if !valid_state {
            return Err(serde::de::Error::custom(
                "comparison decision, score, and method are inconsistent",
            ));
        }

        Ok(Self {
            left: wire.left,
            right: wire.right,
            decision: wire.decision,
            score: wire.score,
            method: wire.method,
            signals: wire.signals.into_boxed_slice(),
        })
    }
}

/// Immutable pairwise and batch deduplication engine.
#[derive(Clone, Debug)]
pub struct Deduplicator {
    pub(crate) config: Config,
}

#[derive(Clone, Copy)]
pub(crate) struct PreparedCandidate<'a> {
    candidate: &'a Candidate,
    occurrence_key: OccurrenceKey,
    correlation_keys: Option<&'a [CorrelationKey]>,
}

impl<'a> PreparedCandidate<'a> {
    pub(crate) const fn cached(
        candidate: &'a Candidate,
        occurrence_key: OccurrenceKey,
        correlation_keys: &'a [CorrelationKey],
    ) -> Self {
        Self {
            candidate,
            occurrence_key,
            correlation_keys: Some(correlation_keys),
        }
    }
}

impl Deduplicator {
    /// Creates an engine from a validated configuration.
    #[must_use]
    pub const fn new(config: Config) -> Self {
        Self { config }
    }

    /// Returns the active policy.
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// Computes the source-local key for a candidate.
    #[must_use]
    pub fn occurrence_key(&self, candidate: &Candidate) -> OccurrenceKey {
        OccurrenceKey::for_candidate(candidate)
    }

    /// Computes every exact correlation key implied by issue aliases and subjects.
    ///
    /// The result is sorted and deduplicated. By default, an issue without a
    /// structured subject has no exact correlation key; this can be enabled with
    /// [`ConfigBuilder::issue_only_exact`](crate::ConfigBuilder::issue_only_exact).
    #[must_use]
    pub fn correlation_keys(&self, candidate: &Candidate) -> Vec<CorrelationKey> {
        let mut keys = Vec::new();
        for issue in candidate.issue_ids() {
            for subject in candidate.subject_ids() {
                keys.push(CorrelationKey::for_issue_subject(
                    candidate.partition(),
                    candidate.kind(),
                    issue,
                    subject,
                ));
            }
            if candidate.subject_ids().is_empty() && self.config.issue_only_exact() {
                keys.push(CorrelationKey::for_issue_only(
                    candidate.partition(),
                    candidate.kind(),
                    issue,
                ));
            }
        }
        keys.sort_unstable();
        keys.dedup();
        keys
    }

    /// Compares two candidates using hard boundaries, exact keys, and fuzzy evidence.
    #[must_use]
    pub fn compare(&self, left: &Candidate, right: &Candidate) -> Comparison {
        let left_key = self.occurrence_key(left);
        let right_key = self.occurrence_key(right);
        self.compare_prepared(
            PreparedCandidate {
                candidate: left,
                occurrence_key: left_key,
                correlation_keys: None,
            },
            PreparedCandidate {
                candidate: right,
                occurrence_key: right_key,
                correlation_keys: None,
            },
        )
    }

    pub(crate) fn compare_prepared(
        &self,
        left: PreparedCandidate<'_>,
        right: PreparedCandidate<'_>,
    ) -> Comparison {
        let PreparedCandidate {
            candidate: left,
            occurrence_key: left_key,
            correlation_keys: cached_left_correlation,
        } = left;
        let PreparedCandidate {
            candidate: right,
            occurrence_key: right_key,
            correlation_keys: cached_right_correlation,
        } = right;
        let (first_key, second_key) = ordered_keys(left_key, right_key);

        if left_key == right_key {
            return comparison(
                first_key,
                second_key,
                Decision::Duplicate,
                Some(Score::MAX),
                MatchMethod::SameOccurrence,
                vec![Signal::new(
                    SignalField::Source,
                    SignalKind::Exact,
                    Some(Score::MAX),
                )],
            );
        }

        let mut signals = Vec::with_capacity(9);
        if left.partition() != right.partition() {
            signals.push(Signal::new(
                SignalField::Partition,
                SignalKind::Different,
                None,
            ));
            return blocked(first_key, second_key, signals);
        }
        signals.push(Signal::new(
            SignalField::Partition,
            SignalKind::Exact,
            Some(Score::MAX),
        ));

        if left.kind() != right.kind() {
            signals.push(Signal::new(SignalField::Kind, SignalKind::Different, None));
            return blocked(first_key, second_key, signals);
        }
        signals.push(Signal::new(
            SignalField::Kind,
            SignalKind::Exact,
            Some(Score::MAX),
        ));

        if self.config.cross_source_only() && left.origin().source() == right.origin().source() {
            signals.push(Signal::new(
                SignalField::Source,
                SignalKind::SameSource,
                None,
            ));
            return blocked(first_key, second_key, signals);
        }

        let computed_left_correlation;
        let left_correlation = if let Some(keys) = cached_left_correlation {
            keys
        } else {
            computed_left_correlation = self.correlation_keys(left);
            &computed_left_correlation
        };
        let computed_right_correlation;
        let right_correlation = if let Some(keys) = cached_right_correlation {
            keys
        } else {
            computed_right_correlation = self.correlation_keys(right);
            &computed_right_correlation
        };
        if sorted_intersects(left_correlation, right_correlation) {
            let exact_subject = sorted_intersects(left.subject_ids(), right.subject_ids());
            signals.push(Signal::new(
                SignalField::Issue,
                SignalKind::Exact,
                Some(Score::MAX),
            ));
            signals.push(Signal::new(
                SignalField::Subject,
                if exact_subject {
                    SignalKind::Exact
                } else {
                    SignalKind::Missing
                },
                exact_subject.then_some(Score::MAX),
            ));
            return comparison(
                first_key,
                second_key,
                Decision::Duplicate,
                Some(Score::MAX),
                MatchMethod::ExactCorrelation,
                signals,
            );
        }

        let evidence = Evidence::collect(left, right);
        signals.extend(evidence.signals());

        if evidence.issue_conflict || evidence.subject_conflict {
            return comparison(
                first_key,
                second_key,
                Decision::Distinct,
                Some(Score::from_valid(0)),
                MatchMethod::Blocked,
                signals,
            );
        }

        let (score, auto_eligible) = evidence.score(&self.config);
        let decision = if auto_eligible && score >= self.config.duplicate_threshold() {
            Decision::Duplicate
        } else if score >= self.config.review_threshold() {
            Decision::Review
        } else {
            Decision::Distinct
        };

        comparison(
            first_key,
            second_key,
            decision,
            Some(score),
            MatchMethod::Fuzzy,
            signals,
        )
    }
}

impl Default for Deduplicator {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

struct Evidence {
    shared_issue: bool,
    issue_conflict: bool,
    exact_subject: bool,
    coordinate_match: bool,
    compatible_coordinate_match: bool,
    subject_detail_conflict: bool,
    subject_conflict: bool,
    cross_kind_subjects: bool,
    version_relation: SignalKind,
    subject_name: Score,
    title: Score,
    location: Score,
    has_subject_name_pair: bool,
    has_title_pair: bool,
    has_location_pair: bool,
}

impl Evidence {
    fn collect(left: &Candidate, right: &Candidate) -> Self {
        let shared_issue = sorted_intersects(left.issue_ids(), right.issue_ids());
        let issue_conflict =
            !left.issue_ids().is_empty() && !right.issue_ids().is_empty() && !shared_issue;

        let exact_subject = sorted_intersects(left.subject_ids(), right.subject_ids());
        let coordinate_match = coordinates_intersect(left.subject_ids(), right.subject_ids());
        let compatible_coordinate_match =
            compatible_coordinates_intersect(left.subject_ids(), right.subject_ids());
        let subject_detail_conflict = coordinate_match && !compatible_coordinate_match;
        let comparable_subject_kinds = left.subject_ids().iter().any(|left_subject| {
            right
                .subject_ids()
                .iter()
                .any(|right_subject| left_subject.kind_tag() == right_subject.kind_tag())
        });
        let cross_kind_subjects = !left.subject_ids().is_empty()
            && !right.subject_ids().is_empty()
            && !comparable_subject_kinds;
        let subject_conflict =
            shared_issue && comparable_subject_kinds && !coordinate_match && !exact_subject;

        let left_versions = versions(left);
        let right_versions = versions(right);
        let version_relation = if left_versions.is_empty() || right_versions.is_empty() {
            SignalKind::Missing
        } else if sorted_intersects(&left_versions, &right_versions) {
            SignalKind::Exact
        } else {
            SignalKind::Different
        };

        let left_names = subject_names(left);
        let right_names = subject_names(right);
        let (subject_name, has_subject_name_pair) = best_similarity(&left_names, &right_names);
        let (title, has_title_pair) = optional_similarity(left.title(), right.title());
        let (location, has_location_pair) = optional_similarity(left.location(), right.location());

        Self {
            shared_issue,
            issue_conflict,
            exact_subject,
            coordinate_match,
            compatible_coordinate_match,
            subject_detail_conflict,
            subject_conflict,
            cross_kind_subjects,
            version_relation,
            subject_name,
            title,
            location,
            has_subject_name_pair,
            has_title_pair,
            has_location_pair,
        }
    }

    fn score(&self, config: &Config) -> (Score, bool) {
        let value = if self.shared_issue && self.coordinate_match {
            let version_bonus = if self.version_relation == SignalKind::Exact {
                500
            } else {
                0
            };
            8_500 + version_bonus + contribution(self.title, 300) + contribution(self.location, 200)
        } else if self.shared_issue {
            5_000
                + contribution(self.subject_name, 3_000)
                + contribution(self.title, 1_000)
                + contribution(self.location, 500)
        } else if self.exact_subject {
            6_000 + contribution(self.title, 2_000) + contribution(self.location, 1_000)
        } else if self.coordinate_match {
            5_500
                + contribution(self.subject_name, 500)
                + contribution(self.title, 2_000)
                + contribution(self.location, 1_000)
        } else {
            let primary = self.subject_name.max(self.title);
            u32::from(primary.get()) + contribution(self.location, 500)
        };
        let score = Score::from_valid(value.min(9_999) as u16);
        let strong_subject_name = self.has_subject_name_pair
            && self.subject_name.get() > 0
            && self.subject_name >= config.subject_similarity_threshold();
        let auto_eligible = self.shared_issue
            && !self.cross_kind_subjects
            && self.version_relation != SignalKind::Different
            && !self.subject_detail_conflict
            && (self.compatible_coordinate_match || strong_subject_name);
        (score, auto_eligible)
    }

    fn signals(&self) -> Vec<Signal> {
        let mut signals = Vec::with_capacity(6);
        let issue_kind = if self.shared_issue {
            SignalKind::Exact
        } else if self.issue_conflict {
            SignalKind::Different
        } else {
            SignalKind::Missing
        };
        signals.push(Signal::new(
            SignalField::Issue,
            issue_kind,
            self.shared_issue.then_some(Score::MAX),
        ));

        let subject_kind = if self.exact_subject {
            SignalKind::Exact
        } else if self.subject_detail_conflict {
            SignalKind::Different
        } else if self.coordinate_match {
            SignalKind::Similar
        } else if self.subject_conflict {
            SignalKind::Different
        } else if self.cross_kind_subjects {
            SignalKind::Incomparable
        } else {
            SignalKind::Missing
        };
        signals.push(Signal::new(
            SignalField::Subject,
            subject_kind,
            (self.exact_subject || self.compatible_coordinate_match).then_some(Score::MAX),
        ));
        signals.push(Signal::new(
            SignalField::Version,
            self.version_relation,
            (self.version_relation == SignalKind::Exact).then_some(Score::MAX),
        ));
        signals.push(fuzzy_signal(
            SignalField::SubjectName,
            self.subject_name,
            self.has_subject_name_pair,
        ));
        signals.push(fuzzy_signal(
            SignalField::Title,
            self.title,
            self.has_title_pair,
        ));
        signals.push(fuzzy_signal(
            SignalField::Location,
            self.location,
            self.has_location_pair,
        ));
        signals
    }
}

fn subject_names(candidate: &Candidate) -> Vec<&str> {
    candidate
        .subject_names()
        .iter()
        .map(String::as_str)
        .chain(candidate.subject_ids().iter().map(SubjectId::subject_name))
        .filter(|value| !value.is_empty())
        .collect()
}

fn versions(candidate: &Candidate) -> Vec<&str> {
    let mut versions = candidate
        .affected_version()
        .into_iter()
        .chain(
            candidate
                .subject_ids()
                .iter()
                .filter_map(SubjectId::version),
        )
        .collect::<Vec<_>>();
    versions.sort_unstable();
    versions.dedup();
    versions
}

fn coordinates_intersect(left: &[SubjectId], right: &[SubjectId]) -> bool {
    left.iter().any(|left_subject| {
        right.iter().any(|right_subject| {
            left_subject.kind_tag() == right_subject.kind_tag()
                && left_subject.coordinate() == right_subject.coordinate()
        })
    })
}

fn compatible_coordinates_intersect(left: &[SubjectId], right: &[SubjectId]) -> bool {
    left.iter().any(|left_subject| {
        right.iter().any(|right_subject| {
            left_subject.kind_tag() == right_subject.kind_tag()
                && left_subject.coordinate() == right_subject.coordinate()
                && left_subject.details_compatible(right_subject)
        })
    })
}

fn best_similarity(left: &[&str], right: &[&str]) -> (Score, bool) {
    let mut best = Score::from_valid(0);
    let mut compared = false;
    for left_value in left {
        for right_value in right {
            compared = true;
            best = best.max(Score::from_ratio(normalize::similarity(
                left_value,
                right_value,
            )));
        }
    }
    (best, compared)
}

fn optional_similarity(left: Option<&str>, right: Option<&str>) -> (Score, bool) {
    match (left, right) {
        (Some(left), Some(right)) => (Score::from_ratio(normalize::similarity(left, right)), true),
        _ => (Score::from_valid(0), false),
    }
}

fn contribution(score: Score, weight: u32) -> u32 {
    u32::from(score.get()) * weight / u32::from(Score::MAX.get())
}

fn fuzzy_signal(field: SignalField, score: Score, compared: bool) -> Signal {
    if compared {
        let kind = if score == Score::MAX {
            SignalKind::Exact
        } else {
            SignalKind::Similar
        };
        Signal::new(field, kind, Some(score))
    } else {
        Signal::new(field, SignalKind::Missing, None)
    }
}

fn sorted_intersects<T: Ord>(left: &[T], right: &[T]) -> bool {
    let mut left_index = 0;
    let mut right_index = 0;
    while left_index < left.len() && right_index < right.len() {
        match left[left_index].cmp(&right[right_index]) {
            std::cmp::Ordering::Less => left_index += 1,
            std::cmp::Ordering::Greater => right_index += 1,
            std::cmp::Ordering::Equal => return true,
        }
    }
    false
}

fn ordered_keys(left: OccurrenceKey, right: OccurrenceKey) -> (OccurrenceKey, OccurrenceKey) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

fn comparison(
    left: OccurrenceKey,
    right: OccurrenceKey,
    decision: Decision,
    score: Option<Score>,
    method: MatchMethod,
    signals: Vec<Signal>,
) -> Comparison {
    Comparison {
        left,
        right,
        decision,
        score,
        method,
        signals: signals.into_boxed_slice(),
    }
}

fn blocked(left: OccurrenceKey, right: OccurrenceKey, signals: Vec<Signal>) -> Comparison {
    comparison(
        left,
        right,
        Decision::NotComparable,
        None,
        MatchMethod::Blocked,
        signals,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Candidate;

    fn finding(source: &str, native_id: &str, title: &str) -> Candidate {
        Candidate::builder(source, native_id)
            .partition("repo:example")
            .issue("CVE-2024-3094")
            .subject_name("xz-utils")
            .title(title)
            .build()
            .unwrap()
    }

    #[test]
    fn compare_is_symmetric() {
        let engine = Deduplicator::default();
        let left = finding("one", "1", "Backdoored xz package");
        let right = finding("two", "2", "xz package backdoor");

        assert_eq!(engine.compare(&left, &right), engine.compare(&right, &left));
    }

    #[test]
    fn cached_comparison_matches_the_public_pairwise_path() {
        fn assert_equivalent(engine: &Deduplicator, left: &Candidate, right: &Candidate) {
            let left_key = engine.occurrence_key(left);
            let right_key = engine.occurrence_key(right);
            let left_correlation = engine.correlation_keys(left);
            let right_correlation = engine.correlation_keys(right);
            let cached = engine.compare_prepared(
                PreparedCandidate::cached(left, left_key, &left_correlation),
                PreparedCandidate::cached(right, right_key, &right_correlation),
            );

            assert_eq!(cached, engine.compare(left, right));
        }

        let engine = Deduplicator::default();
        let same = finding("one", "1", "Finding");
        assert_equivalent(&engine, &same, &same);

        let fuzzy_left = finding("one", "1", "Backdoored xz package");
        let fuzzy_right = finding("two", "2", "xz package backdoor");
        assert_equivalent(&engine, &fuzzy_left, &fuzzy_right);

        let exact_left = Candidate::builder("one", "1")
            .partition("repo:example")
            .issue("CVE-2024-3094")
            .purl("pkg:cargo/widget@1.0.0")
            .unwrap()
            .build()
            .unwrap();
        let exact_right = Candidate::builder("two", "2")
            .partition("repo:example")
            .issue("CVE-2024-3094")
            .purl("pkg:cargo/widget@1.0.0")
            .unwrap()
            .build()
            .unwrap();
        assert_equivalent(&engine, &exact_left, &exact_right);

        let different_partition = Candidate::builder("two", "3")
            .partition("repo:different")
            .issue("CVE-2024-3094")
            .title("Finding")
            .build()
            .unwrap();
        assert_equivalent(&engine, &same, &different_partition);
    }

    #[test]
    fn compare_blocks_different_partitions() {
        let engine = Deduplicator::default();
        let left = finding("one", "1", "Finding");
        let right = Candidate::builder("two", "2")
            .partition("repo:different")
            .issue("CVE-2024-3094")
            .title("Finding")
            .build()
            .unwrap();

        assert_eq!(
            engine.compare(&left, &right).decision(),
            Decision::NotComparable
        );
    }

    #[test]
    fn compare_blocks_conflicting_issue_ids() {
        let engine = Deduplicator::default();
        let left = finding("one", "1", "Identical title");
        let right = Candidate::builder("two", "2")
            .partition("repo:example")
            .issue("CVE-2024-9999")
            .subject_name("xz-utils")
            .title("Identical title")
            .build()
            .unwrap();

        assert_eq!(engine.compare(&left, &right).decision(), Decision::Distinct);
    }

    #[test]
    fn text_only_similarity_never_auto_merges() {
        let engine = Deduplicator::default();
        let left = Candidate::builder("one", "1")
            .partition("repo:example")
            .title("Public S3 bucket")
            .build()
            .unwrap();
        let right = Candidate::builder("two", "2")
            .partition("repo:example")
            .title("Public S3 bucket")
            .build()
            .unwrap();

        assert_eq!(engine.compare(&left, &right).decision(), Decision::Review);
    }

    #[test]
    fn conflicting_versions_require_review() {
        let engine = Deduplicator::default();
        let left = Candidate::builder("one", "1")
            .partition("repo:example")
            .issue("CVE-2024-3094")
            .purl("pkg:cargo/widget@1.0.0")
            .unwrap()
            .build()
            .unwrap();
        let right = Candidate::builder("two", "2")
            .partition("repo:example")
            .issue("CVE-2024-3094")
            .purl("pkg:cargo/widget@2.0.0")
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(engine.compare(&left, &right).decision(), Decision::Review);
    }

    #[test]
    fn conflicting_purl_qualifiers_require_review() {
        let engine = Deduplicator::default();
        let left = Candidate::builder("one", "1")
            .partition("repo:example")
            .issue("CVE-2024-3094")
            .purl("pkg:deb/debian/widget@1.0?arch=amd64")
            .unwrap()
            .build()
            .unwrap();
        let right = Candidate::builder("two", "2")
            .partition("repo:example")
            .issue("CVE-2024-3094")
            .purl("pkg:deb/debian/widget@1.0?arch=arm64")
            .unwrap()
            .build()
            .unwrap();

        let comparison = engine.compare(&left, &right);
        assert_eq!(comparison.decision(), Decision::Review);
        assert!(comparison.signals().iter().any(|signal| {
            signal.field() == SignalField::Subject && signal.kind() == SignalKind::Different
        }));
    }

    #[test]
    fn one_sided_purl_qualifiers_remain_compatible() {
        let engine = Deduplicator::default();
        let left = Candidate::builder("one", "1")
            .partition("repo:example")
            .issue("CVE-2024-3094")
            .purl("pkg:deb/debian/widget@1.0?arch=amd64")
            .unwrap()
            .build()
            .unwrap();
        let right = Candidate::builder("two", "2")
            .partition("repo:example")
            .issue("CVE-2024-3094")
            .purl("pkg:deb/debian/widget@1.0")
            .unwrap()
            .build()
            .unwrap();

        let comparison = engine.compare(&left, &right);
        assert_eq!(comparison.decision(), Decision::Duplicate);
        assert!(comparison.signals().iter().any(|signal| {
            signal.field() == SignalField::Subject
                && signal.kind() == SignalKind::Similar
                && signal.score() == Some(Score::MAX)
        }));

        #[cfg(feature = "serde")]
        {
            let encoded = serde_json::to_value(&comparison).unwrap();
            let decoded: Comparison = serde_json::from_value(encoded).unwrap();
            assert_eq!(decoded, comparison);
        }
    }

    #[test]
    fn zero_subject_threshold_does_not_treat_missing_names_as_an_anchor() {
        let engine = Deduplicator::new(
            Config::builder()
                .duplicate_threshold(5_000)
                .review_threshold(0)
                .subject_similarity_threshold(0)
                .build()
                .unwrap(),
        );
        let left = Candidate::builder("one", "1")
            .partition("repo:example")
            .issue("CVE-2024-3094")
            .build()
            .unwrap();
        let right = Candidate::builder("two", "2")
            .partition("repo:example")
            .issue("CVE-2024-3094")
            .build()
            .unwrap();

        assert_eq!(engine.compare(&left, &right).decision(), Decision::Review);
    }

    #[test]
    fn same_source_policy_runs_after_same_occurrence_detection() {
        let engine = Deduplicator::default();
        let candidate = finding("one", "1", "Finding");
        assert_eq!(
            engine.compare(&candidate, &candidate).method(),
            MatchMethod::SameOccurrence
        );
    }

    #[test]
    fn correlation_keys_are_alias_order_independent() {
        let engine = Deduplicator::new(Config::builder().issue_only_exact(true).build().unwrap());
        let left = Candidate::builder("one", "1")
            .partition("global")
            .issue("GHSA-AAAA-BBBB-CCCC")
            .issue("CVE-2024-1")
            .build()
            .unwrap();
        let right = Candidate::builder("two", "2")
            .partition("global")
            .issue("CVE-2024-1")
            .issue("GHSA-AAAA-BBBB-CCCC")
            .build()
            .unwrap();

        assert_eq!(
            engine.correlation_keys(&left),
            engine.correlation_keys(&right)
        );
    }

    #[test]
    fn score_rejects_values_above_maximum() {
        assert_eq!(Score::new(10_001), Err(ScoreError(10_001)));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trips_comparisons_and_rejects_reversed_keys() {
        let engine = Deduplicator::default();
        let left = finding("one", "1", "Backdoored xz package");
        let right = finding("two", "2", "xz package backdoor");
        let comparison = engine.compare(&left, &right);
        let mut json = serde_json::to_value(&comparison).unwrap();

        let decoded: Comparison = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(decoded, comparison);

        let object = json.as_object_mut().unwrap();
        let left = object["left"].clone();
        let right = object["right"].clone();
        object.insert("left".to_owned(), right);
        object.insert("right".to_owned(), left);
        assert!(serde_json::from_value::<Comparison>(json).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_rejects_a_perfect_score_labeled_as_similar() {
        let json = r#"{"field":"title","kind":"similar","score":10000}"#;

        assert!(serde_json::from_str::<Signal>(json).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_rejects_unknown_fields() {
        let engine = Deduplicator::default();
        let comparison = engine.compare(
            &finding("one", "1", "Backdoored xz package"),
            &finding("two", "2", "xz package backdoor"),
        );

        let mut comparison_json = serde_json::to_value(&comparison).unwrap();
        comparison_json["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Comparison>(comparison_json).is_err());

        let mut signal_json = serde_json::to_value(&comparison.signals()[0]).unwrap();
        signal_json["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Signal>(signal_json).is_err());
    }
}
