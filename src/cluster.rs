use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

use crate::compare::PreparedCandidate;
use crate::{
    Candidate, Comparison, CorrelationKey, Decision, Deduplicator, FindingKind, MatchMethod,
    OccurrenceKey, OversizedBlockPolicy, Score,
};

/// The structured key that produced a batch candidate block.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum BlockKind {
    /// Candidates shared a normalized issue identifier.
    Issue,
    /// Candidates shared a versionless structured subject coordinate.
    Subject,
}

/// A non-fatal clustering condition returned to the caller.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum ClusterWarning {
    /// Fuzzy comparisons were skipped for a block while exact keys were retained.
    OversizedBlock {
        /// The kind of blocking key.
        kind: BlockKind,
        /// The number of candidates in the block.
        size: usize,
        /// The configured maximum block size.
        limit: usize,
    },
}

/// Aggregate counters from a clustering run.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ClusterStats {
    candidate_count: usize,
    candidate_pair_count: usize,
    comparison_count: usize,
    exact_merge_count: usize,
    fuzzy_merge_count: usize,
    cluster_count: usize,
}

impl ClusterStats {
    /// Returns the number of input candidates.
    #[must_use]
    pub const fn candidate_count(&self) -> usize {
        self.candidate_count
    }

    /// Returns the number of unique blocked candidate pairs.
    #[must_use]
    pub const fn candidate_pair_count(&self) -> usize {
        self.candidate_pair_count
    }

    /// Returns the number of pair comparisons, including complete-link checks.
    #[must_use]
    pub const fn comparison_count(&self) -> usize {
        self.comparison_count
    }

    /// Returns the number of successful exact-key union operations.
    #[must_use]
    pub const fn exact_merge_count(&self) -> usize {
        self.exact_merge_count
    }

    /// Returns the number of successful fuzzy complete-link union operations.
    #[must_use]
    pub const fn fuzzy_merge_count(&self) -> usize {
        self.fuzzy_merge_count
    }

    /// Returns the number of output clusters, including singletons.
    #[must_use]
    pub const fn cluster_count(&self) -> usize {
        self.cluster_count
    }
}

/// A provenance-preserving group of occurrence keys.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Cluster {
    members: Box<[OccurrenceKey]>,
}

impl Cluster {
    /// Returns sorted source-local occurrence keys.
    #[must_use]
    pub fn members(&self) -> &[OccurrenceKey] {
        &self.members
    }

    /// Returns `true` when the cluster contains more than one occurrence.
    #[must_use]
    pub fn is_duplicate(&self) -> bool {
        self.members.len() > 1
    }
}

/// The complete result of deterministic batch correlation.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ClusterResult {
    clusters: Box<[Cluster]>,
    review_pairs: Box<[Comparison]>,
    warnings: Box<[ClusterWarning]>,
    stats: ClusterStats,
}

impl ClusterResult {
    /// Returns all clusters, including singletons.
    #[must_use]
    pub fn clusters(&self) -> &[Cluster] {
        &self.clusters
    }

    /// Returns plausible pairs that were deliberately not auto-merged.
    #[must_use]
    pub fn review_pairs(&self) -> &[Comparison] {
        &self.review_pairs
    }

    /// Returns non-fatal block warnings.
    #[must_use]
    pub fn warnings(&self) -> &[ClusterWarning] {
        &self.warnings
    }

    /// Returns aggregate run counters.
    #[must_use]
    pub const fn stats(&self) -> ClusterStats {
        self.stats
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ClusterWarning {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        enum WireWarning {
            OversizedBlock {
                kind: BlockKind,
                size: usize,
                limit: usize,
            },
        }

        match <WireWarning as serde::Deserialize>::deserialize(deserializer)? {
            WireWarning::OversizedBlock { kind, size, limit } if limit >= 2 && size > limit => {
                Ok(Self::OversizedBlock { kind, size, limit })
            }
            WireWarning::OversizedBlock { .. } => Err(serde::de::Error::custom(
                "oversized-block warning must have a limit of at least two and size above limit",
            )),
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ClusterStats {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireStats {
            candidate_count: usize,
            candidate_pair_count: usize,
            comparison_count: usize,
            exact_merge_count: usize,
            fuzzy_merge_count: usize,
            cluster_count: usize,
        }

        let wire = <WireStats as serde::Deserialize>::deserialize(deserializer)?;
        let max_pairs =
            (wire.candidate_count as u128) * (wire.candidate_count.saturating_sub(1) as u128) / 2;
        let merge_count = wire.exact_merge_count.checked_add(wire.fuzzy_merge_count);
        let valid = wire.cluster_count <= wire.candidate_count
            && (wire.candidate_pair_count as u128) <= max_pairs
            && wire.comparison_count >= wire.candidate_pair_count
            && (wire.comparison_count as u128) <= max_pairs
            && merge_count == Some(wire.candidate_count.saturating_sub(wire.cluster_count));
        if !valid {
            return Err(serde::de::Error::custom(
                "cluster statistics violate count invariants",
            ));
        }

        Ok(Self {
            candidate_count: wire.candidate_count,
            candidate_pair_count: wire.candidate_pair_count,
            comparison_count: wire.comparison_count,
            exact_merge_count: wire.exact_merge_count,
            fuzzy_merge_count: wire.fuzzy_merge_count,
            cluster_count: wire.cluster_count,
        })
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Cluster {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireCluster {
            members: Vec<OccurrenceKey>,
        }

        let wire = <WireCluster as serde::Deserialize>::deserialize(deserializer)?;
        if wire.members.is_empty() || wire.members.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(serde::de::Error::custom(
                "cluster members must be non-empty, unique, and sorted",
            ));
        }
        Ok(Self {
            members: wire.members.into_boxed_slice(),
        })
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ClusterResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireResult {
            clusters: Vec<Cluster>,
            review_pairs: Vec<Comparison>,
            warnings: Vec<ClusterWarning>,
            stats: ClusterStats,
        }

        let wire = <WireResult as serde::Deserialize>::deserialize(deserializer)?;
        if wire
            .clusters
            .windows(2)
            .any(|pair| pair[0].members()[0] >= pair[1].members()[0])
        {
            return Err(serde::de::Error::custom(
                "clusters must be sorted by their first member",
            ));
        }

        let mut cluster_by_member = BTreeMap::new();
        for (cluster_index, cluster) in wire.clusters.iter().enumerate() {
            for &member in cluster.members() {
                if cluster_by_member.insert(member, cluster_index).is_some() {
                    return Err(serde::de::Error::custom(
                        "an occurrence key may belong to only one cluster",
                    ));
                }
            }
        }
        if cluster_by_member.len() != wire.stats.candidate_count()
            || wire.clusters.len() != wire.stats.cluster_count()
        {
            return Err(serde::de::Error::custom(
                "cluster contents do not match aggregate statistics",
            ));
        }

        let mut previous_pair = None;
        for comparison in &wire.review_pairs {
            let pair = (comparison.left(), comparison.right());
            let left_cluster = cluster_by_member.get(&pair.0);
            let right_cluster = cluster_by_member.get(&pair.1);
            if comparison.decision() != Decision::Review
                || previous_pair.is_some_and(|previous| previous >= pair)
                || left_cluster.is_none()
                || right_cluster.is_none()
                || left_cluster == right_cluster
            {
                return Err(serde::de::Error::custom(
                    "review pairs must be sorted, unique, review decisions between output clusters",
                ));
            }
            previous_pair = Some(pair);
        }

        Ok(Self {
            clusters: wire.clusters.into_boxed_slice(),
            review_pairs: wire.review_pairs.into_boxed_slice(),
            warnings: wire.warnings.into_boxed_slice(),
            stats: wire.stats,
        })
    }
}

/// A batch clustering failure.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum ClusterError {
    /// The input contained the same source occurrence more than once.
    #[error("duplicate occurrence key `{0}` in clustering input")]
    DuplicateOccurrence(OccurrenceKey),
    /// A fuzzy block exceeded the configured maximum and policy required an error.
    #[error("{kind:?} block contains {size} candidates, exceeding limit {limit}")]
    OversizedBlock {
        /// The kind of blocking key.
        kind: BlockKind,
        /// The number of candidates in the block.
        size: usize,
        /// The configured maximum block size.
        limit: usize,
    },
}

impl Deduplicator {
    /// Correlates a batch into deterministic, provenance-preserving clusters.
    ///
    /// Exact keys are unioned first. Fuzzy merges then use complete-link
    /// semantics: every cross-pair between two existing groups must independently
    /// qualify as [`Decision::Duplicate`]. Text-only pairs are not generated in
    /// batch mode, preventing unrestricted quadratic comparison. With the default
    /// cross-source-only policy, exact and fuzzy clusters both contain at most one
    /// occurrence from each source.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError::DuplicateOccurrence`] for repeated occurrence
    /// keys, or [`ClusterError::OversizedBlock`] when configured to fail on a
    /// block larger than [`crate::Config::max_block_size`].
    pub fn cluster(&self, candidates: &[Candidate]) -> Result<ClusterResult, ClusterError> {
        let occurrence_keys = candidates
            .iter()
            .map(|candidate| self.occurrence_key(candidate))
            .collect::<Vec<_>>();
        let mut keyed = occurrence_keys
            .iter()
            .copied()
            .enumerate()
            .map(|(index, key)| (key, index))
            .collect::<Vec<_>>();
        keyed.sort_unstable();
        for pair in keyed.windows(2) {
            if pair[0].0 == pair[1].0 {
                return Err(ClusterError::DuplicateOccurrence(pair[0].0));
            }
        }

        let mut stats = ClusterStats {
            candidate_count: candidates.len(),
            ..ClusterStats::default()
        };
        let mut disjoint = DisjointSet::new(candidates);
        let mut exact_blocks: BTreeMap<CorrelationKey, Vec<usize>> = BTreeMap::new();
        let mut correlation_keys = vec![Vec::new(); candidates.len()];
        for &(_, index) in &keyed {
            let keys = self.correlation_keys(&candidates[index]);
            for &key in &keys {
                exact_blocks.entry(key).or_default().push(index);
            }
            correlation_keys[index] = keys;
        }

        for members in exact_blocks.values() {
            let mut anchors = Vec::new();
            for &member in members {
                let member_root = disjoint.find(member);
                let mut assigned = false;
                for &anchor in &anchors {
                    let anchor_root = disjoint.find(anchor);
                    let member_root = disjoint.find(member_root);
                    if anchor_root == member_root {
                        assigned = true;
                        break;
                    }
                    if self.config.cross_source_only()
                        && !disjoint.sources_disjoint(anchor_root, member_root)
                    {
                        continue;
                    }
                    if disjoint.union(anchor_root, member_root) {
                        stats.exact_merge_count += 1;
                    }
                    assigned = true;
                    break;
                }
                if !assigned {
                    anchors.push(member_root);
                }
            }
        }

        let mut issue_blocks: BTreeMap<BlockKey, Vec<usize>> = BTreeMap::new();
        let mut subject_blocks: BTreeMap<BlockKey, Vec<usize>> = BTreeMap::new();
        for &(_, index) in &keyed {
            let candidate = &candidates[index];
            for issue in candidate.issue_ids() {
                issue_blocks
                    .entry(BlockKey::new(
                        candidate,
                        format!("issue:{}", issue.as_str()),
                    ))
                    .or_default()
                    .push(index);
            }
            for subject in candidate.subject_ids() {
                subject_blocks
                    .entry(BlockKey::new(
                        candidate,
                        format!("{}:{}", subject.kind_tag(), subject.coordinate()),
                    ))
                    .or_default()
                    .push(index);
            }
        }

        let mut warnings = Vec::new();
        let mut candidate_pairs = BTreeSet::new();
        self.add_block_pairs(
            BlockKind::Issue,
            issue_blocks.values(),
            &occurrence_keys,
            &mut candidate_pairs,
            &mut warnings,
        )?;
        self.add_block_pairs(
            BlockKind::Subject,
            subject_blocks.values(),
            &occurrence_keys,
            &mut candidate_pairs,
            &mut warnings,
        )?;
        stats.candidate_pair_count = candidate_pairs.len();

        let index_by_key = keyed.iter().copied().collect::<BTreeMap<_, _>>();
        let mut decision_cache = BTreeMap::new();
        let mut fuzzy_edges = Vec::new();
        let mut review_pairs = BTreeMap::new();
        for &(left_key, right_key) in &candidate_pairs {
            let left = index_by_key[&left_key];
            let right = index_by_key[&right_key];
            stats.comparison_count += 1;
            let comparison = self.compare_prepared(
                PreparedCandidate::cached(
                    &candidates[left],
                    occurrence_keys[left],
                    &correlation_keys[left],
                ),
                PreparedCandidate::cached(
                    &candidates[right],
                    occurrence_keys[right],
                    &correlation_keys[right],
                ),
            );
            decision_cache.insert((left_key, right_key), comparison.decision());
            match comparison.decision() {
                Decision::Duplicate if comparison.method() == MatchMethod::Fuzzy => {
                    fuzzy_edges.push((
                        Reverse(comparison.score().unwrap_or(Score::MAX)),
                        left_key,
                        right_key,
                        left,
                        right,
                    ));
                }
                Decision::Review => {
                    review_pairs.insert((left_key, right_key), comparison);
                }
                Decision::Duplicate | Decision::Distinct | Decision::NotComparable => {}
            }
        }
        fuzzy_edges.sort_unstable_by_key(|edge| (edge.0, edge.1, edge.2));

        for (_, _, _, left, right) in fuzzy_edges {
            let left_root = disjoint.find(left);
            let right_root = disjoint.find(right);
            if left_root == right_root {
                continue;
            }
            let left_members = disjoint.members(left_root).to_vec();
            let right_members = disjoint.members(right_root).to_vec();
            let mut complete_link = true;
            for &left_member in &left_members {
                for &right_member in &right_members {
                    let left_key = occurrence_keys[left_member];
                    let right_key = occurrence_keys[right_member];
                    let pair = if left_key <= right_key {
                        (left_key, right_key)
                    } else {
                        (right_key, left_key)
                    };
                    let decision = if let Some(&decision) = decision_cache.get(&pair) {
                        decision
                    } else {
                        stats.comparison_count += 1;
                        let comparison = self.compare_prepared(
                            PreparedCandidate::cached(
                                &candidates[left_member],
                                occurrence_keys[left_member],
                                &correlation_keys[left_member],
                            ),
                            PreparedCandidate::cached(
                                &candidates[right_member],
                                occurrence_keys[right_member],
                                &correlation_keys[right_member],
                            ),
                        );
                        let decision = comparison.decision();
                        decision_cache.insert(pair, decision);
                        if decision == Decision::Review {
                            review_pairs.insert(pair, comparison);
                        }
                        decision
                    };
                    if decision != Decision::Duplicate {
                        complete_link = false;
                    }
                }
            }
            if complete_link && disjoint.union(left_root, right_root) {
                stats.fuzzy_merge_count += 1;
            }
        }

        review_pairs.retain(|&(left_key, right_key), _| {
            let left = index_by_key[&left_key];
            let right = index_by_key[&right_key];
            disjoint.find(left) != disjoint.find(right)
        });

        let mut grouped: BTreeMap<usize, Vec<OccurrenceKey>> = BTreeMap::new();
        for &(key, index) in &keyed {
            let root = disjoint.find(index);
            grouped.entry(root).or_default().push(key);
        }
        let mut clusters = grouped
            .into_values()
            .map(|mut members| {
                members.sort_unstable();
                Cluster {
                    members: members.into_boxed_slice(),
                }
            })
            .collect::<Vec<_>>();
        clusters.sort_unstable_by_key(|cluster| cluster.members[0]);
        stats.cluster_count = clusters.len();

        Ok(ClusterResult {
            clusters: clusters.into_boxed_slice(),
            review_pairs: review_pairs
                .into_values()
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            warnings: warnings.into_boxed_slice(),
            stats,
        })
    }

    fn add_block_pairs<'a>(
        &self,
        kind: BlockKind,
        blocks: impl Iterator<Item = &'a Vec<usize>>,
        occurrence_keys: &[OccurrenceKey],
        pairs: &mut BTreeSet<(OccurrenceKey, OccurrenceKey)>,
        warnings: &mut Vec<ClusterWarning>,
    ) -> Result<(), ClusterError> {
        for members in blocks {
            if members.len() < 2 {
                continue;
            }
            if members.len() > self.config.max_block_size() {
                match self.config.oversized_block_policy() {
                    OversizedBlockPolicy::ExactOnlyAndWarn => {
                        warnings.push(ClusterWarning::OversizedBlock {
                            kind,
                            size: members.len(),
                            limit: self.config.max_block_size(),
                        });
                        continue;
                    }
                    OversizedBlockPolicy::Error => {
                        return Err(ClusterError::OversizedBlock {
                            kind,
                            size: members.len(),
                            limit: self.config.max_block_size(),
                        });
                    }
                }
            }
            for left_offset in 0..members.len() {
                for right_offset in (left_offset + 1)..members.len() {
                    let left = occurrence_keys[members[left_offset]];
                    let right = occurrence_keys[members[right_offset]];
                    pairs.insert(if left <= right {
                        (left, right)
                    } else {
                        (right, left)
                    });
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct BlockKey {
    partition: String,
    kind: FindingKind,
    value: String,
}

impl BlockKey {
    fn new(candidate: &Candidate, value: String) -> Self {
        Self {
            partition: candidate.partition().to_owned(),
            kind: candidate.kind().clone(),
            value,
        }
    }
}

struct DisjointSet {
    parent: Vec<usize>,
    members: Vec<Vec<usize>>,
    sources: Vec<BTreeSet<String>>,
}

impl DisjointSet {
    fn new(candidates: &[Candidate]) -> Self {
        let size = candidates.len();
        Self {
            parent: (0..size).collect(),
            members: (0..size).map(|index| vec![index]).collect(),
            sources: candidates
                .iter()
                .map(|candidate| BTreeSet::from([candidate.origin().source().to_owned()]))
                .collect(),
        }
    }

    fn find(&mut self, index: usize) -> usize {
        if self.parent[index] != index {
            self.parent[index] = self.find(self.parent[index]);
        }
        self.parent[index]
    }

    fn members(&self, root: usize) -> &[usize] {
        &self.members[root]
    }

    fn sources_disjoint(&self, left_root: usize, right_root: usize) -> bool {
        self.sources[left_root].is_disjoint(&self.sources[right_root])
    }

    fn union(&mut self, left: usize, right: usize) -> bool {
        let mut left_root = self.find(left);
        let mut right_root = self.find(right);
        if left_root == right_root {
            return false;
        }
        if self.members[left_root].len() < self.members[right_root].len()
            || (self.members[left_root].len() == self.members[right_root].len()
                && right_root < left_root)
        {
            std::mem::swap(&mut left_root, &mut right_root);
        }
        self.parent[right_root] = left_root;
        let mut merged = std::mem::take(&mut self.members[right_root]);
        self.members[left_root].append(&mut merged);
        self.members[left_root].sort_unstable();
        let merged_sources = std::mem::take(&mut self.sources[right_root]);
        self.sources[left_root].extend(merged_sources);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Candidate, Config};

    fn named(source: &str, id: &str, name: &str) -> Candidate {
        Candidate::builder(source, id)
            .partition("global")
            .issue("CVE-2024-1")
            .subject_name(name)
            .build()
            .unwrap()
    }

    #[test]
    fn cluster_retains_singletons() {
        let candidates = [
            Candidate::builder("one", "1")
                .partition("a")
                .issue("CVE-2024-1")
                .build()
                .unwrap(),
            Candidate::builder("two", "2")
                .partition("b")
                .issue("CVE-2024-1")
                .build()
                .unwrap(),
        ];

        let result = Deduplicator::default().cluster(&candidates).unwrap();
        assert_eq!(result.clusters().len(), 2);
    }

    #[test]
    fn cluster_rejects_duplicate_occurrence_keys() {
        let candidate = named("one", "1", "package");
        let error = Deduplicator::default()
            .cluster(&[candidate.clone(), candidate])
            .unwrap_err();
        assert!(matches!(error, ClusterError::DuplicateOccurrence(_)));
    }

    #[test]
    fn cluster_does_not_generate_unblocked_text_only_pairs() {
        let candidates = [
            Candidate::builder("one", "1")
                .partition("global")
                .title("Identical finding")
                .build()
                .unwrap(),
            Candidate::builder("two", "2")
                .partition("global")
                .title("Identical finding")
                .build()
                .unwrap(),
        ];

        let result = Deduplicator::default().cluster(&candidates).unwrap();
        assert_eq!(result.stats().candidate_pair_count(), 0);
    }

    #[test]
    fn oversized_fuzzy_block_warns_and_keeps_exact_only() {
        let engine = Deduplicator::new(Config::builder().max_block_size(2).build().unwrap());
        let candidates = [
            named("one", "1", "alpha"),
            named("two", "2", "beta"),
            named("three", "3", "gamma"),
        ];

        let result = engine.cluster(&candidates).unwrap();
        assert_eq!(result.stats().candidate_pair_count(), 0);
        assert_eq!(
            result.warnings(),
            [ClusterWarning::OversizedBlock {
                kind: BlockKind::Issue,
                size: 3,
                limit: 2,
            }]
        );
    }

    #[test]
    fn oversized_fuzzy_block_can_be_an_error() {
        let engine = Deduplicator::new(
            Config::builder()
                .max_block_size(2)
                .oversized_block_policy(OversizedBlockPolicy::Error)
                .build()
                .unwrap(),
        );
        let candidates = [
            named("one", "1", "alpha"),
            named("two", "2", "beta"),
            named("three", "3", "gamma"),
        ];

        assert_eq!(
            engine.cluster(&candidates).unwrap_err(),
            ClusterError::OversizedBlock {
                kind: BlockKind::Issue,
                size: 3,
                limit: 2,
            }
        );
    }

    #[test]
    fn fuzzy_clustering_uses_complete_link_not_connected_components() {
        let engine = Deduplicator::new(
            Config::builder()
                .duplicate_threshold(7_000)
                .review_threshold(6_000)
                .subject_similarity_threshold(7_000)
                .build()
                .unwrap(),
        );
        let candidates = [
            named("one", "1", "alpha beta"),
            named("two", "2", "alpha beta gamma"),
            named("three", "3", "beta gamma"),
        ];

        let result = engine.cluster(&candidates).unwrap();
        let largest = result
            .clusters()
            .iter()
            .map(|cluster| cluster.members().len())
            .max();
        assert_eq!(largest, Some(2));
    }

    #[test]
    fn clustering_is_input_order_invariant() {
        let engine = Deduplicator::default();
        let left = named("one", "1", "xz utils");
        let right = named("two", "2", "xz-utils");
        let first = engine.cluster(&[left.clone(), right.clone()]).unwrap();
        let second = engine.cluster(&[right, left]).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn exact_clustering_does_not_bridge_same_source_occurrences() {
        let candidates = [
            Candidate::builder("one", "1")
                .partition("global")
                .issue("CVE-2024-1")
                .purl("pkg:generic/widget@1")
                .unwrap()
                .build()
                .unwrap(),
            Candidate::builder("one", "2")
                .partition("global")
                .issue("CVE-2024-1")
                .purl("pkg:generic/widget@1")
                .unwrap()
                .build()
                .unwrap(),
            Candidate::builder("two", "3")
                .partition("global")
                .issue("CVE-2024-1")
                .purl("pkg:generic/widget@1")
                .unwrap()
                .build()
                .unwrap(),
        ];

        let engine = Deduplicator::default();
        let result = engine.cluster(&candidates).unwrap();
        let reordered = engine
            .cluster(&[
                candidates[2].clone(),
                candidates[0].clone(),
                candidates[1].clone(),
            ])
            .unwrap();
        assert_eq!(result.clusters().len(), 2);
        assert_eq!(
            result
                .clusters()
                .iter()
                .map(|cluster| cluster.members().len())
                .max(),
            Some(2)
        );
        assert_eq!(result, reordered);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trips_cluster_results_and_rejects_empty_clusters() {
        let result = Deduplicator::default()
            .cluster(&[named("one", "1", "xz utils"), named("two", "2", "xz-utils")])
            .unwrap();
        let mut json = serde_json::to_value(&result).unwrap();

        let decoded: ClusterResult = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(decoded, result);

        json["clusters"][0]["members"] = serde_json::json!([]);
        assert!(serde_json::from_value::<ClusterResult>(json).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_rejects_cluster_statistics_that_do_not_match_contents() {
        let result = Deduplicator::default()
            .cluster(&[named("one", "1", "package")])
            .unwrap();
        let mut json = serde_json::to_value(result).unwrap();

        json["stats"]["candidate_count"] = serde_json::json!(2);
        assert!(serde_json::from_value::<ClusterResult>(json).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_rejects_unknown_fields() {
        let result = Deduplicator::default()
            .cluster(&[named("one", "1", "package")])
            .unwrap();

        let mut result_json = serde_json::to_value(&result).unwrap();
        result_json["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ClusterResult>(result_json).is_err());

        let mut cluster_json = serde_json::to_value(&result.clusters()[0]).unwrap();
        cluster_json["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Cluster>(cluster_json).is_err());

        let mut stats_json = serde_json::to_value(result.stats()).unwrap();
        stats_json["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ClusterStats>(stats_json).is_err());

        let warning = ClusterWarning::OversizedBlock {
            kind: BlockKind::Issue,
            size: 3,
            limit: 2,
        };
        let mut warning_json = serde_json::to_value(warning).unwrap();
        warning_json["OversizedBlock"]["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ClusterWarning>(warning_json).is_err());
    }

    #[test]
    fn oversized_subject_block_warns_and_keeps_exact_only() {
        let engine = Deduplicator::new(Config::builder().max_block_size(2).build().unwrap());
        let candidates = [
            Candidate::builder("one", "1")
                .partition("global")
                .purl("pkg:generic/widget@1.0")
                .unwrap()
                .build()
                .unwrap(),
            Candidate::builder("two", "2")
                .partition("global")
                .purl("pkg:generic/widget@2.0")
                .unwrap()
                .build()
                .unwrap(),
            Candidate::builder("three", "3")
                .partition("global")
                .purl("pkg:generic/widget@3.0")
                .unwrap()
                .build()
                .unwrap(),
        ];

        let result = engine.cluster(&candidates).unwrap();
        assert_eq!(result.stats().candidate_pair_count(), 0);
        assert_eq!(
            result.warnings(),
            [ClusterWarning::OversizedBlock {
                kind: BlockKind::Subject,
                size: 3,
                limit: 2,
            }]
        );
    }

    #[test]
    fn cluster_reports_review_pairs_for_plausible_but_unmerged_matches() {
        let engine = Deduplicator::default();
        let candidates = [
            named("one", "1", "acme widget"),
            named("two", "2", "acme widget"),
        ];

        let result = engine.cluster(&candidates).unwrap();
        assert_eq!(result.clusters().len(), 2);
        assert_eq!(result.review_pairs().len(), 1);
        assert_eq!(result.review_pairs()[0].decision(), Decision::Review);
    }

    #[test]
    fn cluster_stats_reports_expected_counts_for_a_simple_exact_merge() {
        let candidates = [
            Candidate::builder("one", "1")
                .partition("global")
                .issue("CVE-2024-1")
                .purl("pkg:generic/widget@1.0")
                .unwrap()
                .build()
                .unwrap(),
            Candidate::builder("two", "2")
                .partition("global")
                .issue("CVE-2024-1")
                .purl("pkg:generic/widget@1.0")
                .unwrap()
                .build()
                .unwrap(),
        ];

        let stats = Deduplicator::default().cluster(&candidates).unwrap().stats();
        assert_eq!(stats.candidate_count(), 2);
        assert_eq!(stats.candidate_pair_count(), 1);
        assert_eq!(stats.comparison_count(), 1);
        assert_eq!(stats.exact_merge_count(), 1);
        assert_eq!(stats.fuzzy_merge_count(), 0);
        assert_eq!(stats.cluster_count(), 1);
    }
}
