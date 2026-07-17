use crate::Score;

/// How clustering handles an oversized fuzzy candidate block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum OversizedBlockPolicy {
    /// Keep exact-key matches, skip fuzzy pairs, and return a warning.
    ExactOnlyAndWarn,
    /// Stop clustering with an error.
    Error,
}

/// Validated comparison and clustering policy.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Config {
    duplicate_threshold: Score,
    review_threshold: Score,
    subject_similarity_threshold: Score,
    cross_source_only: bool,
    issue_only_exact: bool,
    max_block_size: usize,
    oversized_block_policy: OversizedBlockPolicy,
}

impl Config {
    /// Starts a configuration builder with conservative defaults.
    #[must_use]
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }

    /// Returns the minimum score eligible for an automatic duplicate decision.
    #[must_use]
    pub const fn duplicate_threshold(&self) -> Score {
        self.duplicate_threshold
    }

    /// Returns the minimum score surfaced for human review.
    #[must_use]
    pub const fn review_threshold(&self) -> Score {
        self.review_threshold
    }

    /// Returns the fuzzy subject-name threshold used as a strong anchor.
    #[must_use]
    pub const fn subject_similarity_threshold(&self) -> Score {
        self.subject_similarity_threshold
    }

    /// Returns whether different occurrences from one source are excluded.
    #[must_use]
    pub const fn cross_source_only(&self) -> bool {
        self.cross_source_only
    }

    /// Returns whether a shared issue without a subject creates an exact key.
    #[must_use]
    pub const fn issue_only_exact(&self) -> bool {
        self.issue_only_exact
    }

    /// Returns the largest block eligible for fuzzy pair generation.
    #[must_use]
    pub const fn max_block_size(&self) -> usize {
        self.max_block_size
    }

    /// Returns the oversized-block behavior.
    #[must_use]
    pub const fn oversized_block_policy(&self) -> OversizedBlockPolicy {
        self.oversized_block_policy
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            duplicate_threshold: Score::from_valid(8_500),
            review_threshold: Score::from_valid(6_500),
            subject_similarity_threshold: Score::from_valid(9_000),
            cross_source_only: true,
            issue_only_exact: false,
            max_block_size: 1_000,
            oversized_block_policy: OversizedBlockPolicy::ExactOnlyAndWarn,
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Config {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireConfig {
            duplicate_threshold: u16,
            review_threshold: u16,
            subject_similarity_threshold: u16,
            cross_source_only: bool,
            issue_only_exact: bool,
            max_block_size: usize,
            oversized_block_policy: OversizedBlockPolicy,
        }

        let wire = <WireConfig as serde::Deserialize>::deserialize(deserializer)?;
        Config::builder()
            .duplicate_threshold(wire.duplicate_threshold)
            .review_threshold(wire.review_threshold)
            .subject_similarity_threshold(wire.subject_similarity_threshold)
            .cross_source_only(wire.cross_source_only)
            .issue_only_exact(wire.issue_only_exact)
            .max_block_size(wire.max_block_size)
            .oversized_block_policy(wire.oversized_block_policy)
            .build()
            .map_err(serde::de::Error::custom)
    }
}

/// Builds a validated [`Config`].
#[derive(Clone, Debug)]
pub struct ConfigBuilder {
    duplicate_threshold: u16,
    review_threshold: u16,
    subject_similarity_threshold: u16,
    cross_source_only: bool,
    issue_only_exact: bool,
    max_block_size: usize,
    oversized_block_policy: OversizedBlockPolicy,
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self {
            duplicate_threshold: 8_500,
            review_threshold: 6_500,
            subject_similarity_threshold: 9_000,
            cross_source_only: true,
            issue_only_exact: false,
            max_block_size: 1_000,
            oversized_block_policy: OversizedBlockPolicy::ExactOnlyAndWarn,
        }
    }
}

impl ConfigBuilder {
    /// Sets the automatic duplicate threshold in basis points (`0..=10_000`).
    #[must_use]
    pub const fn duplicate_threshold(mut self, value: u16) -> Self {
        self.duplicate_threshold = value;
        self
    }

    /// Sets the review threshold in basis points (`0..=10_000`).
    #[must_use]
    pub const fn review_threshold(mut self, value: u16) -> Self {
        self.review_threshold = value;
        self
    }

    /// Sets the fuzzy subject-name anchor threshold in basis points.
    #[must_use]
    pub const fn subject_similarity_threshold(mut self, value: u16) -> Self {
        self.subject_similarity_threshold = value;
        self
    }

    /// Restricts comparison of different occurrences to different sources.
    #[must_use]
    pub const fn cross_source_only(mut self, value: bool) -> Self {
        self.cross_source_only = value;
        self
    }

    /// Enables exact issue-only keys when neither candidate has a subject.
    #[must_use]
    pub const fn issue_only_exact(mut self, value: bool) -> Self {
        self.issue_only_exact = value;
        self
    }

    /// Sets the largest fuzzy candidate block.
    #[must_use]
    pub const fn max_block_size(mut self, value: usize) -> Self {
        self.max_block_size = value;
        self
    }

    /// Sets the oversized-block behavior.
    #[must_use]
    pub const fn oversized_block_policy(mut self, value: OversizedBlockPolicy) -> Self {
        self.oversized_block_policy = value;
        self
    }

    /// Validates and builds the configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for scores above 10,000, a review threshold
    /// above the duplicate threshold, or a block limit smaller than two.
    pub fn build(self) -> Result<Config, ConfigError> {
        let duplicate_threshold =
            Score::new(self.duplicate_threshold).map_err(|_| ConfigError::ScoreOutOfRange {
                field: "duplicate_threshold",
                value: self.duplicate_threshold,
            })?;
        let review_threshold =
            Score::new(self.review_threshold).map_err(|_| ConfigError::ScoreOutOfRange {
                field: "review_threshold",
                value: self.review_threshold,
            })?;
        let subject_similarity_threshold =
            Score::new(self.subject_similarity_threshold).map_err(|_| {
                ConfigError::ScoreOutOfRange {
                    field: "subject_similarity_threshold",
                    value: self.subject_similarity_threshold,
                }
            })?;
        if review_threshold > duplicate_threshold {
            return Err(ConfigError::ThresholdOrder);
        }
        if self.max_block_size < 2 {
            return Err(ConfigError::BlockSize(self.max_block_size));
        }

        Ok(Config {
            duplicate_threshold,
            review_threshold,
            subject_similarity_threshold,
            cross_source_only: self.cross_source_only,
            issue_only_exact: self.issue_only_exact,
            max_block_size: self.max_block_size,
            oversized_block_policy: self.oversized_block_policy,
        })
    }
}

/// An invalid deduplication policy.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// A score exceeded 10,000 basis points.
    #[error("configuration field `{field}` must be at most 10000, got {value}")]
    ScoreOutOfRange {
        /// The invalid field name.
        field: &'static str,
        /// The invalid value.
        value: u16,
    },
    /// The review threshold exceeded the duplicate threshold.
    #[error("review threshold must not exceed duplicate threshold")]
    ThresholdOrder,
    /// The maximum fuzzy block size was too small.
    #[error("maximum block size must be at least 2, got {0}")]
    BlockSize(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_conservative() {
        let config = Config::default();
        assert_eq!(
            (
                config.duplicate_threshold().get(),
                config.review_threshold().get(),
                config.cross_source_only(),
                config.issue_only_exact()
            ),
            (8_500, 6_500, true, false)
        );
    }

    #[test]
    fn build_rejects_reversed_thresholds() {
        let error = Config::builder()
            .duplicate_threshold(8_000)
            .review_threshold(8_001)
            .build()
            .unwrap_err();
        assert_eq!(error, ConfigError::ThresholdOrder);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_rejects_invalid_policy() {
        let json = r#"{
            "duplicate_threshold":8000,
            "review_threshold":9000,
            "subject_similarity_threshold":9000,
            "cross_source_only":true,
            "issue_only_exact":false,
            "max_block_size":1000,
            "oversized_block_policy":"exact_only_and_warn"
        }"#;

        assert!(serde_json::from_str::<Config>(json).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_rejects_unknown_fields() {
        let mut json = serde_json::to_value(Config::default()).unwrap();
        json["duplicate_threshhold"] = serde_json::json!(9_000);

        assert!(serde_json::from_value::<Config>(json).is_err());
    }
}
