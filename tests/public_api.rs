use custos_dedup::{
    Candidate, ClusterError, Config, Decision, Deduplicator, MatchMethod, NormalizedCpe,
    NormalizedPurl, OccurrenceKey, SignalField, SignalKind,
};

fn purl_finding(
    source: &str,
    native_id: &str,
    partition: &str,
    issue: &str,
    purl: &str,
) -> Candidate {
    Candidate::builder(source, native_id)
        .partition(partition)
        .issue(issue)
        .purl(purl)
        .unwrap()
        .title("Remote code execution in widget")
        .build()
        .unwrap()
}

#[test]
fn canonical_purls_produce_exact_cross_source_correlation() {
    let left = purl_finding(
        "scanner-a",
        "17",
        "image:sha256:abc",
        "CVE-2025-1234",
        "pkg:GITHUB/Acme/Widget@1.0?Z=two&a=one",
    );
    let right = purl_finding(
        "scanner-b",
        "91",
        "image:sha256:abc",
        "cve-2025-1234",
        "pkg:github/acme/widget@1.0?a=one&z=two",
    );

    let comparison = Deduplicator::default().compare(&left, &right);
    assert_eq!(comparison.decision(), Decision::Duplicate);
    assert_eq!(comparison.method(), MatchMethod::ExactCorrelation);
}

#[test]
fn legacy_and_formatted_cpe_bindings_are_equivalent() {
    let legacy = NormalizedCpe::parse("cpe:/a:acme:widget:1.0").unwrap();
    let formatted = NormalizedCpe::parse("cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*").unwrap();

    assert_eq!(legacy, formatted);
    assert_eq!(legacy.as_str(), formatted.as_str());
}

#[test]
fn hard_partitions_override_identical_evidence() {
    let left = purl_finding(
        "scanner-a",
        "17",
        "tenant:a",
        "CVE-2025-1234",
        "pkg:generic/acme/widget@1.0",
    );
    let right = purl_finding(
        "scanner-b",
        "91",
        "tenant:b",
        "CVE-2025-1234",
        "pkg:generic/acme/widget@1.0",
    );

    assert_eq!(
        Deduplicator::default().compare(&left, &right).decision(),
        Decision::NotComparable
    );
}

#[test]
fn conflicting_structured_subjects_are_distinct_even_with_shared_text() {
    let left = purl_finding(
        "scanner-a",
        "17",
        "repository:acme/api",
        "CVE-2025-1234",
        "pkg:cargo/widget@1.0",
    );
    let right = purl_finding(
        "scanner-b",
        "91",
        "repository:acme/api",
        "CVE-2025-1234",
        "pkg:cargo/different-widget@1.0",
    );

    assert_eq!(
        Deduplicator::default().compare(&left, &right).decision(),
        Decision::Distinct
    );
}

#[test]
fn purl_and_cpe_do_not_auto_merge_without_a_crosswalk() {
    let purl = purl_finding(
        "scanner-a",
        "17",
        "asset:one",
        "CVE-2025-1234",
        "pkg:generic/acme/widget@1.0",
    );
    let cpe = Candidate::builder("scanner-b", "91")
        .partition("asset:one")
        .issue("CVE-2025-1234")
        .cpe("cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*")
        .unwrap()
        .title("Remote code execution in widget")
        .build()
        .unwrap();

    let comparison = Deduplicator::default().compare(&purl, &cpe);
    assert_eq!(comparison.decision(), Decision::Review);
    assert!(comparison.signals().iter().any(|signal| {
        signal.field() == SignalField::Subject && signal.kind() == SignalKind::Incomparable
    }));
}

#[test]
fn issue_only_exact_policy_reports_missing_subject_evidence() {
    let engine = Deduplicator::new(Config::builder().issue_only_exact(true).build().unwrap());
    let left = Candidate::builder("scanner-a", "17")
        .partition("asset:one")
        .issue("CVE-2025-1234")
        .build()
        .unwrap();
    let right = Candidate::builder("scanner-b", "91")
        .partition("asset:one")
        .issue("CVE-2025-1234")
        .build()
        .unwrap();

    let comparison = engine.compare(&left, &right);
    assert_eq!(comparison.decision(), Decision::Duplicate);
    assert!(comparison.signals().iter().any(|signal| {
        signal.field() == SignalField::Subject && signal.kind() == SignalKind::Missing
    }));
}

#[test]
fn normalization_is_idempotent_at_the_public_api() {
    let purl = NormalizedPurl::parse("pkg:PYPI/Django_package@5.0").unwrap();
    let reparsed = NormalizedPurl::parse(purl.as_str()).unwrap();
    assert_eq!(purl, reparsed);
}

#[cfg(feature = "serde")]
#[test]
fn candidate_json_round_trip_retains_validated_state() {
    let candidate = purl_finding(
        "scanner-a",
        "17",
        "asset:one",
        "CVE-2025-1234",
        "pkg:generic/acme/widget@1.0",
    );

    let json = serde_json::to_string(&candidate).unwrap();
    let decoded: Candidate = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, candidate);
}

#[test]
fn cluster_correlates_cross_source_duplicates_and_tracks_stats() {
    let left = purl_finding(
        "scanner-a",
        "17",
        "repository:acme/api",
        "CVE-2024-3094",
        "pkg:generic/acme/widget@1.0",
    );
    let right = purl_finding(
        "scanner-b",
        "91",
        "repository:acme/api",
        "cve-2024-3094",
        "pkg:generic/acme/widget@1.0",
    );

    let result = Deduplicator::default().cluster(&[left, right]).unwrap();

    assert_eq!(result.clusters().len(), 1);
    assert!(result.clusters()[0].is_duplicate());
    assert_eq!(result.clusters()[0].members().len(), 2);
    assert!(result.review_pairs().is_empty());
    assert!(result.warnings().is_empty());
    assert_eq!(result.stats().candidate_count(), 2);
    assert_eq!(result.stats().cluster_count(), 1);
    assert_eq!(result.stats().exact_merge_count(), 1);
}

#[test]
fn cluster_rejects_repeated_occurrences_in_input() {
    let candidate = purl_finding(
        "scanner-a",
        "17",
        "repository:acme/api",
        "CVE-2024-3094",
        "pkg:generic/acme/widget@1.0",
    );
    let error = Deduplicator::default()
        .cluster(&[candidate.clone(), candidate])
        .unwrap_err();
    assert!(matches!(error, ClusterError::DuplicateOccurrence(_)));
}

#[test]
fn occurrence_key_string_round_trip_and_rejects_invalid_prefix() {
    let candidate = purl_finding(
        "scanner-a",
        "17",
        "repository:acme/api",
        "CVE-2024-3094",
        "pkg:generic/acme/widget@1.0",
    );
    let key = Deduplicator::default().occurrence_key(&candidate);
    let round_tripped: OccurrenceKey = key.to_string().parse().unwrap();
    assert_eq!(round_tripped, key);
    assert!("corr:v1:deadbeef".parse::<OccurrenceKey>().is_err());
}
