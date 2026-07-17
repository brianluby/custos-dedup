use custos_dedup::{Candidate, Decision, Deduplicator, Score};

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

    println!(
        "decision={:?} method={:?} score={:?}",
        comparison.decision(),
        comparison.method(),
        comparison.score().map(Score::get)
    );
    for signal in comparison.signals() {
        println!(
            "field={:?} relationship={:?} score={:?}",
            signal.field(),
            signal.kind(),
            signal.score().map(Score::get)
        );
    }

    assert_eq!(comparison.decision(), Decision::Duplicate);

    let candidates = [first, second];
    let result = engine.cluster(&candidates)?;
    assert_eq!(result.clusters().len(), 1);
    assert!(result.clusters()[0].is_duplicate());

    Ok(())
}
