use std::fs;
use std::path::Path;
use superbrave::config::{Config, ListConfig, ListFormat};

/// Builds a Config pointing at a fixture list already present on disk.
fn fixture_config(dir: &Path) -> Config {
    let cache = dir.join("cache");
    fs::create_dir_all(&cache).unwrap();
    fs::write(
        cache.join("fixture.txt"),
        include_str!("fixtures/sample.txt"),
    )
    .unwrap();
    Config {
        lists: vec![ListConfig {
            name: "fixture".into(),
            url: "https://example.test/fixture.txt".into(),
            format: ListFormat::Standard,
            enabled: true,
            license: Some("CC0-1.0".into()),
            attribution: None,
            rewritable: false,
        }],
        ..Config::default()
    }
}

fn build(dir: &Path) -> String {
    let cfg = fixture_config(dir);
    let report = superbrave::pipeline::run(
        &cfg,
        &dir.join("cache"),
        dir,
        superbrave::pipeline::Options::default(),
    )
    .unwrap();
    assert!(report.outcome.emitted_network > 0, "expected network rules");
    let list = fs::read_to_string(dir.join("SuperBrave.txt")).unwrap();
    assert!(list.starts_with("[Adblock Plus 2.0]"), "missing ABP header");
    list
}

fn tempdir(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("superbrave-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn unsupported_and_directive_lines_are_dropped() {
    let dir = tempdir("drop");
    let list = build(&dir);
    for gone in ["!#if", "!#endif", "$popup", "##.ad-slot\n#@#"] {
        assert!(
            !list.contains(gone),
            "expected {gone:?} to be dropped:\n{list}"
        );
    }
}

#[test]
fn supported_network_and_cosmetic_rules_survive() {
    let dir = tempdir("keep");
    let list = build(&dir);
    for kept in [
        "||ads.tracker.test^",
        "/banner.gif$image",
        "/pixel.png$domain=shop.test",
        "@@||cdn.tracker.test^",
    ] {
        assert!(list.contains(kept), "expected {kept:?} in output");
    }
}

#[test]
fn caret_path_rule_is_repaired_and_to_rule_is_not() {
    let dir = tempdir("repair");
    let list = build(&dir);
    // The `^/` form can never match; the repair fixes it.
    assert!(
        list.contains("||a.com/never-matches"),
        "caret repair missing:\n{list}"
    );
    // `$to=` suppresses blocking, so it must be left alone rather than stripped.
    assert!(
        list.contains("/only/$to=tracker.test"),
        "to= rule was altered:\n{list}"
    );
}

#[test]
fn report_is_written() {
    let dir = tempdir("report");
    build(&dir);
    let report = fs::read_to_string(dir.join("report.json")).unwrap();
    assert!(report.contains("fixture"));
    assert!(report.contains("by_reason"));
}

#[test]
fn analyze_writes_nothing() {
    let dir = tempdir("analyze");
    let cfg = fixture_config(&dir);
    superbrave::pipeline::run(
        &cfg,
        &dir.join("cache"),
        &dir,
        superbrave::pipeline::Options {
            verify: true,
            emit: false,
            engine_blob: false,
        },
    )
    .unwrap();
    assert!(
        !dir.join("SuperBrave.txt").exists(),
        "analyze must not emit"
    );
}

#[test]
fn self_consistency_ratio_is_reported() {
    let dir = tempdir("ratio");
    let cfg = fixture_config(&dir);
    let report = superbrave::pipeline::run(
        &cfg,
        &dir.join("cache"),
        &dir,
        superbrave::pipeline::Options::default(),
    )
    .unwrap();
    assert_eq!(report.outcome.regression_gained, 0);
    assert!(report.summary().contains("vs upstream"));
    assert!(report.outcome.verified_sampled > 0);
    assert_eq!(report.outcome.self_consistency, 1.0);
    assert!(report.summary().contains("self-consistency"));
}

#[test]
fn equivalent_rewrites_are_applied_and_reported() {
    let dir = tempdir("optimise");
    let list = build(&dir);
    let cfg = fixture_config(&dir);
    let report = superbrave::pipeline::run(
        &cfg,
        &dir.join("cache"),
        &dir,
        superbrave::pipeline::Options::default(),
    )
    .unwrap();

    // `$3p` and `$third-party` are the same filter, so only one copy ships.
    assert!(list.contains("||alias.tracker.test^$third-party"));
    assert_eq!(
        list.matches("||alias.tracker.test^").count(),
        1,
        "alias duplicate survived:\n{list}"
    );
    // A trailing wildcard is implied by a prefix match.
    assert!(list.contains("||wild.tracker.test/banners/"), "{list}");
    // A `$badfilter` pair cannot affect any request, so both halves go.
    assert!(!list.contains("disabled.tracker.test"), "{list}");
    // Two rules differing only in document scope become one.
    assert!(
        list.contains("||scope.tracker.test^$domain=shop.test|forum.test"),
        "{list}"
    );

    assert!(report.outcome.optimised_rewritten > 0);
    assert!(
        report
            .outcome
            .optimise_stages
            .iter()
            .all(|s| s.accepted && s.diffs == 0),
        "a stage was not proven equivalent: {:?}",
        report.outcome.optimise_stages
    );
    assert!(report.summary().contains("equivalent rewrites"));
}

#[test]
fn optimisation_never_costs_upstream_coverage() {
    // The pipeline refuses to emit when a request blocked upstream is no longer
    // blocked, so reaching a report at all is the coverage assertion.
    let dir = tempdir("optimise-regression");
    let cfg = fixture_config(&dir);
    let report = superbrave::pipeline::run(
        &cfg,
        &dir.join("cache"),
        &dir,
        superbrave::pipeline::Options::default(),
    )
    .unwrap();
    assert!(report.outcome.optimise_stages.iter().all(|s| s.accepted));
    assert_eq!(report.outcome.self_consistency, 1.0);
}
