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
    let report = superbrave::pipeline::run(&cfg, &dir.join("cache"), dir, None).unwrap();
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
