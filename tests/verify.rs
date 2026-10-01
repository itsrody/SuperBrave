use superbrave::verify::{compile, self_consistency, Check};

#[test]
fn self_consistency_flags_rules_that_cannot_match() {
    let net = "||ads.example.test^\n||broken.example.test^/path\n/banner.gif$image\n";
    let c = compile(net, "");
    let sc = self_consistency(&c.engine, net, 100);
    assert!(sc.sampled >= 2, "expected rules to be probed, got {sc:?}");
    // The `^/` rule is unsatisfiable and must be the one reported.
    assert!(
        sc.misses
            .iter()
            .any(|m| m.starts_with("||broken.example.test")),
        "{sc:?}"
    );
}

#[test]
fn unscoped_and_scoped_rules_both_pass() {
    let net = "||ads.example.test^\n||cdn.example.test^$script,third-party\n/pixel.png$domain=shop.test\n";
    let c = compile(net, "");
    let sc = self_consistency(&c.engine, net, 100);
    assert_eq!(sc.misses, Vec::<String>::new(), "{sc:?}");
}

#[test]
fn check_reports_blocking_state() {
    let c = compile("||ads.example.test^\n", "");
    assert!(
        Check::run(
            &c.engine,
            "https://ads.example.test/x",
            "https://s.test/",
            "xhr"
        )
        .unwrap()
        .blocked
    );
    assert!(
        !Check::run(&c.engine, "https://safe.test/x", "https://s.test/", "xhr")
            .unwrap()
            .blocked
    );
}

#[test]
fn regression_detects_a_lost_block() {
    // Upstream blocks the host; the "built" list does not contain the rule.
    let up = "||tracker.example.test^\n";
    let built = compile("", "");
    let r = superbrave::verify::regression_vs_upstream(up, &built);
    // The corpus probes that host as script, xhr and image, so all three are lost.
    assert_eq!(r.lost.len(), 3, "{r:?}");
    assert!(r
        .lost
        .iter()
        .all(|(u, _, _)| u.contains("tracker.example.test")));
}

#[test]
fn regression_is_clean_when_nothing_is_removed() {
    let text = "||tracker.example.test^\n||ads.example.test^\n||metrics.example.test^\n";
    let built = compile(text, "");
    let r = superbrave::verify::regression_vs_upstream(text, &built);
    assert!(r.lost.is_empty(), "{r:?}");
    assert!(r.identical > 0);
}
