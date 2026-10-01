use superbrave::optimise::optimise;
use superbrave::pipeline::Accepted;

fn rules(texts: &[&str]) -> Vec<Accepted> {
    texts
        .iter()
        .map(|t| Accepted {
            text: (*t).to_string(),
            source: 0,
            origin: "verbatim",
        })
        .collect()
}

fn texts(accepted: Vec<Accepted>) -> Vec<String> {
    let mut v: Vec<String> = accepted.into_iter().map(|a| a.text).collect();
    v.sort();
    v
}

#[test]
fn option_aliases_are_canonicalised_and_deduplicated() {
    let out = optimise(rules(&[
        "||a.com^$3p",
        "||a.com^$third-party",
        "||b.com^$doc",
        "||b.com^$document",
        "||c.com^$all",
        "||d.com^$xhr,from=e.com",
        "||d.com^$from=e.com,xmlhttprequest",
    ]));
    assert!(out.stages[0].accepted, "stage 1 was rejected");
    assert_eq!(
        texts(out.into_rules()),
        vec![
            "||a.com^$third-party".to_string(),
            "||b.com^$document".to_string(),
            "||c.com^$all".to_string(),
            "||d.com^$domain=e.com,xmlhttprequest".to_string(),
        ]
    );
}

#[test]
fn canonicalisation_leaves_unknown_options_alone() {
    // An option the engine might add later is never guessed at or reordered.
    let out = optimise(rules(&["||a.com^$script,futureshim=1,image"]));
    assert!(out
        .into_rules()
        .iter()
        .any(|r| r.text == "||a.com^$script,futureshim=1,image"));
}

#[test]
fn positional_options_are_never_reordered() {
    let out = optimise(rules(&["||a.com^$image,csp=script-src 'self'"]));
    assert!(out
        .into_rules()
        .iter()
        .any(|r| r.text == "||a.com^$image,csp=script-src 'self'"));
}

#[test]
fn trailing_and_doubled_wildcards_collapse() {
    let out = optimise(rules(&[
        "||a.com/ads/*",
        "||b.com/ads/**/x.js",
        "||c.com/ads",
    ]));
    let got = texts(out.into_rules());
    assert!(got.contains(&"||a.com/ads/".to_string()), "{got:?}");
    assert!(got.contains(&"||b.com/ads/*/x.js".to_string()), "{got:?}");
    assert!(got.contains(&"||c.com/ads".to_string()), "{got:?}");
}

#[test]
fn a_separator_anchor_is_never_dropped() {
    // `^` expands to *any* separator character, so `||a.com/^x` also matches
    // `||a.com/?x`. Dropping the `^` would narrow the rule and lose blocks.
    let out = optimise(rules(&["||a.com/^x", "||b.com^^x"]));
    let got = texts(out.into_rules());
    assert!(got.contains(&"||a.com/^x".to_string()), "{got:?}");
    assert!(got.contains(&"||b.com^^x".to_string()), "{got:?}");
}

#[test]
fn wildcards_are_only_collapsed_on_hostname_anchored_rules() {
    // A bare pattern is a candidate for the engine's pattern-fusion optimisation,
    // which groups by the filter mask. Rewriting one would split its fusion group,
    // so the pass leaves fusable rules alone.
    let out = optimise(rules(&["/ads/images/*$image"]));
    assert!(out
        .into_rules()
        .iter()
        .any(|r| r.text == "/ads/images/*$image"));
}

#[test]
fn badfilter_pairs_are_both_removed() {
    let out = optimise(rules(&[
        "||fwcdn1.com/js/storyblock.js",
        "||fwcdn1.com/js/storyblock.js$badfilter",
        "||kept.com^",
    ]));
    let got = texts(out.into_rules());
    assert_eq!(got, vec!["||kept.com^".to_string()]);
}

#[test]
fn a_badfilter_does_not_reach_rules_that_merely_share_its_pattern() {
    // The engine pairs a `$badfilter` rule with its target by hashing the whole
    // filter, `badfilter` bit excluded. `||adjust.com^` differs in mask from
    // `||adjust.com`, so it survives the badfilter and must survive the pass.
    let out = optimise(rules(&[
        "||adjust.com",
        "||adjust.com$badfilter",
        "||adjust.com^",
        "||adjust.com$script",
    ]));
    let got = texts(out.into_rules());
    assert_eq!(
        got,
        vec![
            "||adjust.com$script".to_string(),
            "||adjust.com^".to_string()
        ]
    );
}

#[test]
fn all_is_never_dropped_because_it_covers_more_than_an_empty_mask() {
    // An empty positive mask becomes `FROM_NETWORK_TYPES`, but `$all` becomes
    // `FROM_ALL_TYPES`, which also covers documents and subdocuments.
    let out = optimise(rules(&["||acir.com/grupoacir/$all"]));
    let got = texts(out.into_rules());
    assert_eq!(got, vec!["||acir.com/grupoacir/$all".to_string()]);
}

#[test]
fn a_dollar_in_the_pattern_is_not_mistaken_for_the_options() {
    // The engine finds the option list with the *last* `$` in the line. Taking the
    // first one would truncate the pattern and turn the tail into options.
    let out = optimise(rules(&[
        "%3C?php%20echo%20substr(md5(microtime()));?%3E&$doc",
        "&bemobdata=c%$all",
    ]));
    let got = texts(out.into_rules());
    assert!(
        got.contains(&"%3C?php%20echo%20substr(md5(microtime()));?%3E&$document".to_string()),
        "{got:?}"
    );
    assert!(got.contains(&"&bemobdata=c%$all".to_string()), "{got:?}");
}

#[test]
fn an_exception_keeps_its_marker_when_its_options_are_reordered() {
    let out = optimise(rules(&["@@||47news.jp/static/*$3p,domain=x.com,css"]));
    let got = texts(out.into_rules());
    assert_eq!(
        got,
        vec!["@@||47news.jp/static/*$domain=x.com,stylesheet,third-party".to_string()]
    );
}

#[test]
fn a_cosmetic_selector_is_never_treated_as_a_network_rule() {
    // `vipbox.*##a[href^="https://x/?y"]` contains `$`, `^` and `,` that belong to
    // the selector. The engine never parses options for a cosmetic rule.
    let out = optimise(rules(&["vipbox.*##a[href^=\"https://x.com/?$1,2\"]"]));
    assert_eq!(
        texts(out.into_rules()),
        vec!["vipbox.*##a[href^=\"https://x.com/?$1,2\"]".to_string()]
    );
}

#[test]
fn a_wildcard_that_opens_the_path_is_kept_because_it_marks_the_host() {
    // That `*` is where the engine splits the hostname off and switches the
    // hostname to a regex match, so `||a.com*` does not mean `||a.com`.
    let out = optimise(rules(&["||buzzer.xhamster*"]));
    let got = texts(out.into_rules());
    assert_eq!(got, vec!["||buzzer.xhamster*".to_string()]);
}

#[test]
fn document_scopes_are_merged() {
    let out = optimise(rules(&[
        "||a.com/ads$domain=x.com",
        "||a.com/ads$domain=y.com",
        "||a.com/ads$script,domain=x.com",
        "||a.com/ads$script,domain=y.com",
        "||a.com/ads$domain=x.com|already.com",
        "||b.com/x$domain=p.com",
    ]));
    let got = texts(out.into_rules());
    assert!(
        got.contains(&"||a.com/ads$domain=x.com|y.com".to_string()),
        "{got:?}"
    );
    assert!(
        got.contains(&"||a.com/ads$script,domain=x.com|y.com".to_string()),
        "{got:?}"
    );
    // A scope that is already a list is left alone; a lone scope has no sibling.
    assert!(
        got.contains(&"||a.com/ads$domain=x.com|already.com".to_string()),
        "{got:?}"
    );
    assert!(
        got.contains(&"||b.com/x$domain=p.com".to_string()),
        "{got:?}"
    );
}

#[test]
fn exceptions_merge_like_blocking_rules() {
    let out = optimise(rules(&[
        "@@||a.com/x$domain=p.com",
        "@@||a.com/x$domain=q.com",
    ]));
    let got = texts(out.into_rules());
    assert_eq!(got, vec!["@@||a.com/x$domain=p.com|q.com".to_string()]);
}

#[test]
fn every_stage_is_proven_equivalent_against_a_corpus() {
    // The pass must not be able to emit a rule set that blocks differently from
    // what it was given, whichever rewrites happen to be available.
    let input = rules(&[
        "||ads.tracker.test^$3p",
        "||ads.tracker.test^$third-party",
        "||pixel.test^$domain=shop.test",
        "||pixel.test^$domain=news.test",
        "||dead.test^$badfilter",
        "||banners.test/*",
        "@@||cdn.test^$doc",
        "##.ad-slot",
        "/banner.gif$image",
    ]);
    let before = superbrave::verify::compile(&superbrave::optimise::rules_text(&input), "");
    let out = optimise(input);
    let after_text = superbrave::optimise::rules_text(&out.final_rules);
    let after = superbrave::verify::compile(&after_text, "");

    let mut compared = 0usize;
    for (u, s, k) in superbrave::verify::probe_corpus() {
        for rule in [
            "https://ads.tracker.test/x.js",
            "https://pixel.test/p.gif",
            "https://banners.test/a.png",
            "https://cdn.test/a.js",
        ] {
            let Ok(req) = adblock::request::Request::new(
                &format!("{u}{}", rule.trim_start_matches("https://")),
                &s,
                &k,
                "get",
            ) else {
                continue;
            };
            let a = before.engine.check_network_request(&req);
            let b = after.engine.check_network_request(&req);
            assert_eq!(a.filter.is_some(), b.filter.is_some(), "{req:?}");
            assert_eq!(a.exception.is_some(), b.exception.is_some(), "{req:?}");
            compared += 1;
        }
    }
    assert!(compared > 0);
}

#[test]
fn a_stage_that_changes_behaviour_is_dropped_whole() {
    // `@@||a.com/x$domain=p.com` alone does not block anything, and neither does
    // merging it, so this asserts the mechanism rather than a specific verdict:
    // every stage that reports work must also report zero verdict changes.
    let out = optimise(rules(&[
        "||a.com^$domain=x.com",
        "||a.com^$domain=y.com",
        "||b.com^$3p",
        "||b.com^$third-party",
    ]));
    for stage in &out.stages {
        if stage.removed > 0 || stage.rewritten > 0 {
            assert!(stage.accepted, "{} was not equivalent", stage.name);
            assert_eq!(stage.diffs, 0, "{} changed a verdict", stage.name);
        }
    }
    assert!(out.rules_out < out.rules_in);
}

#[test]
fn the_gate_rejects_a_rewrite_that_narrows_a_rule() {
    // Dropping `^` after a separator looks like a tidy-up, but `^` expands to any
    // separator character, so the rewrite stops matching `/a.com/?x`. This is the
    // mistake the gate exists to stop.
    let before = rules(&["||a.com/^x"]);
    let after = rules(&["||a.com/x"]);
    assert!(
        superbrave::optimise::differences(&before, &after) > 0,
        "gate failed to notice a narrowing rewrite"
    );
}

#[test]
fn the_gate_rejects_dropping_a_rule_that_was_live() {
    let before = rules(&["||a.com/ads/*", "||b.com^"]);
    let after = rules(&["||a.com/ads"]);
    assert!(superbrave::optimise::differences(&before, &after) > 0);
}

#[test]
fn the_gate_accepts_the_rewrites_the_pass_actually_makes() {
    let before = rules(&[
        "||a.com^$3p",
        "||a.com^$third-party",
        "||b.com/ads/*",
        "||c.com/ads/*",
        "||d.com^$domain=x.com",
        "||d.com^$domain=y.com",
        "||e.com^",
        "||e.com^$badfilter",
    ]);
    let after = optimise(before.clone()).into_rules();
    assert_eq!(superbrave::optimise::differences(&before, &after), 0);
}
