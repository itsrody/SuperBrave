use superbrave::rewrite::{rewrite_line, Rewrite};

fn repaired(rule: &str) -> Option<String> {
    match rewrite_line(rule) {
        Rewrite::Equivalent(r) => Some(r),
        _ => None,
    }
}

#[test]
fn caret_path_rule_is_repaired_to_a_matching_form() {
    // `||a.com^/p` compiles but can never match; `||a.com/p` is the author's intent.
    // This is a deliberate behaviour change, not a no-op normalisation.
    match rewrite_line("||a.com^/p") {
        Rewrite::BehaviourChange { rule, .. } => assert_eq!(rule, "||a.com/p"),
        other => panic!("expected behaviour change, got {other:?}"),
    }
}

#[test]
fn caret_separator_without_slash_is_left_alone() {
    // `^` followed by a non-separator is a legal ABP separator and does match.
    assert_eq!(repaired("||a.com^ads1"), None);
}

#[test]
fn to_option_rules_are_never_stripped() {
    // `$to=` makes a rule redirect-only: it suppresses blocking entirely rather
    // than being inert. Removing it would silently start blocking requests.
    assert_eq!(repaired("/x.js$to=tracker.com"), None);
    assert_eq!(repaired("/x.js$script,to=a.com|b.com"), None);
}

#[test]
fn important_removeparam_is_split_into_a_blocking_rule() {
    let out = repaired("||a.com^$important,removeparam=utm_source");
    assert_eq!(out.as_deref(), Some("||a.com^$removeparam=utm_source"));
}

#[test]
fn already_efficient_rules_are_left_untouched() {
    assert_eq!(repaired("||ads.example.com^$script,third-party"), None);
}

#[test]
fn malformed_rules_report_no_repair() {
    assert!(matches!(
        rewrite_line("||a.com^$popup"),
        Rewrite::Impossible(_)
    ));
}
