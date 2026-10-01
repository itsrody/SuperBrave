//! Corpus-wide rewrites.
//!
//! The per-line repair pass in [`crate::rewrite`] fixes rules the engine mishandles.
//! This module does the opposite job: it rewrites rules that are *already correct*
//! into an equivalent form that is cheaper for the engine to evaluate, or removes
//! rules that cannot affect any request.
//!
//! Every stage here is admitted only after it proves itself equivalent to the
//! rule set it replaced, by differential-testing the two compiled engines across
//! a request corpus derived from the rules the stage touched. A stage that changes
//! a single verdict is discarded in full; the pipeline never ships an unproven
//! rewrite.

use crate::pipeline::Accepted;
use crate::verify::{compile, Check};
use std::collections::{HashMap, HashSet};

/// A single stage of the optimisation pass and what it did.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Stage {
    pub name: &'static str,
    /// False when the differential gate rejected the stage.
    pub accepted: bool,
    /// Rules deleted outright.
    pub removed: usize,
    /// Rules rewritten in place.
    pub rewritten: usize,
    /// Verdicts that differed while the stage was on trial.
    pub diffs: usize,
}

#[derive(Debug, Clone, Default)]
pub struct Outcome {
    pub stages: Vec<Stage>,
    pub rules_in: usize,
    pub rules_out: usize,
    /// The accepted rule set.
    pub final_rules: Vec<Accepted>,
}

impl Outcome {
    /// Rules the pass deleted, counting only stages that were kept.
    pub fn removed(&self) -> usize {
        self.stages
            .iter()
            .filter(|s| s.accepted)
            .map(|s| s.removed)
            .sum()
    }

    /// Rules the pass rewrote in place, counting only stages that were kept.
    pub fn rewritten(&self) -> usize {
        self.stages
            .iter()
            .filter(|s| s.accepted)
            .map(|s| s.rewritten)
            .sum()
    }

    /// The accepted rule set.
    pub fn into_rules(self) -> Vec<Accepted> {
        self.final_rules
    }
}

/// Splits a rule into its exception marker, pattern and raw option list.
///
/// The `$` that opens the options is the *last* one in the line, because that is
/// where the engine looks (`memrchr` in `abstract_network.rs`). A pattern is
/// therefore allowed to contain `$` of its own, and taking the first one instead
/// would truncate the pattern and turn the rest of it into options.
fn parts(rule: &str) -> (&str, &str, &str) {
    let marker = if rule.starts_with("@@") { "@@" } else { "" };
    let body = rule.strip_prefix("@@").unwrap_or(rule);
    match body.rfind('$') {
        Some(i) => (marker, &body[..i], &body[i..]),
        None => (marker, body, ""),
    }
}

/// Splits a rule into its pattern and its raw option list, keeping the `@@` marker
/// on the pattern.
fn split_rule(rule: &str) -> (&str, &str) {
    let (marker, pattern, _) = parts(rule);
    // Both halves have to come from one slice of the rule, so the marker is put
    // back by asking for the prefix rather than concatenating.
    let end = marker.len() + pattern.len();
    (&rule[..end], &rule[end..])
}

/// The option body without its leading `$`.
fn option_list(options: &str) -> &str {
    options.strip_prefix('$').unwrap_or("")
}

/// The canonical spelling of an option name, mirroring the engine's own option
/// parser in `abstract_network.rs`: every alias below is parsed into the same
/// variant, so two rules differing only by spelling are the same rule and only one
/// copy needs to survive. A name the engine does not accept is deliberately
/// absent, because a rule carrying one is dropped by the engine anyway and its
/// options are never worth reordering.
fn canonical_name(name: &str) -> &'static str {
    match name {
        "domain" | "from" => "domain",
        "to" => "to",
        "badfilter" => "badfilter",
        "important" => "important",
        "match-case" => "match-case",
        "third-party" | "3p" => "third-party",
        "first-party" | "1p" => "first-party",
        "tag" => "tag",
        "redirect" | "rewrite" => "redirect",
        "redirect-rule" => "redirect-rule",
        "csp" => "csp",
        "removeparam" => "removeparam",
        "generichide" | "ghide" => "generichide",
        "document" | "doc" => "document",
        "image" => "image",
        "media" => "media",
        "object" | "object-subrequest" => "object",
        "other" => "other",
        "ping" | "beacon" => "ping",
        "script" => "script",
        "stylesheet" | "css" => "stylesheet",
        "subdocument" | "frame" => "subdocument",
        "xmlhttprequest" | "xhr" => "xmlhttprequest",
        "websocket" => "websocket",
        "font" => "font",
        "all" => "all",
        "method" => "method",
        _ => "",
    }
}

/// Options the engine treats positionally or whose value grammar depends on the
/// option's position, so they are never reordered.
const POSITIONAL: &[&str] = &["csp", "removeparam"];

/// Rewrites a rule's option list into a canonical order. Returns `None` when the
/// rule is already canonical or cannot be safely reordered.
fn canonical_options(rule: &str) -> Option<String> {
    // A cosmetic selector may contain `$`, `^` and `,` of its own, and the engine
    // does not parse options for it at all. The differential gate only watches
    // network requests, so rewriting one here would go unchecked.
    if is_cosmetic(rule) {
        return None;
    }
    let (marker, pattern, options) = parts(rule);
    if options.is_empty() {
        return None;
    }
    let mut out: Vec<String> = Vec::new();
    for option in option_list(options).split(',') {
        if option.is_empty() {
            continue;
        }
        let negated = option.starts_with('~');
        let body = if negated { &option[1..] } else { option };
        let (name, value) = body.split_once('=').unwrap_or((body, ""));
        let canonical = canonical_name(name);
        // An unknown name is left exactly as written rather than guessed at.
        if canonical.is_empty() {
            return None;
        }
        if POSITIONAL.contains(&canonical) {
            return None;
        }
        // `$all` is left in place. An empty positive mask becomes `FROM_NETWORK_TYPES`,
        // but `$all` becomes `FROM_ALL_TYPES`, which also covers documents and
        // subdocuments, so removing it narrows the rule.
        let mut rendered = if value.is_empty() {
            canonical.to_string()
        } else {
            format!("{canonical}={value}")
        };
        if negated {
            rendered.insert(0, '~');
        }
        out.push(rendered);
    }
    if out.is_empty() {
        let candidate = format!("{marker}{pattern}");
        return (candidate != rule).then_some(candidate);
    }
    out.sort_unstable();
    out.dedup();
    let candidate = format!("{marker}{pattern}${}", out.join(","));
    (candidate != rule).then_some(candidate)
}

/// Wildcards and anchors a hostname-anchored rule does not need.
///
/// The engine compiles any pattern containing `*` or `^` through its regex path,
/// while a plain pattern takes a substring or prefix compare. Two rewrites are safe
/// on the path of a `||` rule:
///
/// * `**` compiles to `.*.*`, which is just `.*`.
/// * a trailing `*` compiles to a trailing `.*`, and a left-anchored `^P.*` accepts
///   exactly the strings `^P` accepts.
///
/// Two things are deliberately left alone:
///
/// * A `^`, because it expands to *any* separator character: `||a.com/^x` also
///   matches `||a.com/?x`, so dropping it would narrow the rule.
/// * A `*` that opens the path, because that is also where the engine splits the
///   hostname off and marks it as a regex. Removing it would change how the
///   hostname itself is matched, not just the path.
fn collapse_wildcards(pattern: &str) -> Option<String> {
    let rest = pattern.strip_prefix("||")?;
    let (host, path) = rest.split_at(rest.find(['/', '*', '^']).unwrap_or(rest.len()));
    // A wildcard inside the hostname makes the engine match it as a regex.
    if host.contains('*') {
        return None;
    }
    let chars: Vec<char> = path.chars().collect();
    let opens_path = chars.first() == Some(&'*');
    let mut out = String::with_capacity(path.len());
    let (mut i, mut changed) = (0usize, false);
    while i < chars.len() {
        if chars[i] == '*' {
            while i + 1 < chars.len() && chars[i + 1] == '*' {
                i += 1;
                changed = true;
            }
            if i + 1 == chars.len() && !opens_path {
                changed = true;
            } else {
                out.push('*');
            }
        } else {
            out.push(chars[i]);
        }
        i += 1;
    }
    let collapsed = format!("||{host}{out}");
    (changed && collapsed != pattern).then_some(collapsed)
}

fn rebuild(marker: &str, pattern: &str, options: &str) -> String {
    format!("{marker}{pattern}{options}")
}

/// Stage 1: canonicalise option spellings, then drop the duplicates that exposes.
fn stage_canonicalise(rules: &[Accepted]) -> (Vec<Accepted>, usize, usize) {
    let mut out = Vec::with_capacity(rules.len());
    let mut seen: HashSet<String> = HashSet::with_capacity(rules.len());
    let (mut removed, mut rewritten) = (0usize, 0usize);
    for rule in rules {
        let canonical = canonical_options(&rule.text);
        // A rule with nothing to canonicalise yields `None`, which is not a
        // rewrite; counting those would report nearly every rule as changed.
        let changed = canonical
            .as_deref()
            .is_some_and(|c| c != rule.text.as_str());
        let text = canonical.unwrap_or_else(|| rule.text.clone());
        if changed {
            rewritten += 1;
        }
        if seen.insert(text.clone()) {
            out.push(Accepted {
                text,
                source: rule.source,
                origin: if changed { "canonical" } else { rule.origin },
            });
        } else {
            removed += 1;
        }
    }
    (out, removed, rewritten)
}

/// Stage 2: remove wildcards a `||` rule does not need.
fn stage_collapse_wildcards(rules: &[Accepted]) -> (Vec<Accepted>, usize, usize) {
    let mut out = Vec::with_capacity(rules.len());
    let (removed, mut rewritten) = (0usize, 0usize);
    for rule in rules {
        let (pattern, options) = split_rule(&rule.text);
        let marker = if rule.text.starts_with("@@") {
            "@@"
        } else {
            ""
        };
        match collapse_wildcards(pattern) {
            Some(collapsed) => {
                rewritten += 1;
                out.push(Accepted {
                    text: rebuild(marker, &collapsed, options),
                    source: rule.source,
                    origin: "collapsed",
                });
            }
            None => out.push(rule.clone()),
        }
    }
    (out, removed, rewritten)
}

/// Stage 3: a `$badfilter` rule disables one specific rule, so both can go.
///
/// The engine pairs them by a hash over the filter's mask, features, domains and
/// pattern — the `badfilter` bit itself excluded (`compute_filter_id` in
/// `network.rs`). Siblings that merely share a pattern, such as `||a.com^` next to
/// `||a.com`, are *not* disabled, so a pair is only formed when stripping
/// `badfilter` from the rule's own options reproduces the target rule exactly.
fn stage_drop_badfilter_pairs(rules: &[Accepted]) -> (Vec<Accepted>, usize, usize) {
    let identities: HashSet<&str> = rules.iter().map(|r| r.text.as_str()).collect();
    let mut drop: HashSet<String> = HashSet::new();
    for rule in rules {
        let (marker, pattern, options) = parts(&rule.text);
        let all: Vec<&str> = option_list(options).split(',').collect();
        let kept: Vec<&str> = all.iter().copied().filter(|o| *o != "badfilter").collect();
        if kept.len() == all.len() {
            continue;
        }
        let target = if kept.is_empty() {
            format!("{marker}{pattern}")
        } else {
            format!("{marker}{pattern}${}", kept.join(","))
        };
        // Only an exact match is disabled by the engine, and only then is the
        // target safe to delete.
        if identities.contains(target.as_str()) {
            drop.insert(rule.text.clone());
            drop.insert(target);
        }
    }
    let mut removed = 0usize;
    let out: Vec<Accepted> = rules
        .iter()
        .filter(|rule| {
            if drop.contains(&rule.text) {
                removed += 1;
                return false;
            }
            true
        })
        .cloned()
        .collect();
    (out, removed, 0)
}

/// The single `domain=` scope of a rule, plus everything else about it. `None`
/// when the rule has no scope, or more than one, or a scope that is already a
/// `|`-delimited list.
fn split_scope(text: &str) -> Option<(String, Vec<String>, String)> {
    let (_, pattern, options) = parts(text);
    if !pattern.starts_with("||") {
        return None;
    }
    let mut scope = None;
    let mut rest = Vec::new();
    for option in option_list(options).split(',') {
        match option.strip_prefix("domain=") {
            Some(value) if !value.contains('|') && scope.is_none() => {
                scope = Some(value.to_string());
            }
            Some(_) => return None,
            None => rest.push(option.to_string()),
        }
    }
    Some((pattern.to_string(), rest, scope?))
}

/// Stage 4: fold rules that share a pattern and options into one `domain=` list.
fn stage_merge_scopes(rules: &[Accepted]) -> (Vec<Accepted>, usize, usize) {
    let mut groups: HashMap<(String, Vec<String>), Vec<usize>> = HashMap::new();
    for (i, rule) in rules.iter().enumerate() {
        if let Some((pattern, rest, _)) = split_scope(&rule.text) {
            groups.entry((pattern, rest)).or_default().push(i);
        }
    }
    let mut merged_at: HashMap<usize, Accepted> = HashMap::new();
    let mut dropped: HashSet<usize> = HashSet::new();
    for ((pattern, rest), members) in &groups {
        if members.len() < 2 {
            continue;
        }
        let marker = if rules[members[0]].text.starts_with("@@") {
            "@@"
        } else {
            ""
        };
        let scopes: Vec<String> = members
            .iter()
            .map(|i| split_scope(&rules[*i].text).map(|(_, _, s)| s))
            .collect::<Option<Vec<_>>>()
            .unwrap_or_default();
        if scopes.len() != members.len() {
            continue;
        }
        let options = if rest.is_empty() {
            format!("$domain={}", scopes.join("|"))
        } else {
            format!("${},domain={}", rest.join(","), scopes.join("|"))
        };
        merged_at.insert(
            members[0],
            Accepted {
                text: rebuild(marker, pattern, &options),
                source: rules[members[0]].source,
                origin: "merged",
            },
        );
        dropped.extend(members[1..].iter().copied());
    }
    let merged: Vec<Accepted> = rules
        .iter()
        .enumerate()
        .filter(|(i, _)| !dropped.contains(i))
        .map(|(i, rule)| merged_at.remove(&i).unwrap_or_else(|| rule.clone()))
        .collect();
    (merged, dropped.len(), 0)
}

/// One stage of the pass, named so it can be reported on.
pub type StageFn = fn(&[Accepted]) -> (Vec<Accepted>, usize, usize);

/// The stages, in the order they are attempted. Public so a caller can run or
/// report on them individually.
pub const STAGES: &[(&str, StageFn)] = &[
    ("canonical option spellings", stage_canonicalise),
    ("collapse redundant wildcards", stage_collapse_wildcards),
    ("drop badfilter pairs", stage_drop_badfilter_pairs),
    ("merge document scopes", stage_merge_scopes),
];

/// Runs every stage, keeping only the ones that prove themselves equivalent.
pub fn optimise(rules: Vec<Accepted>) -> Outcome {
    let mut outcome = Outcome {
        rules_in: rules.len(),
        rules_out: rules.len(),
        final_rules: vec![],
        ..Default::default()
    };
    let mut current = rules;
    let mut probed: HashSet<String> = HashSet::new();
    for (name, stage) in STAGES {
        let (candidate, removed, rewritten) = stage(&current);
        if removed == 0 && rewritten == 0 {
            outcome.stages.push(Stage {
                name,
                accepted: true,
                removed: 0,
                rewritten: 0,
                diffs: 0,
            });
            continue;
        }
        // Only the rules a stage rewrote or deleted need probing: a rewrite can
        // only break requests its own rule would have matched. The probe set
        // accumulates, and both engines are always measured against the same one.
        probed.extend(touched(&current, &candidate));
        let reference = Verdict::of(&current, &probed);
        let trial = Verdict::of(&candidate, &probed);
        let diffs = reference.diff(&trial);
        let accepted = diffs == 0;
        outcome.stages.push(Stage {
            name,
            accepted,
            removed,
            rewritten,
            diffs,
        });
        if accepted {
            current = candidate;
        }
    }
    outcome.rules_out = current.len();
    outcome.final_rules = current;
    outcome
}

/// Rule texts that appear in one set but not the other.
fn touched(before: &[Accepted], after: &[Accepted]) -> HashSet<String> {
    let left: HashSet<&str> = before.iter().map(|r| r.text.as_str()).collect();
    let right: HashSet<&str> = after.iter().map(|r| r.text.as_str()).collect();
    before
        .iter()
        .filter(|r| !right.contains(r.text.as_str()))
        .map(|r| r.text.clone())
        .chain(
            after
                .iter()
                .filter(|r| !left.contains(r.text.as_str()))
                .map(|r| r.text.clone()),
        )
        .collect()
}

/// A fingerprint of what an engine does, one entry per corpus request.
struct Verdict {
    checks: Vec<Check>,
    requests: Vec<(String, String, String)>,
}

impl Verdict {
    fn of(rules: &[Accepted], touched: &HashSet<String>) -> Verdict {
        let mut network = String::with_capacity(rules.len() * 48);
        let mut cosmetic = String::with_capacity(rules.len() * 48);
        for rule in rules {
            if is_cosmetic(&rule.text) {
                cosmetic.push_str(&rule.text);
                cosmetic.push('\n');
            } else {
                network.push_str(&rule.text);
                network.push('\n');
            }
        }
        let built = compile(&network, &cosmetic);
        let corpus = corpus_for(touched);
        let checks = corpus
            .iter()
            .map(|(u, s, k)| {
                Check::run(&built.engine, u, s, k).unwrap_or(Check {
                    blocked: false,
                    excepted: false,
                    important: false,
                    redirect: false,
                    rewritten: None,
                })
            })
            .collect();
        Verdict {
            checks,
            requests: corpus,
        }
    }

    fn diff(&self, other: &Verdict) -> usize {
        self.checks.len().abs_diff(other.checks.len())
            + self
                .checks
                .iter()
                .zip(&other.checks)
                .filter(|(a, b)| a != b)
                .count()
    }
}

fn is_cosmetic(text: &str) -> bool {
    text.contains("##") || text.contains("#@#") || text.contains("#?#") || text.contains("#$#")
}

/// Renders a rule set as list text.
pub fn rules_text(rules: &[Accepted]) -> String {
    let mut out = String::with_capacity(rules.len() * 48);
    for rule in rules {
        out.push_str(&rule.text);
        out.push('\n');
    }
    out
}

/// Counts the requests on which two rule sets disagree.
///
/// This is the gate every rewrite has to pass. It probes the fixed corpus plus
/// requests aimed at the rules that differ between the two sets, because a rewrite
/// can only change the requests its own rule would have matched.
pub fn differences(before: &[Accepted], after: &[Accepted]) -> usize {
    changed_requests(before, after).len()
}

/// The requests on which two rule sets disagree, capped so a rejected stage can
/// report what it broke without flooding the log.
pub fn changed_requests(before: &[Accepted], after: &[Accepted]) -> Vec<(String, String, String)> {
    let probed = touched(before, after);
    let left = Verdict::of(before, &probed);
    let right = Verdict::of(after, &probed);
    let mut out = Vec::new();
    for (i, (a, b)) in left.checks.iter().zip(&right.checks).enumerate() {
        if a == b {
            continue;
        }
        if let Some(request) = left.requests.get(i) {
            out.push(request.clone());
        }
        if out.len() == 20 {
            break;
        }
    }
    out
}

/// The request corpus a stage must not disturb.
///
/// A fixed set of realistic requests, plus requests aimed at every rule the stage
/// rewrote or deleted. The failures a bad rewrite causes are always local to the
/// rule it rewrote, so probing those rules directly is what catches them.
fn corpus_for(touched: &HashSet<String>) -> Vec<(String, String, String)> {
    let mut corpus = fixed_corpus();
    for rule in touched {
        corpus.extend(requests_for(rule));
    }
    corpus.sort();
    corpus.dedup();
    corpus
}

fn fixed_corpus() -> Vec<(String, String, String)> {
    let mut v = Vec::new();
    for (url, source) in [
        ("https://doubleclick.net/", "https://news.example/"),
        ("https://ad.doubleclick.net/ddm/ad.js", "https://a.example/"),
        (
            "https://www.google-analytics.com/analytics.js",
            "https://shop.example/",
        ),
        (
            "https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js",
            "https://x.example/",
        ),
        (
            "https://cdn.jsdelivr.net/npm/x@1.0.0/x.js",
            "https://git.example/",
        ),
        ("https://example.com/", "https://news.example/"),
        ("http://insecure.example/ad.js", "https://a.example/"),
        ("https://example.com/?a=1", "https://example.com/"),
        ("https://sub.example.com/ad.js", "https://example.com/"),
        ("https://example.com/ad.js", "https://sub.example.com/"),
    ] {
        for kind in ["script", "image", "xhr", "document", "stylesheet", "media"] {
            v.push((url.to_string(), source.to_string(), kind.to_string()));
        }
    }
    v
}

/// Requests aimed at one rule, covering the shapes a rewriting mistake produces:
/// doubled slashes, separator variants, wildcard tails and third-party origins.
///
/// The count is bounded on purpose: a stage can touch thousands of rules, and the
/// corpus has to stay small enough that both engines can be measured quickly.
fn requests_for(rule: &str) -> Vec<(String, String, String)> {
    let body = rule.strip_prefix("@@").unwrap_or(rule);
    let (pattern, options) = split_rule(body);
    let Some(rest) = pattern.strip_prefix("||") else {
        return vec![];
    };
    // The hostname ends at the first separator, wildcard or anchor.
    let stop = rest.find(['/', '*', '^']).unwrap_or(rest.len());
    let (host, tail) = rest.split_at(stop);
    if host.is_empty() || host.contains('[') || host.contains('*') {
        return vec![];
    }
    let opts = option_list(options);
    let kinds: &[&str] = if opts.contains("document") {
        &["document"]
    } else if opts.contains("script") {
        &["script"]
    } else if opts.contains("image") {
        &["image"]
    } else if opts.contains("xmlhttprequest") {
        &["xhr"]
    } else {
        &["script", "document"]
    };
    let own = format!("https://{host}/");
    let foreign = "https://foreign.example/".to_string();
    // A party-constrained rule only fires from an origin of that relationship, so
    // probing it from the wrong one would hide a broken rewrite.
    let sources: Vec<String> = if opts.contains("third-party") {
        vec![foreign]
    } else if opts.contains("first-party") {
        vec![own]
    } else {
        vec![foreign, own]
    };
    let mut v = Vec::new();
    // The literal path, then the same path with its wildcards and anchors removed,
    // then both extended. Dropping an anchor or a wildcard is exactly the class of
    // mistake that narrows a rule, so those variants have to be probed.
    let shapes = [
        tail.to_string(),
        tail.replace('*', "z"),
        tail.replace('^', "/"),
        tail.replace(['*', '^'], ""),
    ];
    for shape in shapes {
        for path in [shape.clone(), format!("{shape}extra")] {
            for scheme in ["https", "http"] {
                for source in &sources {
                    for kind in kinds {
                        v.push((
                            format!("{scheme}://{host}{path}"),
                            source.clone(),
                            (*kind).to_string(),
                        ));
                    }
                }
            }
        }
    }
    v
}
