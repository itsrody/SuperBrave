use adblock::filters::network::NetworkFilter;
use adblock::lists::{parse_filter, ParseOptions, ParsedLine};
use adblock::request::Request;
use std::collections::HashSet;

/// A single behavioural probe: a request plus the expected match decision.
#[derive(Debug, Clone)]
pub struct Probe {
    pub url: &'static str,
    pub source: &'static str,
    pub kind: &'static str,
}

/// Probes chosen to distinguish a rewrite from the rule it replaces. Each probe is
/// checked against the *original* rule to establish ground truth before the
/// rewritten form is validated.
pub static STRUCTURAL_PROBES: &[Probe] = &[
    Probe {
        url: "https://a.com/p",
        source: "https://s.com/",
        kind: "xhr",
    },
    Probe {
        url: "https://a.com/p/q",
        source: "https://s.com/",
        kind: "xhr",
    },
    Probe {
        url: "https://a.com/xp",
        source: "https://s.com/",
        kind: "xhr",
    },
    Probe {
        url: "https://b.a.com/p",
        source: "https://s.com/",
        kind: "xhr",
    },
    Probe {
        url: "https://a.com/",
        source: "https://s.com/",
        kind: "document",
    },
    Probe {
        url: "https://a.com/z.png",
        source: "https://s.com/",
        kind: "image",
    },
    Probe {
        url: "http://a.com/p",
        source: "https://s.com/",
        kind: "script",
    },
    Probe {
        url: "https://other.com/p",
        source: "https://s.com/",
        kind: "xhr",
    },
    Probe {
        url: "https://a.com/p",
        source: "https://a.com/",
        kind: "xhr",
    },
];

/// Synthetic URL corpus derived from a rule's own pattern. This catches regressions
/// where a rewrite silently changes what the rule matches in the wild, not just on
/// the fixed probe set.
fn collapse(url: String) -> String {
    let scheme_end = url.find("//").map(|i| i + 2).unwrap_or(0);
    let (head, tail) = url.split_at(scheme_end);
    let mut out = String::with_capacity(url.len());
    let mut prev = ' ';
    for c in tail.chars() {
        if c == '/' && prev == '/' {
            continue;
        }
        out.push(c);
        prev = c;
    }
    let trimmed = out.trim_end_matches('/');
    if trimmed.len() == scheme_end {
        head.to_string()
    } else {
        format!("{head}{trimmed}")
    }
}

pub fn derived_probes(rule: &str) -> Vec<(String, String, &'static str)> {
    let mut out = Vec::new();
    let body = rule.split('$').next().unwrap_or(rule);
    let body = body.trim_start_matches('@').trim_start();

    let mut patterns: Vec<String> = Vec::new();
    if let Some(rest) = body.strip_prefix("||") {
        patterns.push(format!("https://{rest}"));
        if let Some(idx) = rest.find(['^', '*', '/']) {
            patterns.push(format!("https://{}/", &rest[..idx]));
        }
    } else {
        patterns.push(format!("https://host.invalid{body}"));
        patterns.push(format!("https://host.invalid/{body}"));
    }
    for p in patterns {
        let url = collapse(p.replace('*', "z").replace('^', "/"));
        if !url.is_empty() && url.starts_with("http") {
            for kind in ["xhr", "script", "image"] {
                out.push((url.clone(), "https://s.com/".to_string(), kind));
            }
        }
    }
    out
}

fn build(rule: &str, extra: &[&str]) -> adblock::Engine {
    let mut fs = adblock::FilterSet::new(true);
    let _ = fs.add_filter_list(rule.to_string(), ParseOptions::default());
    for e in extra {
        let _ = fs.add_filter_list((*e).to_string(), ParseOptions::default());
    }
    adblock::Engine::new_with_filter_set(fs)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Block,
    Exception,
    Pass,
}

fn outcome(engine: &adblock::Engine, req: &Request) -> Outcome {
    let r = engine.check_network_request(req);
    if r.filter.is_some() {
        if r.exception.is_some() {
            Outcome::Exception
        } else {
            Outcome::Block
        }
    } else {
        Outcome::Pass
    }
}

fn probe_set(
    rule: &str,
    extra: &[&str],
    derived: &[(String, String, &'static str)],
) -> Vec<Outcome> {
    let engine = build(rule, extra);
    let mut out = Vec::with_capacity(STRUCTURAL_PROBES.len() + derived.len());
    for p in STRUCTURAL_PROBES {
        match Request::new(p.url, p.source, p.kind, "get") {
            Ok(r) => out.push(outcome(&engine, &r)),
            Err(_) => out.push(Outcome::Pass),
        }
    }
    for (u, s, k) in derived {
        match Request::new(u, s, k, "get") {
            Ok(r) => out.push(outcome(&engine, &r)),
            Err(_) => out.push(Outcome::Pass),
        }
    }
    out
}

/// Result of attempting to repair a rule that the engine accepts but mishandles.
#[derive(Debug, Clone)]
pub enum Rewrite {
    /// The repair is behaviourally identical on the probe corpus.
    Equivalent(String),
    /// The repair changes behaviour; the caller must decide.
    BehaviourChange { rule: String, note: &'static str },
    /// No repair found.
    Impossible(&'static str),
}

/// `||host^/path` compiles to a pattern anchored at a separator that can never match,
/// because the caret is consumed as a separator and the following `/` then requires a
/// second separator. `||host/path` is the form the author meant.
pub fn try_repair_caret_path(rule: &str) -> Option<Rewrite> {
    let exception = rule.starts_with("@@");
    let body = if exception { &rule[2..] } else { rule };
    let dollar = body.rfind('$');
    let (pattern, options) = match dollar {
        Some(i) => (&body[..i], Some(&body[i..])),
        None => (body, None),
    };
    if !pattern.starts_with("||") {
        return None;
    }
    let host_and_path = &pattern[2..];
    let caret = host_and_path.find('^')?;
    let after = &host_and_path[caret + 1..];
    // Only the pathological `^/` form. `^` followed by anything else is a legal
    // separator and does match.
    if !after.starts_with('/') {
        return None;
    }
    let new_pattern = format!("||{}{}", &host_and_path[..caret], after);
    let mut rebuilt = String::with_capacity(rule.len());
    if exception {
        rebuilt.push_str("@@");
    }
    rebuilt.push_str(&new_pattern);
    if let Some(o) = options {
        rebuilt.push_str(o);
    }
    Some(verify_repair(rule, &rebuilt))
}

/// `$important,$removeparam=x` is a known engine defect: the removeparam branch is
/// taken first, so the rule rewrites the URL but never blocks. Splitting into two
/// rules recovers the author's intent.
pub fn try_split_removeparam_important(rule: &str) -> Option<Rewrite> {
    if rule.starts_with("@@") {
        return None;
    }
    let dollar = rule.rfind('$')?;
    let opts = &rule[dollar + 1..];
    let parts: Vec<&str> = opts.split(',').collect();
    if !opts.split(',').any(|o| o == "important") {
        return None;
    }
    let remove: Vec<&str> = parts
        .iter()
        .filter(|o| o.starts_with("removeparam="))
        .copied()
        .collect();
    if remove.is_empty() {
        return None;
    }
    let remaining: Vec<&str> = parts
        .iter()
        .copied()
        .filter(|o| *o != "important")
        .collect();
    if remaining.is_empty() {
        return None;
    }
    let pattern = &rule[..dollar];
    let block = format!("{pattern}${}.important", remaining.join(","));
    let rewrite = format!("{pattern}${}", remaining.join(","));
    Some(verify_repair(&block, &rewrite))
}

/// Runs the rewrite pipeline for a single line.
pub fn rewrite_line(rule: &str) -> Rewrite {
    if let Some(r) = try_split_removeparam_important(rule) {
        return r;
    }
    if let Some(r) = try_repair_caret_path(rule) {
        return r;
    }
    Rewrite::Impossible("no-applicable-repair")
}

/// Establishes ground truth from the original and compares the candidate.
pub fn verify_repair(original: &str, candidate: &str) -> Rewrite {
    if parse_filter(candidate, true, ParseOptions::default()).is_err() {
        return Rewrite::Impossible("candidate-rejected-by-engine");
    }
    let derived = derived_probes(original);
    let before = probe_set(original, &[], &derived);
    let after = probe_set(candidate, &[], &derived);
    if before == after {
        Rewrite::Equivalent(candidate.to_string())
    } else {
        Rewrite::BehaviourChange {
            rule: candidate.to_string(),
            note: "differs-on-probe-corpus",
        }
    }
}

/// Attempts to find an equivalent textual form for a rule, searching a small set of
/// candidate transforms. Returns `None` when no candidate is provably equivalent.
pub fn find_equivalent(rule: &str, candidates: &[String]) -> Option<String> {
    let derived = derived_probes(rule);
    let baseline = probe_set(rule, &[], &derived);
    let mut seen = HashSet::new();
    for c in candidates {
        if !seen.insert(c.clone()) {
            continue;
        }
        if c == rule {
            continue;
        }
        if parse_filter(c, true, ParseOptions::default()).is_err() {
            continue;
        }
        if probe_set(c, &[], &derived) == baseline {
            return Some(c.clone());
        }
    }
    None
}

/// Convenience for callers that only need the parsed shape.
pub fn as_network(rule: &str) -> Option<NetworkFilter<'_>> {
    match parse_filter(rule, true, ParseOptions::default()) {
        Ok(ParsedLine::Network(nf)) => Some(nf),
        _ => None,
    }
}
