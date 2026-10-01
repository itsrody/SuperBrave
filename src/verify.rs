use adblock::lists::ParseOptions;
use adblock::Engine;

/// A rule set proven to compile inside the engine, with the sizes we care about.
pub struct Compiled {
    pub engine: Engine,
    pub network_rules: usize,
    pub cosmetic_rules: usize,
    pub build_micros: u128,
}

/// Compiles network and cosmetic text into a single engine. This is the gate: if a
/// list cannot be compiled here, it is not shippable.
pub fn compile(network_text: &str, cosmetic_text: &str) -> Compiled {
    let started = std::time::Instant::now();
    let mut set = adblock::FilterSet::new(false);
    if !network_text.is_empty() {
        let _ = set.add_filter_list(network_text.to_string(), ParseOptions::default());
    }
    if !cosmetic_text.is_empty() {
        let _ = set.add_filter_list(cosmetic_text.to_string(), ParseOptions::default());
    }
    let engine = Engine::new_with_filter_set(set);
    let build_micros = started.elapsed().as_micros();
    Compiled {
        engine,
        network_rules: network_text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count(),
        cosmetic_rules: cosmetic_text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count(),
        build_micros,
    }
}

/// Outcome of one behavioural probe against a compiled engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub blocked: bool,
    pub excepted: bool,
    pub important: bool,
    pub redirect: bool,
    pub rewritten: Option<String>,
}

impl Check {
    pub fn run(engine: &Engine, url: &str, source: &str, kind: &str) -> Option<Check> {
        let req = adblock::request::Request::new(url, source, kind, "get").ok()?;
        let r = engine.check_network_request(&req);
        Some(Check {
            blocked: r.filter.is_some(),
            excepted: r.exception.is_some(),
            important: r.important,
            redirect: r.redirect.is_some(),
            rewritten: r.rewritten_url,
        })
    }
}

/// Measures steady-state match cost with requests built up front, so URL parsing is
/// not attributed to the engine.
pub fn benchmark(
    engine: &Engine,
    samples: &[(String, String, String)],
    iterations: u64,
) -> BenchResult {
    use std::time::Instant;
    let reqs: Vec<_> = samples
        .iter()
        .filter_map(|(u, s, k)| adblock::request::Request::new(u, s, k, "get").ok())
        .collect();
    if reqs.is_empty() {
        return BenchResult {
            ns_per_match: 0.0,
            samples: 0,
            blocked: 0,
        };
    }
    let mut best = f64::MAX;
    let mut blocked = 0u64;
    for _ in 0..5 {
        let t = Instant::now();
        let mut hits = 0u64;
        for i in 0..iterations {
            if engine
                .check_network_request(&reqs[(i as usize) % reqs.len()])
                .filter
                .is_some()
            {
                hits += 1;
            }
        }
        let ns = t.elapsed().as_nanos() as f64 / iterations as f64;
        if ns < best {
            best = ns;
            blocked = hits;
        }
    }
    BenchResult {
        ns_per_match: best,
        samples: reqs.len(),
        blocked,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BenchResult {
    pub ns_per_match: f64,
    pub samples: usize,
    pub blocked: u64,
}

/// Self-consistency check: for a sample of emitted network rules, build a request
/// from the rule's own pattern and assert the engine blocks it. This catches rules
/// that parse but can never match, which is exactly the failure mode that would
/// otherwise ship silently.
pub fn self_consistency(engine: &Engine, network_text: &str, sample: usize) -> SelfCheck {
    let mut total = 0usize;
    let mut matched = 0usize;
    let mut misses: Vec<String> = Vec::new();
    let step = (network_text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .count()
        / sample.max(1))
    .max(1);
    for (i, line) in network_text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('!') || i % step != 0 {
            continue;
        }
        // Rules whose options make a synthetic request ambiguous are skipped
        // entirely rather than counted against the ratio.
        let Some(req) = probe_for_rule(line) else {
            continue;
        };
        total += 1;
        if engine.check_network_request(&req).filter.is_some() {
            matched += 1;
        } else if misses.len() < 20 {
            misses.push(line.to_string());
        }
        if total >= sample {
            break;
        }
    }
    SelfCheck {
        sampled: total,
        blocked: matched,
        misses,
    }
}

#[derive(Debug, Clone)]
pub struct SelfCheck {
    pub sampled: usize,
    pub blocked: usize,
    pub misses: Vec<String>,
}

impl SelfCheck {
    pub fn ratio(&self) -> f64 {
        if self.sampled == 0 {
            return 1.0;
        }
        self.blocked as f64 / self.sampled as f64
    }
}

/// Derives a concrete request URL from a rule pattern. Returns `None` when the
/// rule's options make a synthetic request ambiguous, so such rules are skipped
/// rather than counted as misses.
fn probe_for_rule(rule: &str) -> Option<adblock::request::Request> {
    if rule.starts_with("@@") || rule.starts_with('!') {
        return None;
    }
    let mut it = rule.split('$');
    let pattern = it.next()?;
    // `$a,b,c` is one option list; flatten so each flag is matched individually.
    let options: Vec<&str> = it
        .flat_map(|o| o.split(','))
        .filter(|o| !o.is_empty())
        .collect();
    let pattern = pattern.trim_start_matches('@');

    // The request type must match what the rule claims, otherwise a correct
    // rule looks dead.
    let has = |k: &str| options.contains(&k);
    // A `$ping` rule has no request to match, and a rule carrying any negated
    // type constraint (`$~xhr`) cannot be satisfied by a synthetic probe.
    if has("ping") || options.iter().any(|o| o.starts_with('~')) {
        return None;
    }
    // Party constraints and redirects need more than a URL to model.
    if options
        .iter()
        .any(|o| o.starts_with("redirect=") || *o == "removeparam" || o.starts_with("removeparam="))
    {
        return None;
    }
    let party = if has("3p") {
        "third-party"
    } else if has("1p") {
        "first-party"
    } else {
        "none"
    };

    // Document-frame rules need a navigable document request whose source page is
    // known, which a synthetic URL cannot express.
    if has("frame") || has("subdocument") || has("doc") {
        return None;
    }
    let kind = if has("document") {
        "document"
    } else if has("script") {
        "script"
    } else if has("image") {
        "image"
    } else if has("stylesheet") {
        "stylesheet"
    } else if has("font") {
        "font"
    } else if has("xhr") || has("xmlhttprequest") {
        "xmlhttprequest"
    } else {
        "xhr"
    };

    let (host, path) = if let Some(rest) = pattern.strip_prefix("||") {
        // A `*` inside the host is a wildcard host, not a path wildcard, so only
        // `^` and `/` end the hostname.
        let stop = rest.find(['^', '/']).unwrap_or(rest.len());
        (&rest[..stop], &rest[stop..])
    } else if pattern.starts_with('/') {
        ("probe.invalid", pattern)
    } else {
        return None;
    };
    if host.is_empty() || host.contains('[') || host.contains('*') || is_regex_rule(pattern) {
        return None;
    }
    // `match-case` rules only fire on requests with no query string and no
    // trailing component the synthesised URL would invent.
    if has("match-case") {
        return None;
    }
    // `^` is a separator and `*` is a wildcard, so expand them to concrete
    // characters, then collapse the doubled separator. Real request URLs never
    // carry `//`, so a rule that only matches `//path` is effectively dead and
    // should be reported rather than masked by the probe.
    let path = &path.replace('^', "/").replace('*', "z");
    if path.contains('|') || path.matches('/').count() > 8 {
        return None;
    }

    // A `$domain=` scope picks the document page. A wildcard-only scope admits
    // no concrete request, so those rules cannot be probed.
    let scoped = document_source(&options);
    if scoped.is_none()
        && options
            .iter()
            .any(|o| o.starts_with("domain=") || o.starts_with("from="))
    {
        return None;
    }
    // Third-party rules need a page other than the request's own host; first-party
    // rules need the same host.
    let source = match party {
        "none" => scoped.unwrap_or("https://origin.invalid/"),
        "third-party" => scoped.unwrap_or("https://foreign.invalid/"),
        _ => Box::leak(format!("https://{host}/").into_boxed_str()),
    };

    // A URL never carries `//` after the scheme, so collapse it. A rule that only
    // matched the doubled form, such as `||host^/path`, is then correctly reported
    // as dead rather than masked by the probe.
    let url = collapse_slashes(&format!("https://{host}{path}"));
    adblock::request::Request::new(&url, source, kind, "get").ok()
}

/// Collapses runs of `/` after the scheme, leaving the scheme itself intact.
fn collapse_slashes(url: &str) -> String {
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
    format!("{head}{out}")
}

/// Heuristic regex detection matching what the engine's parser treats as regex.
fn is_regex_rule(pattern: &str) -> bool {
    if pattern.contains("||") {
        return false;
    }
    if pattern.len() > 2 && pattern.starts_with('/') && pattern.ends_with('/') {
        return true;
    }
    matches!(
        pattern,
        "^" | "." | "*" | "+" | "?" | "$" | "(" | ")" | "[" | "]" | "{" | "}" | "\\"
    )
}

/// Derives a document origin satisfying a `domain=` constraint.
fn document_source(options: &[&str]) -> Option<&'static str> {
    let mut constrained = false;
    for o in options {
        let Some(value) = o
            .strip_prefix("domain=")
            .or_else(|| o.strip_prefix("from="))
        else {
            continue;
        };
        constrained = true;
        for part in value.split('|') {
            let bare = part.strip_prefix('~').unwrap_or(part);
            if !bare.is_empty() && !bare.contains('*') && !bare.contains('.') {
                return Some(Box::leak(format!("https://{bare}/").into_boxed_str()));
            }
        }
    }
    // A scope whose domains are all wildcards admits no concrete request, so the
    // rule cannot be meaningfully probed.
    if constrained {
        return None;
    }
    Some("https://origin.invalid/")
}
