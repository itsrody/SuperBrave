use adblock::filters::network::{NetworkFilter, NetworkFilterMask, NetworkFilterMaskHelper};
use adblock::lists::{parse_filter, FilterParseError, ParseOptions, ParsedLine};
use serde::Serialize;
use std::collections::BTreeMap;

/// Classification of a single source line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// Parses and is safe to emit verbatim.
    Verified,
    /// Parses but carries options the engine ignores; a rewrite can recover intent.
    Rewritable,
    /// The engine rejects it.
    Unsupported,
    /// Not a rule at all (comment, blank, header).
    Ignored,
}

#[derive(Debug, Clone)]
pub struct RuleRecord {
    pub source: usize,
    pub source_name: String,
    pub line_no: usize,
    pub raw: String,
    pub verdict: Verdict,
    pub reason: Option<&'static str>,
    pub kind: RuleKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleKind {
    Network,
    Cosmetic,
    None,
}

/// The engine's own rejection reason, mapped to a stable slug for reporting.
pub fn reason_for(err: &FilterParseError) -> &'static str {
    match err {
        FilterParseError::Empty => "empty",
        FilterParseError::Unsupported => "unsupported-syntax",
        FilterParseError::InvalidExpiresInterval => "invalid-expires-interval",
        FilterParseError::Network(e) => match e {
            adblock::filters::network::NetworkFilterError::FilterParseError => "filter-parse-error",
            adblock::filters::network::NetworkFilterError::NegatedBadFilter => "negated-badfilter",
            adblock::filters::network::NetworkFilterError::NegatedImportant => "negated-important",
            adblock::filters::network::NetworkFilterError::NegatedOptionMatchCase => "negated-match-case",
            adblock::filters::network::NetworkFilterError::NegatedExplicitCancel => "negated-explicitcancel",
            adblock::filters::network::NetworkFilterError::NegatedRedirection => "negated-redirect",
            adblock::filters::network::NetworkFilterError::NegatedTag => "negated-tag",
            adblock::filters::network::NetworkFilterError::NegatedGenericHide => "negated-generichide",
            adblock::filters::network::NetworkFilterError::NegatedDocument => "negated-document",
            adblock::filters::network::NetworkFilterError::NegatedAll => "negated-all",
            adblock::filters::network::NetworkFilterError::GenericHideWithoutException => "generichide-without-exception",
            adblock::filters::network::NetworkFilterError::MethodWithGenerichide => "method-with-generichide",
            adblock::filters::network::NetworkFilterError::EmptyRedirection => "empty-redirect",
            adblock::filters::network::NetworkFilterError::EmptyRemoveparam => "empty-removeparam",
            adblock::filters::network::NetworkFilterError::NegatedRemoveparam => "negated-removeparam",
            adblock::filters::network::NetworkFilterError::RemoveparamWithException => "removeparam-with-exception",
            adblock::filters::network::NetworkFilterError::RemoveparamRegexUnsupported => "removeparam-regex-unsupported",
            adblock::filters::network::NetworkFilterError::RedirectionUrlInvalid => "redirect-url-invalid",
            adblock::filters::network::NetworkFilterError::MultipleModifierOptions => "multiple-modifier-options",
            adblock::filters::network::NetworkFilterError::UnrecognisedOption => "unrecognised-option",
            adblock::filters::network::NetworkFilterError::NoRegex => "no-regex",
            adblock::filters::network::NetworkFilterError::FullRegexUnsupported => "full-regex-unsupported",
            adblock::filters::network::NetworkFilterError::RegexParsingError(_) => "regex-parsing-error",
            adblock::filters::network::NetworkFilterError::PunycodeError => "punycode-error",
            adblock::filters::network::NetworkFilterError::CspWithContentType => "csp-with-content-type",
            adblock::filters::network::NetworkFilterError::MatchCaseWithoutFullRegex => "match-case-without-full-regex",
            adblock::filters::network::NetworkFilterError::NoSupportedDomains => "no-supported-domains",
            _ => "network-parse-error",
        },
        FilterParseError::Cosmetic(e) => match e {
            adblock::filters::cosmetic::CosmeticFilterError::PunycodeError => "punycode-error",
            adblock::filters::cosmetic::CosmeticFilterError::InvalidActionSpecifier => "invalid-action-specifier",
            adblock::filters::cosmetic::CosmeticFilterError::UnsupportedSyntax => "cosmetic-unsupported-syntax",
            adblock::filters::cosmetic::CosmeticFilterError::MissingSharp => "missing-sharp",
            adblock::filters::cosmetic::CosmeticFilterError::InvalidCssStyle => "invalid-css-style",
            adblock::filters::cosmetic::CosmeticFilterError::InvalidCssSelector => "invalid-css-selector",
            adblock::filters::cosmetic::CosmeticFilterError::GenericUnhide => "generic-unhide",
            adblock::filters::cosmetic::CosmeticFilterError::GenericScriptInject => "generic-script-inject",
            adblock::filters::cosmetic::CosmeticFilterError::GenericAction => "generic-action",
            adblock::filters::cosmetic::CosmeticFilterError::DoubleNegation => "double-negation",
            adblock::filters::cosmetic::CosmeticFilterError::EmptyRule => "empty-rule",
            adblock::filters::cosmetic::CosmeticFilterError::HtmlFilteringUnsupported => "html-filtering-unsupported",
            adblock::filters::cosmetic::CosmeticFilterError::InvalidScriptletArgs => "invalid-scriptlet-args",
            adblock::filters::cosmetic::CosmeticFilterError::LocationModifiersUnsupported => "location-modifiers-unsupported",
            adblock::filters::cosmetic::CosmeticFilterError::ProceduralFilterWithMultipleSelectors => "procedural-multiple-selectors",
        },
    }
}

/// Detects the `||host^/path` form. The caret consumes the separator and the
/// following `/` then demands a second one, so the pattern is unsatisfiable.
pub fn has_dead_caret_path(pattern: &str) -> bool {
    let body = pattern.strip_prefix("||").unwrap_or(pattern);
    matches!(body.find('^'), Some(i) if body[i + 1..].starts_with('/'))
}

/// Pattern half of a rule, with any exception marker removed.
fn pattern_part(rule: &str) -> &str {
    let body = rule.strip_prefix("@@").unwrap_or(rule);
    body.split('$').next().unwrap_or(body)
}

pub fn parse_options(format: adblock::lists::FilterFormat) -> ParseOptions {
    ParseOptions {
        format,
        rule_types: adblock::lists::RuleTypes::All,
        permissions: Default::default(),
    }
}

/// Tokenizes a network filter the same way the engine's `get_tokens` does, so we
/// can predict which rules land in the token-0 catch-all bucket.
pub fn engine_tokens(nf: &NetworkFilter<'_>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for part in nf.filter.iter() {
        let skip_last = (nf.is_plain() || nf.is_regex()) && !nf.is_right_anchor();
        let skip_first = nf.is_right_anchor();
        let parts = tokenize(part);
        let n = parts.len();
        for (i, t) in parts.into_iter().enumerate() {
            if i == 0 && skip_first {
                continue;
            }
            if skip_last && i + 1 == n {
                continue;
            }
            out.push(t);
        }
    }
    if !nf.mask.contains(NetworkFilterMask::IS_HOSTNAME_REGEX) {
        if let Some(h) = nf.hostname.as_deref() {
            out.extend(tokenize(h));
        }
    } else if let Some(h) = nf.hostname.as_deref() {
        if let Some(p) = h.rfind('.') {
            out.extend(tokenize(&h[..p]));
        }
    }
    out
}

fn tokenize(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in s.chars() {
        if c.is_alphanumeric() || c == '%' {
            cur.push(c);
        } else if !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// A rule the engine will linearly scan on every request.
pub fn is_catch_all(nf: &NetworkFilter<'_>) -> bool {
    if nf.opt_not_domains.is_none() {
        if let Some([_]) = nf.opt_domains.as_deref() {
            return false;
        }
    }
    if !engine_tokens(nf).is_empty() {
        return false;
    }
    !matches!(nf.opt_domains.as_deref(), Some(d) if !d.is_empty() && d.len() <= 256)
}

pub struct ClassifiedLine {
    pub verdict: Verdict,
    pub reason: Option<&'static str>,
    pub kind: RuleKind,
    pub inert: bool,
    pub catch_all: bool,
}

pub fn classify(line: &str, opts: ParseOptions) -> ClassifiedLine {
    let t = line.trim();
    if t.is_empty()
        || t.starts_with('!')
        || (t.starts_with('#') && t[1..].starts_with(char::is_whitespace))
        || t.starts_with("[Adblock")
    {
        return ClassifiedLine {
            verdict: Verdict::Ignored,
            reason: None,
            kind: RuleKind::None,
            inert: false,
            catch_all: false,
        };
    }
    match parse_filter(t, false, opts) {
        Ok(ParsedLine::Network(nf)) => {
            let inert = has_dead_caret_path(pattern_part(t));
            let catch_all = is_catch_all(&nf);
            ClassifiedLine {
                verdict: if inert {
                    Verdict::Rewritable
                } else {
                    Verdict::Verified
                },
                reason: if inert { Some("inert-option") } else { None },
                kind: RuleKind::Network,
                inert,
                catch_all,
            }
        }
        Ok(ParsedLine::Cosmetic(_)) => ClassifiedLine {
            verdict: Verdict::Verified,
            reason: None,
            kind: RuleKind::Cosmetic,
            inert: false,
            catch_all: false,
        },
        Err(e) => {
            let reason = reason_for(&e);
            ClassifiedLine {
                verdict: Verdict::Unsupported,
                reason: Some(reason),
                kind: RuleKind::None,
                inert: false,
                catch_all: false,
            }
        }
    }
}

#[derive(Debug, Default, Serialize)]
pub struct Tally {
    pub total: usize,
    pub verified: usize,
    pub rewritable: usize,
    pub unsupported: usize,
    pub ignored: usize,
    pub catch_all: usize,
    pub by_reason: BTreeMap<String, usize>,
}

impl Tally {
    pub fn record(&mut self, v: Verdict, reason: Option<&'static str>, catch_all: bool) {
        self.total += 1;
        match v {
            Verdict::Verified => self.verified += 1,
            Verdict::Rewritable => self.rewritable += 1,
            Verdict::Unsupported => self.unsupported += 1,
            Verdict::Ignored => self.ignored += 1,
        }
        if catch_all {
            self.catch_all += 1;
        }
        if let Some(r) = reason {
            *self.by_reason.entry(r.to_string()).or_default() += 1;
        }
    }
}
