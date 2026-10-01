use crate::config::{Config, EngineConfig};
use crate::output::Emitter;
use crate::parse::{classify, parse_options, RuleKind, Tally, Verdict};
use crate::rewrite::{as_network, rewrite_line, Rewrite};
use adblock::filters::network::NetworkFilterMaskHelper;
use rayon::prelude::*;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::time::Instant;

#[derive(Debug, Default, Serialize)]
pub struct BuildOutcome {
    pub sources: Vec<SourceOutcome>,
    pub emitted_network: usize,
    pub emitted_cosmetic: usize,
    pub dropped_unsupported: usize,
    pub repaired_equivalent: usize,
    pub repaired_behaviour_change: usize,
    pub deduped: usize,
    pub catch_all_retained: usize,
    pub regex_rules: usize,
    /// Rules sampled by the self-consistency gate.
    pub verified_sampled: usize,
    /// Fraction of sampled rules that blocked their own pattern, 0.0 when the
    /// gate was skipped.
    pub self_consistency: f64,
    pub elapsed_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceOutcome {
    pub name: String,
    pub url: String,
    pub license: Option<String>,
    pub lines: usize,
    pub network: usize,
    pub cosmetic: usize,
    pub unsupported: usize,
    pub ignored: usize,
    pub rewritable: usize,
    pub by_reason: BTreeMap<String, usize>,
}

pub struct Report {
    pub outcome: BuildOutcome,
}

impl Report {
    pub fn summary(&self) -> String {
        let o = &self.outcome;
        let mut s = String::new();
        s.push_str("SuperBrave build\n");
        s.push_str(&format!("  elapsed              {} ms\n", o.elapsed_ms));
        s.push_str(&format!("  network rules        {}\n", o.emitted_network));
        s.push_str(&format!("  cosmetic rules       {}\n", o.emitted_cosmetic));
        s.push_str(&format!(
            "  dropped unsupported  {}\n",
            o.dropped_unsupported
        ));
        s.push_str(&format!(
            "  repaired (verified)  {}\n",
            o.repaired_equivalent
        ));
        if o.repaired_behaviour_change > 0 {
            s.push_str(&format!(
                "  repaired (changed)   {}\n",
                o.repaired_behaviour_change
            ));
        }
        s.push_str(&format!("  deduplicated         {}\n", o.deduped));
        s.push_str(&format!(
            "  catch-all retained   {}\n",
            o.catch_all_retained
        ));
        s.push_str(&format!("  regex rules          {}\n", o.regex_rules));
        if o.verified_sampled > 0 {
            s.push_str(&format!(
                "  self-consistency     {:.1}% of {} sampled\n",
                o.self_consistency * 100.0,
                o.verified_sampled
            ));
        }
        s
    }
}

/// A rule that survived verification, with provenance.
#[derive(Debug, Clone)]
pub struct Accepted {
    pub text: String,
    pub source: usize,
    pub origin: &'static str,
}

/// Runs the whole pipeline.
/// One source list after classification: the rules it contributed plus its stats.
struct Parsed {
    kept: Vec<Accepted>,
    outcome: SourceOutcome,
    catch_all: usize,
    regex_rules: usize,
}

/// Knobs the CLI exposes. Kept explicit so CI and local runs take the same path.
#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Run the self-consistency gate. Off means emit without checking.
    pub verify: bool,
    /// Write the list and report to disk. Off means classify and verify only.
    pub emit: bool,
    /// Also write the serialized engine blob.
    pub engine_blob: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            verify: true,
            emit: true,
            engine_blob: false,
        }
    }
}

pub fn run(
    cfg: &Config,
    cache_dir: &Path,
    output_dir: &Path,
    options: Options,
) -> anyhow::Result<Report> {
    let started = Instant::now();
    let lists: Vec<_> = cfg.enabled_lists().cloned().collect();

    // Stage 1: parse + classify each source in parallel.
    let parsed: Vec<Parsed> = lists
        .par_iter()
        .enumerate()
        .map(|(idx, list)| {
            let (text, format) = crate::fetch::read_cached_list(list, cache_dir)
                .unwrap_or_else(|e| panic!("{}: {e}", list.name));
            let opts = parse_options(format.as_adblock());
            let mut kept = Vec::new();
            let mut tally = Tally::default();
            let (mut network, mut cosmetic) = (0usize, 0usize);
            let mut catch_all = 0usize;
            let mut regex_rules = 0usize;
            let mut lines = 0usize;

            for raw in text.lines() {
                lines += 1;
                let c = classify(raw, opts);
                let is_regex = c.kind == RuleKind::Network
                    && as_network(raw).map(|nf| nf.is_regex()).unwrap_or(false);
                if is_regex {
                    regex_rules += 1;
                    if cfg.engine.regex.policy == crate::config::RegexPolicy::Reject {
                        tally.record(Verdict::Unsupported, Some("regex-policy-reject"), false);
                        continue;
                    }
                }
                tally.record(c.verdict, c.reason, c.catch_all);
                match c.verdict {
                    Verdict::Verified => {
                        if c.kind == RuleKind::Network {
                            network += 1
                        } else {
                            cosmetic += 1
                        }
                        if c.catch_all {
                            catch_all += 1;
                        }
                        kept.push(Accepted {
                            text: raw.trim().to_string(),
                            source: idx,
                            origin: "verbatim",
                        });
                    }
                    Verdict::Rewritable => match rewrite_line(raw.trim()) {
                        Rewrite::Equivalent(t) => {
                            let nc = classify(&t, opts);
                            if nc.verdict == Verdict::Verified {
                                if nc.kind == RuleKind::Network {
                                    network += 1
                                } else {
                                    cosmetic += 1
                                }
                                kept.push(Accepted {
                                    text: t,
                                    source: idx,
                                    origin: "repaired",
                                });
                            }
                        }
                        Rewrite::BehaviourChange { rule, .. } => {
                            let nc = classify(&rule, opts);
                            if nc.verdict == Verdict::Verified {
                                kept.push(Accepted {
                                    text: rule,
                                    source: idx,
                                    origin: "repaired-changed",
                                });
                            }
                        }
                        Rewrite::Impossible(_) => {}
                    },
                    Verdict::Unsupported | Verdict::Ignored => {}
                }
            }

            Parsed {
                kept,
                outcome: SourceOutcome {
                    name: list.name.clone(),
                    url: list.url.clone(),
                    license: list.license.clone(),
                    lines,
                    network,
                    cosmetic,
                    unsupported: tally.unsupported,
                    ignored: tally.ignored,
                    rewritable: tally.rewritable,
                    by_reason: tally.by_reason,
                },
                catch_all,
                regex_rules,
            }
        })
        .collect();

    // Stage 2: merge, preserving source priority (earlier config wins on duplicates).
    let mut seen: HashMap<String, ()> = HashMap::with_capacity(32768);
    let mut merged: Vec<Accepted> = Vec::new();
    let mut deduped = 0usize;
    for p in parsed.iter() {
        for a in &p.kept {
            if seen.insert(a.text.clone(), ()).is_some() {
                deduped += 1;
                continue;
            }
            merged.push(a.clone());
        }
    }

    // Stage 3: verify the merged list end to end.
    let mut net_text = String::with_capacity(merged.len() * 48);
    let mut cos_text = String::with_capacity(merged.len() * 64);
    let (mut n, mut c) = (0usize, 0usize);
    for a in &merged {
        if a.text.contains("##")
            || a.text.contains("#@")
            || a.text.contains("#?")
            || a.text.contains("#$")
        {
            cos_text.push_str(&a.text);
            cos_text.push('\n');
            c += 1;
        } else {
            net_text.push_str(&a.text);
            net_text.push('\n');
            n += 1;
        }
    }
    let built = crate::verify::compile(&net_text, &cos_text);
    log::info!(
        "compiled {} network + {} cosmetic rules in {} us",
        built.network_rules,
        built.cosmetic_rules,
        built.build_micros
    );

    // Stage 3b: self-consistency. Rules that parse but can never match are the
    // main silent-failure mode, so sample the emitted list and check each rule
    // blocks the request its own pattern describes.
    let check = crate::verify::self_consistency(&built.engine, &net_text, 4000);
    log::info!(
        "self-consistency: {}/{} sampled rules block their own pattern ({:.1}%)",
        check.blocked,
        check.sampled,
        check.ratio() * 100.0
    );
    for m in &check.misses {
        log::warn!("never matches: {m}");
    }
    if options.verify && n > 0 && check.sampled > 0 && check.ratio() < 0.5 {
        anyhow::bail!(
            "only {:.1}% of sampled rules block their own pattern; refusing to emit",
            check.ratio() * 100.0
        );
    }

    if !options.emit {
        log::info!("emit disabled; stopping after verification");
        return Ok(Report {
            outcome: outcome_from(&parsed, &merged, n, c, deduped, check, started),
        });
    }

    // Stage 4: emit.
    let emitter = Emitter::new(
        &cfg.output,
        &engine_describe(&cfg.engine),
        options.engine_blob,
    );
    let artifacts = emitter.write(output_dir, &net_text, &cos_text, &built)?;
    for a in &artifacts {
        log::info!("wrote {}", a.path.display());
    }
    if cfg.output.emit_reports {
        emitter.write_report(
            output_dir,
            &parsed.iter().map(|p| &p.outcome).collect::<Vec<_>>(),
        )?;
    }

    Ok(Report {
        outcome: outcome_from(&parsed, &merged, n, c, deduped, check, started),
    })
}

type ParsedList = Vec<Parsed>;

fn outcome_from(
    parsed: &ParsedList,
    merged: &[Accepted],
    n: usize,
    c: usize,
    deduped: usize,
    check: crate::verify::SelfCheck,
    started: Instant,
) -> BuildOutcome {
    BuildOutcome {
        sources: parsed.iter().map(|p| p.outcome.clone()).collect(),
        emitted_network: n,
        emitted_cosmetic: c,
        dropped_unsupported: parsed.iter().map(|p| p.outcome.unsupported).sum(),
        repaired_equivalent: merged.iter().filter(|a| a.origin == "repaired").count(),
        repaired_behaviour_change: merged
            .iter()
            .filter(|a| a.origin == "repaired-changed")
            .count(),
        deduped,
        catch_all_retained: parsed.iter().map(|p| p.catch_all).sum(),
        regex_rules: parsed.iter().map(|p| p.regex_rules).sum(),
        verified_sampled: check.sampled,
        self_consistency: check.ratio(),
        elapsed_ms: started.elapsed().as_millis(),
    }
}

fn engine_describe(cfg: &EngineConfig) -> String {
    let mut feats = Vec::new();
    if cfg.full_regex {
        feats.push("full-regex-handling");
    }
    if cfg.content_blocking {
        feats.push("content-blocking");
    }
    if cfg.resources {
        feats.push("resource-assembler");
    }
    feats.push("css-validation");
    feats.join(",")
}
