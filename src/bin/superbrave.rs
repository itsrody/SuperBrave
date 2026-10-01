use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "superbrave",
    version,
    about = "Generate a verified, engine-optimized filter list for the Brave adblock-rust engine"
)]
struct Cli {
    /// Path to the build configuration.
    #[arg(long, default_value = "config.toml", global = true)]
    config: PathBuf,
    /// Directory for downloaded source lists and metadata.
    #[arg(long, default_value = ".cache", global = true)]
    cache_dir: PathBuf,
    /// Directory for generated artifacts. Defaults to the repo root so the built
    /// list lands where the workflow and raw URLs expect it.
    #[arg(long, default_value = ".", global = true)]
    output_dir: PathBuf,
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand, Debug, Clone)]
enum Cmd {
    /// Download or refresh all enabled source lists.
    Fetch {
        #[arg(long)]
        force: bool,
    },
    /// Classify, repair, verify and emit the merged list.
    Build(BuildArgs),
    /// Fetch then build.
    All(BuildArgs),
    /// Report only; writes nothing.
    Analyze,
}

#[derive(clap::Args, Debug, Clone, Default)]
struct BuildArgs {
    /// Also emit a FlatBuffers-serialized engine blob alongside the list.
    #[arg(long)]
    engine_blob: bool,
    /// Skip the self-consistency gate that refuses to emit an unverified list.
    #[arg(long)]
    no_verify: bool,
}

impl BuildArgs {
    fn options(&self) -> superbrave::pipeline::Options {
        superbrave::pipeline::Options {
            verify: !self.no_verify,
            emit: true,
            engine_blob: self.engine_blob,
        }
    }
}

fn fetch_all(cfg: &superbrave::config::Config, cache_dir: &Path) -> Result<String> {
    use superbrave::fetch::Fetcher;
    let f = superbrave::fetch::HttpFetcher::new(Duration::from_secs(60));
    let mut lines = Vec::new();
    for l in cfg.enabled_lists() {
        match f.fetch(l, cache_dir) {
            Ok(superbrave::fetch::FetchOutcome::Fresh(s)) => lines.push(format!(
                "fetched {} ({} bytes, sha256 {})",
                s.name,
                s.bytes,
                &s.sha256[..16]
            )),
            Ok(superbrave::fetch::FetchOutcome::NotModified(s)) => {
                lines.push(format!("unchanged {} (sha256 {})", s.name, &s.sha256[..16]))
            }
            Err(e) => lines.push(format!("FAILED {}: {e}", l.name)),
        }
    }
    for l in &lines {
        if l.starts_with("FAILED") {
            log::error!("{l}");
        } else {
            log::info!("{l}");
        }
    }
    Ok(lines.join("\n"))
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    let cfg = superbrave::config::Config::load(&cli.config)?;

    match cli
        .command
        .clone()
        .unwrap_or(Cmd::All(BuildArgs::default()))
    {
        Cmd::Fetch { force } => {
            use superbrave::fetch::Fetcher;
            let f = superbrave::fetch::HttpFetcher::new(Duration::from_secs(60));
            for l in cfg.enabled_lists() {
                match f.fetch(l, &cli.cache_dir) {
                    Ok(superbrave::fetch::FetchOutcome::Fresh(s)) => log::info!(
                        "fetched {} ({} bytes, sha256 {})",
                        s.name,
                        s.bytes,
                        &s.sha256[..16]
                    ),
                    Ok(superbrave::fetch::FetchOutcome::NotModified(s)) => {
                        log::info!("unchanged {} (sha256 {})", s.name, &s.sha256[..16])
                    }
                    Err(e) => log::error!("{}: {e}", l.name),
                }
            }
            if force {
                log::info!("--force: ignoring cached validators");
            }
        }
        Cmd::Build(args) | Cmd::All(args) => {
            if matches!(cli.command, Some(Cmd::All(_))) {
                let out = fetch_all(&cfg, &cli.cache_dir)?;
                println!("{}", out);
            }
            let report =
                superbrave::pipeline::run(&cfg, &cli.cache_dir, &cli.output_dir, args.options())?;
            println!("{}", report.summary());
        }
        Cmd::Analyze => {
            // Classify and verify exactly as a build would, but write nothing.
            let report = superbrave::pipeline::run(
                &cfg,
                &cli.cache_dir,
                &cli.output_dir,
                superbrave::pipeline::Options {
                    verify: true,
                    emit: false,
                    engine_blob: false,
                },
            )?;
            println!("{}", report.summary());
        }
    }
    Ok(())
}
