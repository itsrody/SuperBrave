use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
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

#[derive(clap::Args, Debug, Default, Clone)]
struct BuildArgs {
    /// Also emit a FlatBuffers-serialized engine blob.
    #[arg(long)]
    engine_blob: bool,
    /// Run the behavioural equivalence suite before writing output.
    #[arg(long, default_value_t = true)]
    verify: bool,
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
            let _ = force;
        }
        Cmd::Analyze | Cmd::Build(_) | Cmd::All(_) => {
            let out = superbrave::pipeline::run(&cfg, &cli.cache_dir, &cli.output_dir, None)?;
            println!("{}", out.summary());
        }
    }
    Ok(())
}
