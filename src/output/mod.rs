use crate::config::OutputConfig;
use crate::verify::Compiled;
use anyhow::{Context, Result};
use serde::Serialize;
use std::io::Write;
use std::path::Path;

#[derive(Debug)]
pub struct Artifact {
    pub path: std::path::PathBuf,
    pub bytes: usize,
}

#[derive(Serialize)]
struct ListHeader<'a> {
    title: &'a str,
    version: &'a str,
    expires_days: u8,
    homepage: &'a str,
    generator: &'a str,
    engine_features: &'a str,
    network_rules: usize,
    cosmetic_rules: usize,
}

pub struct Emitter {
    cfg: OutputConfig,
    features: String,
    expiry_days: u8,
    title: &'static str,
    version: &'static str,
    homepage: &'static str,
}

impl Emitter {
    pub fn new(cfg: &OutputConfig, features: &str, engine_blob: bool) -> Self {
        let mut cfg = cfg.clone();
        cfg.emit_engine_blob = engine_blob;
        Self {
            expiry_days: cfg.header_expiry_days,
            cfg,
            features: features.to_string(),
            title: "SuperBrave",
            version: env!("CARGO_PKG_VERSION"),
            homepage: "https://github.com/superbrave/SuperBrave",
        }
    }

    pub fn write(
        &self,
        out_dir: &Path,
        network: &str,
        cosmetic: &str,
        compiled: &Compiled,
    ) -> Result<Vec<Artifact>> {
        std::fs::create_dir_all(out_dir)
            .with_context(|| format!("create {}", out_dir.display()))?;
        let path = out_dir.join(&self.cfg.filename);
        let mut body = String::with_capacity(network.len() + cosmetic.len() + 4096);
        let header = ListHeader {
            title: self.title,
            version: self.version,
            expires_days: self.expiry_days,
            homepage: self.homepage,
            generator: concat!("superbrave/", env!("CARGO_PKG_VERSION")),
            engine_features: &self.features,
            network_rules: compiled.network_rules,
            cosmetic_rules: compiled.cosmetic_rules,
        };
        body.push_str("[Adblock Plus 2.0]\n");
        body.push_str(&format!("! Title: {}\n", header.title));
        body.push_str(&format!("! Version: {}\n", header.version));
        body.push_str(&format!("! Expires: {} days\n", header.expires_days));
        body.push_str(&format!("! Homepage: {}\n", header.homepage));
        body.push_str(&format!("! Generator: {}\n", header.generator));
        body.push_str(&format!("! Engine-Features: {}\n", header.engine_features));
        body.push_str(&format!("! Network-Rules: {}\n", header.network_rules));
        body.push_str(&format!("! Cosmetic-Rules: {}\n", header.cosmetic_rules));
        body.push_str(
            "! Licence: see LICENCE.md -- derived from EasyList, uBlock Origin and AdGuard lists\n",
        );
        body.push('\n');

        body.push_str("! --- network rules ---\n");
        body.push_str(network);
        body.push('\n');
        body.push_str("! --- cosmetic rules ---\n");
        body.push_str(cosmetic);

        let bytes = body.len();
        let mut f =
            std::fs::File::create(&path).with_context(|| format!("create {}", path.display()))?;
        f.write_all(body.as_bytes())?;
        f.flush()?;
        let mut out = vec![Artifact { path, bytes }];

        if self.cfg.emit_engine_blob {
            let blob = compiled.engine.serialize();
            let bpath = out_dir.join("SuperBrave.fbs");
            std::fs::write(&bpath, &blob)?;
            out.push(Artifact {
                path: bpath,
                bytes: blob.len(),
            });
        }
        Ok(out)
    }

    pub fn write_report(
        &self,
        out_dir: &Path,
        sources: &[&crate::pipeline::SourceOutcome],
    ) -> Result<()> {
        let p = out_dir.join("report.json");
        let json = serde_json::to_string_pretty(sources)?;
        std::fs::write(&p, json)?;
        Ok(())
    }
}
