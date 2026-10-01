use crate::config::{ListConfig, ListFormat};
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Metadata returned by the uBO repository API for a specific filter list.
/// Used for provenance pinning so builds are reproducible.
#[derive(Debug, Clone)]
pub struct SourceSnapshot {
    pub name: String,
    pub url: String,
    pub bytes: usize,
    pub sha256: String,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub path: PathBuf,
}

pub trait Fetcher {
    fn fetch(&self, list: &ListConfig, cache_dir: &Path) -> Result<FetchOutcome>;
}

pub enum FetchOutcome {
    /// Freshly downloaded content.
    Fresh(SourceSnapshot),
    /// Server reported 304; the cached copy is still current.
    NotModified(SourceSnapshot),
}

pub struct HttpFetcher {
    agent: ureq::Agent,
}

impl Default for HttpFetcher {
    fn default() -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(60))
            .user_agent(concat!("SuperBrave/", env!("CARGO_PKG_VERSION")))
            .build();
        Self { agent }
    }
}

impl HttpFetcher {
    pub fn new(timeout: Duration) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(timeout)
            .user_agent(concat!("SuperBrave/", env!("CARGO_PKG_VERSION")))
            .build();
        Self { agent }
    }

    fn cache_paths(&self, cache_dir: &Path, list: &ListConfig) -> (PathBuf, PathBuf, PathBuf) {
        let base = cache_dir.join(sanitize(&list.name));
        (
            base.with_extension("txt"),
            base.with_extension("meta"),
            base.with_extension("gz"),
        )
    }

    fn load_meta(&self, meta_path: &Path) -> HashMap<String, String> {
        let mut map = HashMap::new();
        if let Ok(text) = std::fs::read_to_string(meta_path) {
            if let Ok(toml::Value::Table(t)) = text.parse::<toml::Value>() {
                for (k, v) in t {
                    if let Some(s) = v.as_str() {
                        map.insert(k, s.to_string());
                    }
                }
            }
        }
        map
    }

    fn write_meta(&self, meta_path: &Path, snap: &SourceSnapshot) -> Result<()> {
        let body = format!(
            "sha256 = \"{}\"\netag = \"{}\"\nlast_modified = \"{}\"\nbytes = {}\nurl = \"{}\"\n",
            snap.sha256,
            snap.etag.as_deref().unwrap_or(""),
            snap.last_modified.as_deref().unwrap_or(""),
            snap.bytes,
            snap.url,
        );
        let mut f = std::fs::File::create(meta_path)
            .with_context(|| format!("create {}", meta_path.display()))?;
        f.write_all(body.as_bytes())?;
        Ok(())
    }

    fn decompress_if_needed(&self, raw: &[u8]) -> Result<String> {
        if raw.len() >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
            use std::io::Read;
            let mut d = flate2::read::GzDecoder::new(raw);
            let mut out = String::new();
            d.read_to_string(&mut out)?;
            return Ok(out);
        }
        Ok(String::from_utf8_lossy(raw).into_owned())
    }
}

impl Fetcher for HttpFetcher {
    fn fetch(&self, list: &ListConfig, cache_dir: &Path) -> Result<FetchOutcome> {
        std::fs::create_dir_all(cache_dir)?;
        let (body_path, meta_path, _gz_path) = self.cache_paths(cache_dir, list);
        let meta = self.load_meta(&meta_path);

        let mut req = self.agent.get(&list.url);
        if let Some(etag) = meta.get("etag").filter(|s| !s.is_empty()) {
            req = req.set("If-None-Match", etag);
        }
        if let Some(lm) = meta.get("last_modified").filter(|s| !s.is_empty()) {
            req = req.set("If-Modified-Since", lm);
        }

        let resp = match req.call() {
            Ok(r) => r,
            Err(ureq::Error::Status(304, _)) => {
                let sha = meta.get("sha256").cloned().unwrap_or_default();
                let snap = SourceSnapshot {
                    name: list.name.clone(),
                    url: list.url.clone(),
                    bytes: meta.get("bytes").and_then(|s| s.parse().ok()).unwrap_or(0),
                    sha256: sha,
                    etag: meta.get("etag").cloned(),
                    last_modified: meta.get("last_modified").cloned(),
                    path: body_path,
                };
                return Ok(FetchOutcome::NotModified(snap));
            }
            Err(e) => return Err(anyhow::anyhow!("fetch {} failed: {e}", list.url)),
        };

        let etag = resp.header("ETag").map(str::to_string);
        let last_modified = resp.header("Last-Modified").map(str::to_string);
        const MAX_BYTES: u64 = 512 * 1024 * 1024;
        let mut capped: std::io::Take<_> = std::io::Read::take(resp.into_reader(), MAX_BYTES);
        let raw = capped.read_to_end_vec().context("read response body")?;
        let text = self.decompress_if_needed(&raw)?;

        let bytes = text.len();
        let sha256 = hex(&Sha256::digest(text.as_bytes()));
        std::fs::write(&body_path, &text)
            .with_context(|| format!("write {}", body_path.display()))?;
        let snap = SourceSnapshot {
            name: list.name.clone(),
            url: list.url.clone(),
            bytes,
            sha256,
            etag,
            last_modified,
            path: body_path,
        };
        self.write_meta(&meta_path, &snap)?;
        Ok(FetchOutcome::Fresh(snap))
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Reads a list from disk, honouring its declared format.
pub fn read_cached_list(list: &ListConfig, cache_dir: &Path) -> Result<(String, ListFormat)> {
    let path = cache_dir.join(sanitize(&list.name)).with_extension("txt");
    let text = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "read cached list {} (run `superbrave fetch` first)",
            path.display()
        )
    })?;
    Ok((text, list.format))
}

trait ReadVec {
    fn read_to_end_vec(&mut self) -> std::io::Result<Vec<u8>>;
}

impl<R: std::io::Read> ReadVec for R {
    fn read_to_end_vec(&mut self) -> std::io::Result<Vec<u8>> {
        let mut v = Vec::new();
        std::io::Read::read_to_end(self, &mut v)?;
        Ok(v)
    }
}
