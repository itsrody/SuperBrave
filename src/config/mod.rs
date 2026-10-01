use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub lists: Vec<ListConfig>,
    #[serde(default)]
    pub output: OutputConfig,
    #[serde(default)]
    pub engine: EngineConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListConfig {
    pub name: String,
    pub url: String,
    #[serde(default = "default_format")]
    pub format: ListFormat,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub attribution: Option<String>,
    /// Whether rules from this list may be rewritten into engine-native form.
    #[serde(default)]
    pub rewritable: bool,
}

fn default_format() -> ListFormat {
    ListFormat::Standard
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ListFormat {
    Standard,
    Hosts,
}

impl ListFormat {
    pub fn as_adblock(self) -> adblock::lists::FilterFormat {
        match self {
            ListFormat::Standard => adblock::lists::FilterFormat::Standard,
            ListFormat::Hosts => adblock::lists::FilterFormat::Hosts,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OutputConfig {
    #[serde(default = "default_output_name")]
    pub filename: String,
    /// Emit a FlatBuffers-serialized engine blob alongside the text list.
    #[serde(default)]
    pub emit_engine_blob: bool,
    /// Emit per-bucket JSON reports.
    #[serde(default)]
    pub emit_reports: bool,
    /// `! Expires:` value written into the list header.
    #[serde(default = "default_expiry")]
    pub header_expiry_days: u8,
}

fn default_output_name() -> String {
    "SuperBrave.txt".to_string()
}

fn default_expiry() -> u8 {
    4
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            filename: default_output_name(),
            emit_engine_blob: false,
            emit_reports: true,
            header_expiry_days: default_expiry(),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
pub struct RegexConfig {
    #[serde(default)]
    pub policy: RegexPolicy,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum RegexPolicy {
    /// Reject any rule whose pattern compiles to a regex.
    Reject,
    #[default]
    /// Accept regex rules but flag them.
    Allow,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EngineConfig {
    /// Enable the `full-regex-handling` feature semantics.
    #[serde(default = "yes")]
    pub full_regex: bool,
    /// Enable `content-blocking` (accepts `$generichide` exceptions).
    #[serde(default = "yes")]
    pub content_blocking: bool,
    /// Enable `resource-assembler` (accepts `$redirect` and `##+js()` scriptlets).
    #[serde(default = "yes")]
    pub resources: bool,
    /// Policy applied to regex-bearing rules.
    #[serde(default)]
    pub regex: RegexConfig,
    /// Rewrite `||host^/path` into the equivalent matching form.
    #[serde(default = "yes")]
    pub rewrite_caret_path: bool,
    /// Rewrite generic cosmetic rules into domain-scoped equivalents where possible.
    #[serde(default = "yes")]
    pub rewrite_generic_cosmetic: bool,
    /// Drop rules that parse but are shadowed by a `@@` exception covering the same
    /// pattern with no domain constraint difference.
    #[serde(default = "yes")]
    pub drop_shadowed: bool,
}

fn yes() -> bool {
    true
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            full_regex: true,
            content_blocking: true,
            resources: true,
            regex: RegexConfig::default(),
            rewrite_caret_path: true,
            rewrite_generic_cosmetic: true,
            drop_shadowed: true,
        }
    }
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read config {}: {e}", path.display()))?;
        let cfg: Config = toml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("failed to parse config {}: {e}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> anyhow::Result<()> {
        let mut names = BTreeMap::new();
        for l in &self.lists {
            if l.name.trim().is_empty() {
                anyhow::bail!("list entry with empty name");
            }
            if names.insert(l.name.clone(), ()).is_some() {
                anyhow::bail!("duplicate list name: {}", l.name);
            }
            if !l.url.starts_with("https://") && !l.url.starts_with("http://") {
                anyhow::bail!("list {}: url must be http(s)", l.name);
            }
        }
        Ok(())
    }

    pub fn enabled_lists(&self) -> impl Iterator<Item = &ListConfig> {
        self.lists.iter().filter(|l| l.enabled)
    }
}
