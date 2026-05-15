use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const MANIFEST_NAME: &str = ".nerdovault.toml";

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub project: String,
    #[serde(default)]
    pub required: Vec<String>,
    #[serde(default)]
    pub aliases: BTreeMap<String, String>,
}

pub fn write_default_manifest(dir: PathBuf) -> Result<PathBuf> {
    let path = dir.join(MANIFEST_NAME);
    if path.exists() {
        return Ok(path);
    }

    let project = dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("myapp")
        .to_string();
    let manifest = Manifest {
        project,
        required: Vec::new(),
        aliases: BTreeMap::new(),
    };
    write_manifest(&path, &manifest)?;
    Ok(path)
}

pub fn record_key_if_manifest_exists(project: &str, key: &str, alias: Option<&str>) -> Result<()> {
    let path = std::env::current_dir()?.join(MANIFEST_NAME);
    if !path.exists() {
        return Ok(());
    }

    let mut manifest = read_manifest(&path)?;
    if manifest.project.is_empty() {
        manifest.project = project.to_string();
    }
    if manifest.project == project && !manifest.required.iter().any(|existing| existing == key) {
        manifest.required.push(key.to_string());
        manifest.required.sort();
    }
    if let Some(alias) = alias {
        manifest.aliases.insert(key.to_string(), alias.to_string());
    }
    write_manifest(&path, &manifest)
}

pub fn read_manifest(path: &Path) -> Result<Manifest> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    toml::from_str(&contents).with_context(|| format!("failed to parse {}", path.display()))
}

fn write_manifest(path: &Path, manifest: &Manifest) -> Result<()> {
    let toml = toml::to_string_pretty(manifest).context("failed to encode manifest")?;
    std::fs::write(path, toml).with_context(|| format!("failed to write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_roundtrip_keeps_aliases_without_values() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(MANIFEST_NAME);
        let mut manifest = Manifest {
            project: "myapp".to_string(),
            required: vec!["XAI_API_KEY".to_string()],
            aliases: BTreeMap::new(),
        };
        manifest
            .aliases
            .insert("XAI_API_KEY".to_string(), "xai/api-key".to_string());

        write_manifest(&path, &manifest).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("XAI_API_KEY"));
        assert!(contents.contains("xai/api-key"));
        assert!(!contents.contains("sk-"));

        let parsed = read_manifest(&path).unwrap();
        assert_eq!(parsed.project, "myapp");
        assert_eq!(
            parsed.aliases.get("XAI_API_KEY").map(String::as_str),
            Some("xai/api-key")
        );
    }
}
