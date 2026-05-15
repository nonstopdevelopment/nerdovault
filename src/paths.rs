use anyhow::{Context, Result};
use directories::ProjectDirs;
use std::env;
use std::path::PathBuf;

pub fn app_dir() -> Result<PathBuf> {
    if let Ok(path) = env::var("NERDOVAULT_HOME") {
        return Ok(PathBuf::from(path));
    }

    let dirs = ProjectDirs::from("dev", "NonstopDev", "Nerdovault")
        .context("could not determine application support directory")?;
    Ok(dirs.data_local_dir().to_path_buf())
}

pub fn ensure_app_dir() -> Result<PathBuf> {
    let dir = app_dir()?;
    std::fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    Ok(dir)
}

pub fn database_path() -> Result<PathBuf> {
    Ok(ensure_app_dir()?.join("vault.sqlite3"))
}
