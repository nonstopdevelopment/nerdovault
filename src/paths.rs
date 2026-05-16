use anyhow::{Context, Result};
use std::env;
use std::fs;
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub const SECURE_DIR_MODE: u32 = 0o700;
pub const SECURE_FILE_MODE: u32 = 0o600;

pub fn app_dir() -> Result<PathBuf> {
    if let Ok(path) = env::var("NERDOVAULT_HOME") {
        return Ok(PathBuf::from(path));
    }

    let home = env::var_os("HOME").context("could not determine home directory")?;
    Ok(PathBuf::from(home).join(".nerdovault"))
}

pub fn ensure_app_dir() -> Result<PathBuf> {
    let dir = app_dir()?;
    fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    secure_dir_permissions(&dir)?;
    Ok(dir)
}

pub fn database_path() -> Result<PathBuf> {
    Ok(ensure_app_dir()?.join("vault.sqlite3"))
}

#[cfg(unix)]
pub fn secure_dir_permissions(path: &std::path::Path) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(SECURE_DIR_MODE))
        .with_context(|| format!("failed to secure permissions on {}", path.display()))
}

#[cfg(not(unix))]
pub fn secure_dir_permissions(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
pub fn secure_file_permissions(path: &std::path::Path) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(SECURE_FILE_MODE))
        .with_context(|| format!("failed to secure permissions on {}", path.display()))
}

#[cfg(not(unix))]
pub fn secure_file_permissions(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
pub fn mode(path: &std::path::Path) -> Result<Option<u32>> {
    let metadata =
        fs::metadata(path).with_context(|| format!("failed to inspect {}", path.display()))?;
    Ok(Some(metadata.permissions().mode() & 0o777))
}

#[cfg(not(unix))]
pub fn mode(_path: &std::path::Path) -> Result<Option<u32>> {
    Ok(None)
}
