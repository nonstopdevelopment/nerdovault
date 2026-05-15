use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

const HOOK: &str = r#"#!/bin/sh
set -eu

if git diff --cached --name-only | grep -E '(^|/)\.env(\.|$)' >/dev/null; then
  echo "nerdovault guard: refusing to commit .env files" >&2
  exit 1
fi

if git diff --cached --unified=0 | grep -E '^\+.*(API[_-]?KEY|SECRET|TOKEN|PASSWORD|PRIVATE[_-]?KEY)\s*=' >/dev/null; then
  echo "nerdovault guard: possible secret assignment in staged diff" >&2
  exit 1
fi
"#;

pub fn install_pre_commit_hook(cwd: PathBuf) -> Result<PathBuf> {
    let git_dir = find_git_dir(&cwd).context("not inside a git repository")?;
    let hooks_dir = git_dir.join("hooks");
    fs::create_dir_all(&hooks_dir)
        .with_context(|| format!("failed to create {}", hooks_dir.display()))?;
    let hook_path = hooks_dir.join("pre-commit");

    if hook_path.exists() {
        let current = fs::read_to_string(&hook_path).unwrap_or_default();
        if !current.contains("nerdovault guard") {
            bail!(
                "{} already exists and was not created by Nerdovault",
                hook_path.display()
            );
        }
    }

    fs::write(&hook_path, HOOK)
        .with_context(|| format!("failed to write {}", hook_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&hook_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&hook_path, perms)?;
    }

    Ok(hook_path)
}

fn find_git_dir(start: &Path) -> Option<PathBuf> {
    for dir in start.ancestors() {
        let git_dir = dir.join(".git");
        if git_dir.is_dir() {
            return Some(git_dir);
        }
    }
    None
}
