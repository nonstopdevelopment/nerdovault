use anyhow::Result;
use regex::Regex;
use std::fmt;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub struct Finding {
    pub path: PathBuf,
    pub line: Option<usize>,
    pub reason: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(f, "{}:{line}: {}", self.path.display(), self.reason),
            None => write!(f, "{}: {}", self.path.display(), self.reason),
        }
    }
}

pub fn scan_path(path: &Path) -> Result<Vec<Finding>> {
    let secret_pattern = Regex::new(
        r#"(?i)(api[_-]?key|secret|token|password|private[_-]?key)\s*=\s*['"]?[A-Za-z0-9_/\-+=:.]{16,}"#,
    )?;
    let mut findings = Vec::new();

    for entry in WalkDir::new(path)
        .into_iter()
        .filter_entry(|entry| !is_ignored_dir(entry.path()))
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let file_name = entry.file_name().to_string_lossy();
        let is_env = file_name == ".env" || file_name.starts_with(".env.");
        if is_env {
            findings.push(Finding {
                path: entry.path().to_path_buf(),
                line: None,
                reason: ".env file present".to_string(),
            });
        }

        if entry.metadata().map(|meta| meta.len()).unwrap_or(0) > 1_000_000 {
            continue;
        }
        let Ok(contents) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        for (idx, line) in contents.lines().enumerate() {
            if secret_pattern.is_match(line) {
                findings.push(Finding {
                    path: entry.path().to_path_buf(),
                    line: Some(idx + 1),
                    reason: "possible secret assignment".to_string(),
                });
            }
        }
    }

    Ok(findings)
}

fn is_ignored_dir(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    matches!(
        name,
        ".git" | "target" | "node_modules" | ".next" | "dist" | "build"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn finds_env_files_and_secret_assignments() {
        let dir = tempfile::tempdir().unwrap();
        let env_path = dir.path().join(".env");
        std::fs::write(
            &env_path,
            format!("{}={}", "XAI_API_KEY", "aaaaaaaaaaaaaaaaaaaa"),
        )
        .unwrap();
        let mut source = std::fs::File::create(dir.path().join("app.js")).unwrap();
        let benign_line = "const token = 'nope';";
        let secret_key = "SECRET_TOKEN";
        let secret_value = "bbbbbbbbbbbbbbbbbbbb";
        writeln!(source, "{benign_line}\n{secret_key}={secret_value}").unwrap();

        let findings = scan_path(dir.path()).unwrap();
        assert!(findings
            .iter()
            .any(|finding| finding.reason == ".env file present"));
        assert!(findings
            .iter()
            .any(|finding| finding.reason == "possible secret assignment"));
    }
}
