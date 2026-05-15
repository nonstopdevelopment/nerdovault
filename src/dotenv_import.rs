use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ParsedEnv {
    pub entries: Vec<(String, String)>,
    pub duplicates: Vec<String>,
}

pub fn parse_env_file(path: &Path) -> Result<ParsedEnv> {
    let iter = dotenvy::from_path_iter(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    let mut duplicates = BTreeSet::new();

    for item in iter {
        let (key, value) = item.with_context(|| format!("failed to parse {}", path.display()))?;
        if !seen.insert(key.clone()) {
            duplicates.insert(key.clone());
        }
        entries.push((key, value));
    }

    Ok(ParsedEnv {
        entries,
        duplicates: duplicates.into_iter().collect(),
    })
}

pub fn confirm_import(parsed: &ParsedEnv, yes: bool) -> Result<bool> {
    println!("Will import {} key(s):", parsed.entries.len());
    for (key, _) in &parsed.entries {
        println!("  {key}");
    }
    if !parsed.duplicates.is_empty() {
        println!(
            "Warning: duplicate key(s) detected; the last value wins: {}",
            parsed.duplicates.join(", ")
        );
    }

    if yes {
        return Ok(true);
    }

    println!("Import these values? [y/N]");
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .context("failed to read confirmation")?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "YES"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parses_env_and_tracks_duplicates() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "A=one").unwrap();
        writeln!(file, "B=\"two\"").unwrap();
        writeln!(file, "A=three").unwrap();

        let parsed = parse_env_file(file.path()).unwrap();
        assert_eq!(parsed.entries.len(), 3);
        assert_eq!(parsed.entries[1], ("B".to_string(), "two".to_string()));
        assert_eq!(parsed.duplicates, vec!["A".to_string()]);
    }
}
