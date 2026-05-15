use crate::audit::AuditEvent;
use crate::crypto::EncryptedValue;
use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct SecretRow {
    pub key: String,
    pub alias_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StoredSecret {
    pub key: String,
    pub encrypted: Option<EncryptedValue>,
    pub alias_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StoredAlias {
    pub encrypted: Option<EncryptedValue>,
}

pub struct Store {
    conn: Connection,
    path: PathBuf,
}

impl Store {
    pub fn open(path: PathBuf) -> Result<Self> {
        let conn = Connection::open(&path)
            .with_context(|| format!("failed to open {}", path.display()))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let store = Self { conn, path };
        store.migrate()?;
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS projects (
                name TEXT PRIMARY KEY,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS aliases (
                name TEXT PRIMARY KEY,
                nonce TEXT,
                ciphertext TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS project_secrets (
                project TEXT NOT NULL,
                key_name TEXT NOT NULL,
                nonce TEXT,
                ciphertext TEXT,
                alias_name TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (project, key_name),
                FOREIGN KEY(project) REFERENCES projects(name) ON DELETE CASCADE,
                FOREIGN KEY(alias_name) REFERENCES aliases(name) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                event TEXT NOT NULL,
                project TEXT,
                key_name TEXT,
                detail TEXT
            );
            "#,
        )?;
        Ok(())
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO settings(key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT value FROM settings WHERE key=?1",
                params![key],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn create_project(&self, name: &str) -> Result<()> {
        let now = now();
        self.conn.execute(
            "INSERT OR IGNORE INTO projects(name, created_at) VALUES (?1, ?2)",
            params![name, now],
        )?;
        Ok(())
    }

    pub fn list_projects(&self) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name FROM projects ORDER BY name COLLATE NOCASE")?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        rows.collect::<rusqlite::Result<Vec<String>>>()
            .map_err(Into::into)
    }

    pub fn delete_project(&self, name: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM projects WHERE name=?1", params![name])?;
        Ok(())
    }

    pub fn set_project_secret(
        &self,
        project: &str,
        key: &str,
        encrypted: &EncryptedValue,
    ) -> Result<()> {
        self.create_project(project)?;
        let now = now();
        self.conn.execute(
            r#"
            INSERT INTO project_secrets(project, key_name, nonce, ciphertext, alias_name, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?5)
            ON CONFLICT(project, key_name) DO UPDATE SET
                nonce=excluded.nonce,
                ciphertext=excluded.ciphertext,
                alias_name=NULL,
                updated_at=excluded.updated_at
            "#,
            params![
                project,
                key,
                encrypted.nonce_b64,
                encrypted.ciphertext_b64,
                now
            ],
        )?;
        Ok(())
    }

    pub fn list_project_secrets(&self, project: &str) -> Result<Vec<SecretRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT key_name, alias_name FROM project_secrets
             WHERE project=?1 ORDER BY key_name COLLATE NOCASE",
        )?;
        let rows = stmt.query_map(params![project], |row| {
            Ok(SecretRow {
                key: row.get(0)?,
                alias_name: row.get(1)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<SecretRow>>>()
            .map_err(Into::into)
    }

    pub fn get_project_secret(&self, project: &str, key: &str) -> Result<Option<StoredSecret>> {
        self.conn
            .query_row(
                "SELECT key_name, nonce, ciphertext, alias_name FROM project_secrets
                 WHERE project=?1 AND key_name=?2",
                params![project, key],
                |row| {
                    let nonce: Option<String> = row.get(1)?;
                    let ciphertext: Option<String> = row.get(2)?;
                    Ok(StoredSecret {
                        key: row.get(0)?,
                        encrypted: match (nonce, ciphertext) {
                            (Some(nonce_b64), Some(ciphertext_b64)) => Some(EncryptedValue {
                                nonce_b64,
                                ciphertext_b64,
                            }),
                            _ => None,
                        },
                        alias_name: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn all_project_secrets(&self, project: &str) -> Result<Vec<StoredSecret>> {
        let mut stmt = self.conn.prepare(
            "SELECT key_name, nonce, ciphertext, alias_name FROM project_secrets
             WHERE project=?1 ORDER BY key_name COLLATE NOCASE",
        )?;
        let rows = stmt.query_map(params![project], |row| {
            let nonce: Option<String> = row.get(1)?;
            let ciphertext: Option<String> = row.get(2)?;
            Ok(StoredSecret {
                key: row.get(0)?,
                encrypted: match (nonce, ciphertext) {
                    (Some(nonce_b64), Some(ciphertext_b64)) => Some(EncryptedValue {
                        nonce_b64,
                        ciphertext_b64,
                    }),
                    _ => None,
                },
                alias_name: row.get(3)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<StoredSecret>>>()
            .map_err(Into::into)
    }

    pub fn delete_project_secret(&self, project: &str, key: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM project_secrets WHERE project=?1 AND key_name=?2",
            params![project, key],
        )?;
        Ok(())
    }

    pub fn create_alias(&self, name: &str) -> Result<()> {
        let now = now();
        self.conn.execute(
            "INSERT OR IGNORE INTO aliases(name, created_at, updated_at) VALUES (?1, ?2, ?2)",
            params![name, now],
        )?;
        Ok(())
    }

    pub fn set_alias_secret(&self, name: &str, encrypted: &EncryptedValue) -> Result<()> {
        let now = now();
        self.conn.execute(
            r#"
            INSERT INTO aliases(name, nonce, ciphertext, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?4)
            ON CONFLICT(name) DO UPDATE SET
                nonce=excluded.nonce,
                ciphertext=excluded.ciphertext,
                updated_at=excluded.updated_at
            "#,
            params![name, encrypted.nonce_b64, encrypted.ciphertext_b64, now],
        )?;
        Ok(())
    }

    pub fn list_aliases(&self) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name FROM aliases ORDER BY name COLLATE NOCASE")?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        rows.collect::<rusqlite::Result<Vec<String>>>()
            .map_err(Into::into)
    }

    pub fn get_alias(&self, name: &str) -> Result<Option<StoredAlias>> {
        self.conn
            .query_row(
                "SELECT nonce, ciphertext FROM aliases WHERE name=?1",
                params![name],
                |row| {
                    let nonce: Option<String> = row.get(0)?;
                    let ciphertext: Option<String> = row.get(1)?;
                    Ok(StoredAlias {
                        encrypted: match (nonce, ciphertext) {
                            (Some(nonce_b64), Some(ciphertext_b64)) => Some(EncryptedValue {
                                nonce_b64,
                                ciphertext_b64,
                            }),
                            _ => None,
                        },
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn delete_alias(&self, name: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM aliases WHERE name=?1", params![name])?;
        Ok(())
    }

    pub fn link_alias(&self, project: &str, key: &str, alias: &str) -> Result<()> {
        self.create_project(project)?;
        let now = now();
        self.conn.execute(
            r#"
            INSERT INTO project_secrets(project, key_name, nonce, ciphertext, alias_name, created_at, updated_at)
            VALUES (?1, ?2, NULL, NULL, ?3, ?4, ?4)
            ON CONFLICT(project, key_name) DO UPDATE SET
                nonce=NULL,
                ciphertext=NULL,
                alias_name=excluded.alias_name,
                updated_at=excluded.updated_at
            "#,
            params![project, key, alias, now],
        )?;
        Ok(())
    }

    pub fn record_audit(
        &self,
        event: &str,
        project: Option<&str>,
        key_name: Option<&str>,
        detail: Option<&str>,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO audit_events(ts, event, project, key_name, detail)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![now(), event, project, key_name, detail],
        )?;
        Ok(())
    }

    pub fn audit_events(&self, limit: usize) -> Result<Vec<AuditEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT ts, event, project, key_name, detail FROM audit_events
             ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(AuditEvent {
                ts: row.get(0)?,
                event: row.get(1)?,
                project: row.get(2)?,
                key_name: row.get(3)?,
                detail: row.get(4)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<AuditEvent>>>()
            .map_err(Into::into)
    }
}

fn now() -> String {
    Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_projects_and_links_aliases() {
        let db = tempfile::NamedTempFile::new().unwrap();
        let store = Store::open(db.path().to_path_buf()).unwrap();
        let encrypted = EncryptedValue {
            nonce_b64: "nonce".to_string(),
            ciphertext_b64: "cipher".to_string(),
        };

        store.create_project("app").unwrap();
        store.set_alias_secret("xai/api-key", &encrypted).unwrap();
        store
            .link_alias("app", "XAI_API_KEY", "xai/api-key")
            .unwrap();

        let secrets = store.list_project_secrets("app").unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].alias_name.as_deref(), Some("xai/api-key"));
        assert_eq!(store.list_projects().unwrap(), vec!["app".to_string()]);
    }
}
