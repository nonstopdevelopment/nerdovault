use crate::audit::AuditEvent;
use crate::crypto;
use crate::dotenv_import;
use crate::keychain::{AccessPolicy, Keychain};
use crate::manifest;
use crate::paths;
use crate::store::{SecretRow, Store, StoredSecret};
use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::path::Path;
use zeroize::Zeroize;

const SETTING_ACCESS_POLICY: &str = "keychain_access_policy";
const SETTING_BIOMETRY_DOMAIN_STATE: &str = "biometry_domain_state";

pub struct Vault {
    store: Store,
}

impl Vault {
    pub fn open() -> Result<Self> {
        let db_path = paths::database_path()?;
        Ok(Self {
            store: Store::open(db_path)?,
        })
    }

    pub fn init(&self, biometry_current_set: bool) -> Result<()> {
        let policy = if biometry_current_set {
            AccessPolicy::BiometryCurrentSet
        } else {
            AccessPolicy::UserPresence
        };
        let domain_state = Keychain::authenticate(policy, "Initialize Nerdovault")?;
        let mut key = Keychain::load_or_create_master_key(policy)?;
        key.zeroize();
        self.store
            .set_setting(SETTING_ACCESS_POLICY, policy.as_str())?;
        if let Some(domain_state) = domain_state {
            self.store
                .set_setting(SETTING_BIOMETRY_DOMAIN_STATE, &domain_state)?;
        }
        self.store.record_audit(
            "init",
            None,
            None,
            Some(if biometry_current_set {
                "biometryCurrentSet"
            } else {
                "userPresence"
            }),
        )?;
        Ok(())
    }

    pub fn create_project(&self, name: &str) -> Result<()> {
        validate_name(name, "project")?;
        self.store.create_project(name)?;
        self.store
            .record_audit("project.create", Some(name), None, None)?;
        Ok(())
    }

    pub fn list_projects(&self) -> Result<Vec<String>> {
        self.store.list_projects()
    }

    pub fn delete_project(&self, name: &str) -> Result<()> {
        self.store.delete_project(name)?;
        self.store
            .record_audit("project.delete", Some(name), None, None)?;
        Ok(())
    }

    pub fn set_project_secret(&self, project: &str, key: &str, value: String) -> Result<()> {
        validate_name(project, "project")?;
        validate_env_key(key)?;
        let mut master_key = self.master_key(&format!("Set {key} for {project}"))?;
        let encrypted = crypto::encrypt(
            &master_key,
            &value,
            &crypto::project_secret_aad(project, key),
        )?;
        master_key.zeroize();
        self.store.set_project_secret(project, key, &encrypted)?;
        manifest::record_key_if_manifest_exists(project, key, None)?;
        self.store
            .record_audit("secret.set", Some(project), Some(key), None)?;
        Ok(())
    }

    pub fn list_project_secrets(&self, project: &str) -> Result<Vec<SecretRow>> {
        self.store.list_project_secrets(project)
    }

    pub fn ensure_project_secret_exists(&self, project: &str, key: &str) -> Result<()> {
        if self.store.get_project_secret(project, key)?.is_none() {
            bail!("secret {key} does not exist in project {project}");
        }
        self.store
            .record_audit("secret.get.redacted", Some(project), Some(key), None)?;
        Ok(())
    }

    pub fn reveal_project_secret(&self, project: &str, key: &str) -> Result<String> {
        let secret = self
            .store
            .get_project_secret(project, key)?
            .with_context(|| format!("secret {key} does not exist in project {project}"))?;
        let mut master_key = self.master_key(&format!("Reveal {key} from {project}"))?;
        let value = self.decrypt_stored_secret(&master_key, project, &secret)?;
        master_key.zeroize();
        self.store
            .record_audit("secret.reveal", Some(project), Some(key), None)?;
        Ok(value)
    }

    pub fn delete_project_secret(&self, project: &str, key: &str) -> Result<()> {
        self.store.delete_project_secret(project, key)?;
        self.store
            .record_audit("secret.delete", Some(project), Some(key), None)?;
        Ok(())
    }

    pub fn resolve_project_env(&self, project: &str) -> Result<BTreeMap<String, String>> {
        let secrets = self.store.all_project_secrets(project)?;
        if secrets.is_empty() {
            bail!("project {project} has no secrets");
        }

        let mut master_key = self.master_key(&format!("Unlock {project} secrets"))?;
        let mut env = BTreeMap::new();
        for secret in &secrets {
            env.insert(
                secret.key.clone(),
                self.decrypt_stored_secret(&master_key, project, secret)?,
            );
        }
        master_key.zeroize();
        self.store.record_audit(
            "project.run",
            Some(project),
            None,
            Some(&format!("{} env vars", env.len())),
        )?;
        Ok(env)
    }

    pub fn import_env_file(&self, project: &str, path: &Path, yes: bool) -> Result<usize> {
        validate_name(project, "project")?;
        let parsed = dotenv_import::parse_env_file(path)?;
        if parsed.entries.is_empty() {
            println!("No values found in {}.", path.display());
            return Ok(0);
        }
        if !dotenv_import::confirm_import(&parsed, yes)? {
            println!("Import cancelled.");
            return Ok(0);
        }

        let mut master_key = self.master_key(&format!("Import .env into {project}"))?;
        let mut count = 0;
        for (key, value) in parsed.entries {
            validate_env_key(&key)?;
            let encrypted = crypto::encrypt(
                &master_key,
                &value,
                &crypto::project_secret_aad(project, &key),
            )?;
            self.store.set_project_secret(project, &key, &encrypted)?;
            manifest::record_key_if_manifest_exists(project, &key, None)?;
            count += 1;
        }
        master_key.zeroize();
        self.store.record_audit(
            "env.import",
            Some(project),
            None,
            Some(&format!("{count} keys from {}", path.display())),
        )?;
        Ok(count)
    }

    pub fn create_alias(&self, name: &str) -> Result<()> {
        validate_name(name, "alias")?;
        self.store.create_alias(name)?;
        self.store
            .record_audit("alias.create", None, None, Some(name))?;
        Ok(())
    }

    pub fn set_alias_secret(&self, name: &str, value: String) -> Result<()> {
        validate_name(name, "alias")?;
        let mut master_key = self.master_key(&format!("Set alias {name}"))?;
        let encrypted = crypto::encrypt(&master_key, &value, &crypto::alias_aad(name))?;
        master_key.zeroize();
        self.store.set_alias_secret(name, &encrypted)?;
        self.store
            .record_audit("alias.set", None, None, Some(name))?;
        Ok(())
    }

    pub fn list_aliases(&self) -> Result<Vec<String>> {
        self.store.list_aliases()
    }

    pub fn delete_alias(&self, name: &str) -> Result<()> {
        self.store.delete_alias(name)?;
        self.store
            .record_audit("alias.delete", None, None, Some(name))?;
        Ok(())
    }

    pub fn link_alias(&self, project: &str, key: &str, alias: &str) -> Result<()> {
        validate_name(project, "project")?;
        validate_env_key(key)?;
        validate_name(alias, "alias")?;
        if self.store.get_alias(alias)?.is_none() {
            bail!("alias {alias} does not exist");
        }
        self.store.link_alias(project, key, alias)?;
        manifest::record_key_if_manifest_exists(project, key, Some(alias))?;
        self.store
            .record_audit("alias.link", Some(project), Some(key), Some(alias))?;
        Ok(())
    }

    pub fn audit_events(&self, limit: usize) -> Result<Vec<AuditEvent>> {
        self.store.audit_events(limit)
    }

    pub fn doctor(&self) -> Result<()> {
        println!("Nerdovault doctor");
        println!("Data directory: {}", paths::app_dir()?.display());
        println!("Database: {}", self.store.path().display());
        println!("Database writable: yes");
        println!(
            "Keychain master key: {}",
            if Keychain::master_key_exists()? {
                "present"
            } else {
                "missing; run `nerdovault init`"
            }
        );
        println!(
            "Access policy: {}",
            self.store
                .get_setting(SETTING_ACCESS_POLICY)?
                .unwrap_or_else(|| AccessPolicy::UserPresence.as_str().to_string())
        );
        if Path::new(".nerdovault.toml").exists() {
            let manifest = crate::manifest::read_manifest(Path::new(".nerdovault.toml"))?;
            println!("Manifest project: {}", manifest.project);
            println!("Manifest required keys: {}", manifest.required.len());
        } else {
            println!("Manifest: not found in current directory");
        }
        Ok(())
    }

    fn master_key(&self, prompt: &str) -> Result<Vec<u8>> {
        let policy = self
            .store
            .get_setting(SETTING_ACCESS_POLICY)?
            .map(|value| AccessPolicy::from_str(&value))
            .unwrap_or(AccessPolicy::UserPresence);
        let domain_state = Keychain::authenticate(policy, prompt)?;
        if policy == AccessPolicy::BiometryCurrentSet {
            let expected = self.store.get_setting(SETTING_BIOMETRY_DOMAIN_STATE)?;
            if expected.is_some() && expected != domain_state {
                bail!("biometry set changed since Nerdovault was initialized");
            }
        }

        if !Keychain::master_key_exists()? {
            return Keychain::load_or_create_master_key(policy);
        }
        Keychain::read_master_key()
    }

    fn decrypt_stored_secret(
        &self,
        master_key: &[u8],
        project: &str,
        secret: &StoredSecret,
    ) -> Result<String> {
        if let Some(alias_name) = &secret.alias_name {
            let alias = self
                .store
                .get_alias(alias_name)?
                .with_context(|| format!("alias {alias_name} does not exist"))?;
            let encrypted = alias
                .encrypted
                .with_context(|| format!("alias {alias_name} does not have a value"))?;
            return crypto::decrypt(master_key, &encrypted, &crypto::alias_aad(alias_name));
        }

        let encrypted = secret
            .encrypted
            .as_ref()
            .with_context(|| format!("secret {} has no value", secret.key))?;
        crypto::decrypt(
            master_key,
            encrypted,
            &crypto::project_secret_aad(project, &secret.key),
        )
    }
}

fn validate_name(name: &str, kind: &str) -> Result<()> {
    if name.trim().is_empty() {
        bail!("{kind} name cannot be empty");
    }
    if name.contains(['\0', '\n', '\r']) {
        bail!("{kind} name contains invalid control characters");
    }
    Ok(())
}

fn validate_env_key(key: &str) -> Result<()> {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        bail!("env key cannot be empty");
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        bail!("env key must start with a letter or underscore");
    }
    if !chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric()) {
        bail!("env key may only contain ASCII letters, numbers, and underscores");
    }
    Ok(())
}
