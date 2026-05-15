use anyhow::{anyhow, Context, Result};
use base64::prelude::*;
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

pub const MASTER_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

#[derive(Debug, Clone)]
pub struct EncryptedValue {
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

pub fn redact() -> &'static str {
    "********"
}

#[cfg(any(target_os = "macos", test))]
pub fn generate_master_key() -> [u8; MASTER_KEY_LEN] {
    let mut key = [0u8; MASTER_KEY_LEN];
    OsRng.fill_bytes(&mut key);
    key
}

pub fn encrypt(master_key: &[u8], plaintext: &str, aad: &[u8]) -> Result<EncryptedValue> {
    let cipher = cipher(master_key)?;
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_bytes(),
                aad,
            },
        )
        .map_err(|_| anyhow!("failed to encrypt secret"))?;

    Ok(EncryptedValue {
        nonce_b64: BASE64_STANDARD.encode(nonce),
        ciphertext_b64: BASE64_STANDARD.encode(ciphertext),
    })
}

pub fn decrypt(master_key: &[u8], encrypted: &EncryptedValue, aad: &[u8]) -> Result<String> {
    let cipher = cipher(master_key)?;
    let nonce = BASE64_STANDARD
        .decode(&encrypted.nonce_b64)
        .context("invalid nonce encoding")?;
    let ciphertext = BASE64_STANDARD
        .decode(&encrypted.ciphertext_b64)
        .context("invalid ciphertext encoding")?;

    if nonce.len() != NONCE_LEN {
        return Err(anyhow!("invalid nonce length"));
    }

    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("failed to decrypt secret"))?;

    String::from_utf8(plaintext).context("secret is not valid UTF-8")
}

fn cipher(master_key: &[u8]) -> Result<XChaCha20Poly1305> {
    if master_key.len() != MASTER_KEY_LEN {
        return Err(anyhow!("invalid master key length"));
    }
    XChaCha20Poly1305::new_from_slice(master_key).context("invalid master key")
}

pub fn project_secret_aad(project: &str, key: &str) -> Vec<u8> {
    format!("nerdovault:v1:project:{project}:key:{key}").into_bytes()
}

pub fn alias_aad(alias: &str) -> Vec<u8> {
    format!("nerdovault:v1:alias:{alias}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypt_roundtrip_requires_matching_aad() {
        let key = generate_master_key();
        let encrypted = encrypt(&key, "secret-value", b"one").unwrap();
        assert_eq!(decrypt(&key, &encrypted, b"one").unwrap(), "secret-value");
        assert!(decrypt(&key, &encrypted, b"two").is_err());
    }
}
