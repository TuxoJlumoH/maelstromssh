//! Key generation, import/export, and ssh-agent support.
//!
//! Re-uses `russh::keys` (which re-exports `ssh_key`) rather than depending
//! on `ssh-key` directly, to avoid pulling in two potentially mismatched
//! versions of the same crate.

pub mod agent;

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use russh::keys::ssh_key::{getrandom::SysRng, rand_core::UnwrapErr};
use russh::keys::{Algorithm, PrivateKey, PublicKey};
use serde::Serialize;

pub use russh::keys::HashAlg;

use crate::error::{Error, Result};
use crate::paths::collapse_home;

#[derive(Debug, Clone, Copy)]
pub enum KeyKind {
    Ed25519,
    /// RSA key generation; `bits` is the modulus size (min 2048).
    Rsa {
        bits: usize,
    },
}

/// Generates a new keypair in memory (not yet written to disk).
pub fn generate(kind: KeyKind, comment: &str) -> Result<PrivateKey> {
    use russh::keys::ssh_key::private::{KeypairData, RsaKeypair};

    let mut rng = UnwrapErr(SysRng);
    let mut key = match kind {
        KeyKind::Ed25519 => PrivateKey::random(&mut rng, Algorithm::Ed25519)?,
        KeyKind::Rsa { bits } => {
            if bits < 2048 {
                return Err(crate::error::Error::Other(format!(
                    "RSA key size must be at least 2048 bits (got {bits})"
                )));
            }
            let keypair = RsaKeypair::random(&mut rng, bits)?;
            PrivateKey::new(KeypairData::Rsa(keypair), "")?
        }
    };
    key.set_comment(comment);
    Ok(key)
}

/// Loads an OpenSSH-format private key from disk, optionally decrypting it.
pub fn load_openssh(path: &Path, passphrase: Option<&str>) -> Result<PrivateKey> {
    Ok(russh::keys::load_secret_key(path, passphrase)?)
}

/// Writes a private key to disk in OpenSSH format.
pub fn save_openssh(key: &PrivateKey, path: &Path) -> Result<()> {
    use std::io::Write;
    let pem = key.to_openssh(russh::keys::ssh_key::LineEnding::default())?;
    let mut file = std::fs::File::create(path)?;
    file.write_all(pem.as_bytes())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Metadata and public key line for a keypair in `~/.ssh`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicKeyInfo {
    /// Key stem name, e.g. `id_ed25519`.
    pub name: String,
    /// Private key path with `~` collapsed, e.g. `~/.ssh/id_ed25519`.
    pub private_path: String,
    /// Public key path with `~` collapsed, e.g. `~/.ssh/id_ed25519.pub`.
    pub public_path: String,
    /// Algorithm name, e.g. `ssh-ed25519`.
    pub algorithm: String,
    /// `SHA256:…` fingerprint.
    pub fingerprint: String,
    /// Key comment, if any.
    pub comment: String,
    /// Full OpenSSH `.pub` line suitable for `authorized_keys`.
    pub openssh: String,
}

/// Returns `~/.ssh`.
pub fn default_ssh_dir() -> Result<PathBuf> {
    let home = dirs::home_dir()
        .ok_or_else(|| Error::Config("could not determine the home directory".into()))?;
    Ok(home.join(".ssh"))
}

/// Lists all valid `*.pub` keys in `ssh_dir`, sorted by name.
pub fn list_ssh_keys(ssh_dir: &Path) -> Result<Vec<PublicKeyInfo>> {
    let read_dir = match std::fs::read_dir(ssh_dir) {
        Ok(d) => d,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::Io(e)),
    };

    let mut keys = Vec::new();
    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("pub") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        let line = raw.lines().next().unwrap_or("").trim();
        let Ok(pubkey) = PublicKey::from_openssh(line) else {
            continue;
        };
        let priv_path = ssh_dir.join(stem);
        keys.push(PublicKeyInfo {
            name: stem.to_string(),
            private_path: collapse_home(&priv_path),
            public_path: collapse_home(&path),
            algorithm: pubkey.algorithm().to_string(),
            fingerprint: pubkey.fingerprint(HashAlg::Sha256).to_string(),
            comment: pubkey.comment().to_string(),
            openssh: line.to_string(),
        });
    }
    keys.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(keys)
}

/// Validates a key filename inside `~/.ssh` and generates a new keypair
/// (`<name>` and `<name>.pub`), refusing to overwrite existing files.
pub fn generate_in_dir(
    ssh_dir: &Path,
    name: &str,
    kind: KeyKind,
    comment: &str,
) -> Result<PublicKeyInfo> {
    let name = name.trim().trim_end_matches(".pub");
    if name.is_empty()
        || name.starts_with('.')
        || name.contains('/')
        || name.contains('\\')
        || name.contains("..")
        || name.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(Error::Config(
            "enter a simple key file name such as id_ed25519".into(),
        ));
    }
    if matches!(
        name,
        "config" | "known_hosts" | "known_hosts.old" | "authorized_keys"
    ) {
        return Err(Error::Config(format!("'{name}' is a reserved SSH file")));
    }

    std::fs::create_dir_all(ssh_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(ssh_dir, std::fs::Permissions::from_mode(0o700));
    }

    let priv_path = ssh_dir.join(name);
    let pub_path = ssh_dir.join(format!("{name}.pub"));
    if priv_path.exists() || pub_path.exists() {
        return Err(Error::Config(format!(
            "key '{name}' already exists in {}",
            collapse_home(ssh_dir)
        )));
    }

    let key = generate(kind, comment)?;
    save_openssh(&key, &priv_path)?;
    let public = key.public_key();
    let openssh = public
        .to_openssh()
        .map_err(|e| Error::Other(format!("encoding public key: {e}")))?;
    std::fs::write(&pub_path, format!("{openssh}\n"))?;

    Ok(PublicKeyInfo {
        name: name.to_string(),
        private_path: collapse_home(&priv_path),
        public_path: collapse_home(&pub_path),
        algorithm: public.algorithm().to_string(),
        fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
        comment: public.comment().to_string(),
        openssh,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_ed25519() {
        let key = generate(KeyKind::Ed25519, "test@maelstromssh").unwrap();
        assert_eq!(key.algorithm(), Algorithm::Ed25519);
    }

    #[test]
    fn generate_rsa_and_roundtrip_to_disk() {
        let key = generate(KeyKind::Rsa { bits: 2048 }, "test@maelstromssh").unwrap();
        assert!(key.algorithm().is_rsa());
        let path =
            std::env::temp_dir().join(format!("maelstromssh-test-rsa-{}", std::process::id()));
        save_openssh(&key, &path).unwrap();
        let loaded = load_openssh(&path, None).unwrap();
        assert!(loaded.algorithm().is_rsa());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn rejects_rsa_below_minimum() {
        assert!(generate(KeyKind::Rsa { bits: 512 }, "x").is_err());
    }

    #[test]
    fn generate_and_roundtrip_to_disk() {
        let key = generate(KeyKind::Ed25519, "test@maelstromssh").unwrap();
        let path =
            std::env::temp_dir().join(format!("maelstromssh-test-key-{}", std::process::id()));
        save_openssh(&key, &path).unwrap();
        let loaded = load_openssh(&path, None).unwrap();
        assert_eq!(loaded.algorithm(), Algorithm::Ed25519);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn generate_in_dir_and_list_keys() {
        let dir =
            std::env::temp_dir().join(format!("maelstromssh-keys-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let info = generate_in_dir(&dir, "id_ed25519", KeyKind::Ed25519, "deploy@test").unwrap();
        assert_eq!(info.name, "id_ed25519");
        assert_eq!(info.algorithm, "ssh-ed25519");
        assert_eq!(info.comment, "deploy@test");
        assert!(info.openssh.starts_with("ssh-ed25519 "));

        // Refuses to overwrite or accept unsafe names.
        assert!(generate_in_dir(&dir, "id_ed25519", KeyKind::Ed25519, "").is_err());
        assert!(generate_in_dir(&dir, "../bad", KeyKind::Ed25519, "").is_err());
        assert!(generate_in_dir(&dir, "authorized_keys", KeyKind::Ed25519, "").is_err());

        let listed = list_ssh_keys(&dir).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0], info);

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
