//! Key generation, import/export, and ssh-agent support.
//!
//! Re-uses `russh::keys` (which re-exports `ssh_key`) rather than depending
//! on `ssh-key` directly, to avoid pulling in two potentially mismatched
//! versions of the same crate.

pub mod agent;

use std::path::Path;

use russh::keys::ssh_key::{getrandom::SysRng, rand_core::UnwrapErr};
use russh::keys::{Algorithm, PrivateKey};

pub use russh::keys::HashAlg;

use crate::error::Result;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_ed25519() {
        let key = generate(KeyKind::Ed25519, "test@vortexssh").unwrap();
        assert_eq!(key.algorithm(), Algorithm::Ed25519);
    }

    #[test]
    fn generate_rsa_and_roundtrip_to_disk() {
        let key = generate(KeyKind::Rsa { bits: 2048 }, "test@vortexssh").unwrap();
        assert!(key.algorithm().is_rsa());
        let path = std::env::temp_dir().join(format!("vortexssh-test-rsa-{}", std::process::id()));
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
        let key = generate(KeyKind::Ed25519, "test@vortexssh").unwrap();
        let path = std::env::temp_dir().join(format!("vortexssh-test-key-{}", std::process::id()));
        save_openssh(&key, &path).unwrap();
        let loaded = load_openssh(&path, None).unwrap();
        assert_eq!(loaded.algorithm(), Algorithm::Ed25519);
        std::fs::remove_file(&path).ok();
    }
}
