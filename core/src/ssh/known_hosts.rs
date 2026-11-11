//! Reading and removing entries in an OpenSSH `known_hosts` file.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use russh::keys::{HashAlg, PublicKey};
use serde::Serialize;

use crate::error::{Error, Result};

/// One host key entry from a `known_hosts` file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KnownHostEntry {
    /// 1-based line number in `known_hosts`.
    pub line: usize,
    /// Host pattern(s) on this line, or `"(hashed host)"` when hashed (`|1|…`).
    pub hosts: String,
    /// Whether the host field is HMAC-SHA1 hashed (`HashKnownHosts yes`).
    pub hashed: bool,
    /// Key algorithm, e.g. `ssh-ed25519` or `ecdsa-sha2-nistp256`.
    pub algorithm: String,
    /// `SHA256:…` fingerprint of the public key.
    pub fingerprint: String,
    /// Optional trailing comment on the line.
    pub comment: String,
}

/// Returns `~/.ssh/known_hosts`.
pub fn default_known_hosts_path() -> Result<PathBuf> {
    let home = dirs::home_dir()
        .ok_or_else(|| Error::Config("could not determine the home directory".into()))?;
    Ok(home.join(".ssh").join("known_hosts"))
}

/// Lists all valid host key entries in `path`. If `path` does not exist,
/// returns an empty list.
pub fn list_known_hosts(path: &Path) -> Result<Vec<KnownHostEntry>> {
    let content = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::Io(e)),
    };

    let mut entries = Vec::new();
    for (idx, raw) in content.lines().enumerate() {
        if let Some(entry) = parse_line(idx + 1, raw) {
            entries.push(entry);
        }
    }
    Ok(entries)
}

fn parse_line(line_no: usize, raw: &str) -> Option<KnownHostEntry> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    // Optional marker (@cert-authority, @revoked) comes first if present.
    let mut parts = trimmed.split_whitespace();
    let first = parts.next()?;
    let hosts_field = if first.starts_with('@') {
        parts.next()?
    } else {
        first
    };
    let alg = parts.next()?;
    let b64 = parts.next()?;
    let comment: Vec<&str> = parts.collect();

    let openssh_str = format!("{alg} {b64}");
    let pubkey = PublicKey::from_openssh(&openssh_str).ok()?;
    let fingerprint = pubkey.fingerprint(HashAlg::Sha256).to_string();
    let hashed = hosts_field.starts_with("|1|");
    let hosts = if hashed {
        "(hashed host)".to_string()
    } else {
        hosts_field.to_string()
    };

    Some(KnownHostEntry {
        line: line_no,
        hosts,
        hashed,
        algorithm: pubkey.algorithm().to_string(),
        fingerprint,
        comment: comment.join(" "),
    })
}

/// Removes a single 1-based line number from `path`. Returns `Ok(true)` if a
/// known-host entry on that line was removed.
pub fn remove_known_host_line(path: &Path, target_line: usize) -> Result<bool> {
    if target_line == 0 {
        return Ok(false);
    }
    let content = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(Error::Io(e)),
    };

    let mut kept = Vec::new();
    let mut removed = false;
    for (idx, line) in content.lines().enumerate() {
        if idx + 1 == target_line && parse_line(idx + 1, line).is_some() {
            removed = true;
        } else {
            kept.push(line);
        }
    }

    if removed {
        write_lines(path, &kept)?;
    }
    Ok(removed)
}

/// Removes all unhashed entries matching `host_label` (e.g. `"example.com"` or
/// `"[example.com]:2222"`). Returns the number of entries removed.
pub fn remove_known_host(path: &Path, host_label: &str) -> Result<usize> {
    let target = host_label.trim();
    if target.is_empty() {
        return Ok(0);
    }
    let content = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(Error::Io(e)),
    };

    let alt = target
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix("]:22"));

    let mut kept = Vec::new();
    let mut removed = 0usize;
    for (idx, line) in content.lines().enumerate() {
        let should_remove = match parse_line(idx + 1, line) {
            Some(entry) if !entry.hashed => entry.hosts.split(',').any(|h| {
                h.eq_ignore_ascii_case(target) || alt.is_some_and(|a| h.eq_ignore_ascii_case(a))
            }),
            _ => false,
        };
        if should_remove {
            removed += 1;
        } else {
            kept.push(line);
        }
    }

    if removed > 0 {
        write_lines(path, &kept)?;
    }
    Ok(removed)
}

fn write_lines(path: &Path, lines: &[&str]) -> Result<()> {
    let mut out = lines.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    std::fs::write(path, out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

    #[test]
    fn lists_and_removes_entries() {
        let dir = std::env::temp_dir().join(format!("maelstromssh-kh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let kh = dir.join("known_hosts");

        let text = format!(
            "# comment line\n\
             web-01.example.com,10.0.0.1 {SAMPLE_KEY} deploy@web-01\n\
             [db-01.example.com]:2222 {SAMPLE_KEY}\n\
             |1|F1E2D3C4B5A69788=|9988776655443322= {SAMPLE_KEY}\n"
        );
        std::fs::write(&kh, text).unwrap();

        let entries = list_known_hosts(&kh).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].line, 2);
        assert_eq!(entries[0].hosts, "web-01.example.com,10.0.0.1");
        assert!(!entries[0].hashed);
        assert_eq!(entries[0].algorithm, "ssh-ed25519");
        assert!(entries[0].fingerprint.starts_with("SHA256:"));
        assert_eq!(entries[0].comment, "deploy@web-01");

        assert_eq!(entries[1].line, 3);
        assert_eq!(entries[1].hosts, "[db-01.example.com]:2222");

        assert_eq!(entries[2].line, 4);
        assert!(entries[2].hashed);
        assert_eq!(entries[2].hosts, "(hashed host)");

        // Remove by host name.
        let count = remove_known_host(&kh, "10.0.0.1").unwrap();
        assert_eq!(count, 1);

        let entries = list_known_hosts(&kh).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].hosts, "[db-01.example.com]:2222");

        // Remove by line number (the hashed entry is now on line 3).
        assert!(remove_known_host_line(&kh, 3).unwrap());
        let entries = list_known_hosts(&kh).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].hosts, "[db-01.example.com]:2222");

        // Comments are preserved.
        let remaining = std::fs::read_to_string(&kh).unwrap();
        assert!(remaining.starts_with("# comment line\n"));

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
