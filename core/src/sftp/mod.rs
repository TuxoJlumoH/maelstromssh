//! SFTP file transfer, layered on top of an authenticated `ssh::Session`.
//!
//! `open` wires up the subsystem channel; `get`/`put` stream files in chunks
//! (never fully in memory), and `list` flattens a directory into a
//! front-end-friendly form. One-shot and interactive shells (the CLI `sftp`
//! command) drive these.

use std::path::Path;

use crate::error::{Error, Result};
use crate::ssh::Session;

/// Re-exported so front-ends can name the session type without depending on
/// `russh_sftp` directly.
pub use russh_sftp::client::fs::File;
pub use russh_sftp::client::SftpSession;

/// A single read buffer for streaming transfers.
const BUF_SIZE: usize = 64 * 1024;

/// A directory entry in a front-end-friendly shape (no `russh` types).
pub struct DirEntry {
    pub name: String,
    /// A directory, or a symlink that points to one.
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
    /// Seconds since the Unix epoch, when the server reports it.
    pub modified: Option<u32>,
    /// Unix permission bits (e.g. `0o644`), when the server reports them.
    pub permissions: Option<u32>,
}

/// Opens an SFTP subsystem channel on an existing session and wraps it in
/// `russh_sftp`'s client, which provides `read_dir`, `open`, `metadata`, etc.
pub async fn open(session: &Session) -> Result<SftpSession> {
    let channel = session.open_subsystem("sftp").await?;
    SftpSession::new(channel.into_stream())
        .await
        .map_err(Error::Sftp)
}

/// Downloads `remote` to `local` in chunks, returning the number of bytes
/// transferred. Overwrites `local` if it exists.
pub async fn get(sftp: &SftpSession, remote: &str, local: &Path) -> Result<u64> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut src = sftp.open(remote).await.map_err(Error::Sftp)?;
    let mut dst = tokio::fs::File::create(local).await?;

    let mut buf = vec![0u8; BUF_SIZE];
    let mut total = 0u64;
    loop {
        let n = src.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n]).await?;
        total += n as u64;
    }
    dst.flush().await?;
    Ok(total)
}

/// Uploads `local` to `remote` in chunks, returning the number of bytes
/// transferred. Creates or truncates `remote`.
pub async fn put(sftp: &SftpSession, local: &Path, remote: &str) -> Result<u64> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut src = tokio::fs::File::open(local).await?;
    let mut dst = sftp.create(remote).await.map_err(Error::Sftp)?;

    let mut buf = vec![0u8; BUF_SIZE];
    let mut total = 0u64;
    loop {
        let n = src.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n]).await?;
        total += n as u64;
    }
    dst.flush().await?;
    Ok(total)
}

/// Lists a remote directory, sorted by name. Each entry carries whether it is
/// a directory and its size in bytes.
pub async fn list(sftp: &SftpSession, path: &str) -> Result<Vec<DirEntry>> {
    let mut entries = Vec::new();
    for entry in sftp.read_dir(path).await.map_err(Error::Sftp)? {
        let meta = entry.metadata();
        let name = entry.file_name();
        let is_symlink = meta.file_type().is_symlink();
        let is_dir = if is_symlink {
            let target = format!("{}/{name}", path.trim_end_matches('/'));
            sftp.metadata(target)
                .await
                .is_ok_and(|m| m.file_type().is_dir())
        } else {
            meta.file_type().is_dir()
        };
        entries.push(DirEntry {
            name,
            is_dir,
            is_symlink,
            size: meta.size.unwrap_or(0),
            modified: meta.mtime,
            permissions: meta.permissions.map(|p| p & 0o7777),
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

/// Opens a remote file for streaming reads (e.g. to serve a download).
pub async fn open_read(sftp: &SftpSession, path: &str) -> Result<File> {
    sftp.open(path).await.map_err(Error::Sftp)
}

/// Creates or truncates a remote file for streaming writes.
pub async fn open_write(sftp: &SftpSession, path: &str) -> Result<File> {
    sftp.create(path).await.map_err(Error::Sftp)
}

/// The size of a remote file in bytes, following symlinks.
pub async fn file_size(sftp: &SftpSession, path: &str) -> Result<Option<u64>> {
    Ok(sftp.metadata(path).await.map_err(Error::Sftp)?.size)
}

/// Resolves `path` to an absolute remote path (handles `.`/`..`/symlinks).
pub async fn canonicalize(sftp: &SftpSession, path: &str) -> Result<String> {
    sftp.canonicalize(path).await.map_err(Error::Sftp)
}

pub async fn remove_file(sftp: &SftpSession, path: &str) -> Result<()> {
    sftp.remove_file(path).await.map_err(Error::Sftp)
}

pub async fn remove_dir(sftp: &SftpSession, path: &str) -> Result<()> {
    sftp.remove_dir(path).await.map_err(Error::Sftp)
}

pub async fn create_dir(sftp: &SftpSession, path: &str) -> Result<()> {
    sftp.create_dir(path).await.map_err(Error::Sftp)
}

pub async fn rename(sftp: &SftpSession, from: &str, to: &str) -> Result<()> {
    sftp.rename(from, to).await.map_err(Error::Sftp)
}

/// Follows symlinks at `path` (also a dangling one) to the path that
/// writing to it would really create or replace. Other paths are returned
/// as they are.
pub async fn resolve_link(sftp: &SftpSession, path: &str) -> Result<String> {
    let mut path = path.to_string();
    for _ in 0..40 {
        match sftp.symlink_metadata(path.as_str()).await {
            Ok(meta) if meta.file_type().is_symlink() => {}
            _ => return Ok(path),
        }
        let target = sftp.read_link(path.as_str()).await.map_err(Error::Sftp)?;
        path = if target.starts_with('/') {
            target
        } else {
            match path.rsplit_once('/') {
                Some((dir, _)) => format!("{dir}/{target}"),
                None => target,
            }
        };
    }
    Err(Error::Other(format!(
        "{path}: too many levels of symbolic links"
    )))
}

/// Moves a finished upload at `temp` to `dest`, replacing `dest` if it
/// exists and keeping its permission bits. A symlink at `dest` is followed,
/// so the file it points to is replaced. SFTP v3 renames do not overwrite,
/// so an existing file is moved aside first and put back if the final
/// rename fails: `dest` is never left missing or half-written.
pub async fn replace(sftp: &SftpSession, temp: &str, dest: &str) -> Result<()> {
    let Ok(meta) = sftp.symlink_metadata(dest).await else {
        return rename(sftp, temp, dest).await;
    };
    let (dest, meta) = if meta.file_type().is_symlink() {
        let target = canonicalize(sftp, dest).await?;
        let meta = sftp.metadata(target.as_str()).await.map_err(Error::Sftp)?;
        (target, meta)
    } else {
        (dest.to_string(), meta)
    };
    if meta.file_type().is_dir() {
        return Err(Error::Other(format!("{dest} is a folder")));
    }
    if let Some(permissions) = meta.permissions {
        let mut attrs = russh_sftp::protocol::FileAttributes::empty();
        attrs.permissions = Some(permissions & 0o7777);
        let _ = sftp.set_metadata(temp, attrs).await;
    }
    let backup = format!("{temp}.old");
    rename(sftp, &dest, &backup).await?;
    if let Err(e) = rename(sftp, temp, &dest).await {
        let _ = rename(sftp, &backup, &dest).await;
        return Err(e);
    }
    let _ = remove_file(sftp, &backup).await;
    Ok(())
}
