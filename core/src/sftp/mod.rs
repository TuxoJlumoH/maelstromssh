//! SFTP file transfer, layered on top of an authenticated `ssh::Session`.
//!
//! `open` wires up the subsystem channel; `get`/`put` stream files in chunks
//! (never fully in memory), and `list` flattens a directory into a
//! front-end-friendly form. One-shot and interactive shells (the CLI `sftp`
//! command) drive these.

use std::io::SeekFrom;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use russh_sftp::protocol::{OpenFlags, StatusCode};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Notify;

use crate::error::{Error, Result};
use crate::ssh::Session;

pub use russh_sftp::client::SftpSession;
pub use russh_sftp::client::fs::File;

/// A single read buffer for streaming transfers.
const BUF_SIZE: usize = 64 * 1024;

/// Interval for throttling progress callback updates (~10 updates/s).
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

/// Cooperative cancellation token for SFTP transfers.
#[derive(Clone, Default, Debug)]
pub struct CancelToken {
    flag: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }

    /// Resolves immediately if already cancelled, or when `cancel()` is called.
    pub async fn cancelled(&self) {
        loop {
            let notified = self.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

/// Options controlling `get_with` and `put_with`.
#[derive(Clone, Default, Debug)]
pub struct TransferOptions {
    /// Continue from the existing destination file size instead of truncating.
    pub resume: bool,
    /// Optional cancellation token checked before and during the transfer.
    pub cancel: Option<CancelToken>,
}

/// A directory entry in a front-end-friendly shape (no `russh` types).
#[derive(Debug, Clone)]
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

async fn copy_stream<R, W>(
    src: &mut R,
    dst: &mut W,
    offset: u64,
    total: Option<u64>,
    cancel: Option<&CancelToken>,
    mut on_progress: impl FnMut(u64, Option<u64>),
) -> Result<u64>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut buf = vec![0u8; BUF_SIZE];
    let mut copied = 0u64;
    let mut last_reported = offset;
    let mut last_tick = tokio::time::Instant::now();

    on_progress(offset, total);

    loop {
        if cancel.as_ref().is_some_and(|c| c.is_cancelled()) {
            return Err(Error::Cancelled);
        }

        let n = match cancel {
            Some(c) => {
                tokio::select! {
                    biased;
                    _ = c.cancelled() => return Err(Error::Cancelled),
                    res = src.read(&mut buf) => res?,
                }
            }
            None => src.read(&mut buf).await?,
        };

        if n == 0 {
            break;
        }

        match cancel {
            Some(c) => {
                tokio::select! {
                    biased;
                    _ = c.cancelled() => return Err(Error::Cancelled),
                    res = dst.write_all(&buf[..n]) => res?,
                }
            }
            None => dst.write_all(&buf[..n]).await?,
        }

        copied += n as u64;
        let done = offset + copied;
        if last_tick.elapsed() >= PROGRESS_INTERVAL {
            on_progress(done, total);
            last_reported = done;
            last_tick = tokio::time::Instant::now();
        }

        if cancel.as_ref().is_some_and(|c| c.is_cancelled()) {
            return Err(Error::Cancelled);
        }
    }

    dst.flush().await?;

    let final_done = offset + copied;
    if final_done != last_reported {
        on_progress(final_done, total);
    }

    if cancel.as_ref().is_some_and(|c| c.is_cancelled()) {
        return Err(Error::Cancelled);
    }

    Ok(copied)
}

/// Downloads `remote` to `local` in chunks, reporting cumulative progress
/// `(done, total)` at most ~10x/s (plus start and completion).
/// Returns the number of bytes transferred in this call.
pub async fn get_with(
    sftp: &SftpSession,
    remote: &str,
    local: &Path,
    opts: &TransferOptions,
    mut on_progress: impl FnMut(u64, Option<u64>),
) -> Result<u64> {
    if opts.cancel.as_ref().is_some_and(CancelToken::is_cancelled) {
        return Err(Error::Cancelled);
    }

    let mut src = sftp.open(remote).await.map_err(Error::Sftp)?;
    let total = src.metadata().await.map_err(Error::Sftp)?.size;

    let (mut dst, offset) = if opts.resume {
        let offset = match tokio::fs::metadata(local).await {
            Ok(m) => {
                if m.is_dir() {
                    return Err(Error::Other(format!("{} is a directory", local.display())));
                }
                let existing = m.len();
                if let Some(remote_size) = total {
                    if existing == remote_size {
                        on_progress(existing, total);
                        return Ok(0);
                    }
                    if existing > remote_size {
                        return Err(Error::Other(format!(
                            "cannot resume download: local file ({existing} B) is larger than remote file ({remote_size} B)"
                        )));
                    }
                }
                existing
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
            Err(e) => return Err(Error::Io(e)),
        };
        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(local)
            .await?;
        (file, offset)
    } else {
        (tokio::fs::File::create(local).await?, 0)
    };

    if offset > 0 {
        src.seek(SeekFrom::Start(offset)).await?;
        dst.seek(SeekFrom::Start(offset)).await?;
    }

    copy_stream(
        &mut src,
        &mut dst,
        offset,
        total,
        opts.cancel.as_ref(),
        on_progress,
    )
    .await
}

/// Uploads `local` to `remote` in chunks, reporting cumulative progress
/// `(done, total)` at most ~10x/s (plus start and completion).
/// Returns the number of bytes transferred in this call.
pub async fn put_with(
    sftp: &SftpSession,
    local: &Path,
    remote: &str,
    opts: &TransferOptions,
    mut on_progress: impl FnMut(u64, Option<u64>),
) -> Result<u64> {
    if opts.cancel.as_ref().is_some_and(CancelToken::is_cancelled) {
        return Err(Error::Cancelled);
    }

    let mut src = tokio::fs::File::open(local).await?;
    let local_size = src.metadata().await?.len();
    let total = Some(local_size);

    let (mut dst, offset) = if opts.resume {
        let offset = match sftp.metadata(remote).await {
            Ok(m) => {
                if m.file_type().is_dir() {
                    return Err(Error::Other(format!("{remote} is a directory")));
                }
                let existing = m.size.unwrap_or(0);
                if existing == local_size {
                    on_progress(existing, total);
                    return Ok(0);
                }
                if existing > local_size {
                    return Err(Error::Other(format!(
                        "cannot resume upload: remote file ({existing} B) is larger than local file ({local_size} B)"
                    )));
                }
                existing
            }
            Err(russh_sftp::client::error::Error::Status(s))
                if s.status_code == StatusCode::NoSuchFile =>
            {
                0
            }
            Err(e) => return Err(Error::Sftp(e)),
        };
        let file = sftp
            .open_with_flags(remote, OpenFlags::WRITE | OpenFlags::CREATE)
            .await
            .map_err(Error::Sftp)?;
        (file, offset)
    } else {
        let file = sftp.create(remote).await.map_err(Error::Sftp)?;
        (file, 0)
    };

    if offset > 0 {
        src.seek(SeekFrom::Start(offset)).await?;
        dst.seek(SeekFrom::Start(offset)).await?;
    }

    let copied = copy_stream(
        &mut src,
        &mut dst,
        offset,
        total,
        opts.cancel.as_ref(),
        on_progress,
    )
    .await?;
    dst.shutdown().await?;
    Ok(copied)
}

/// Downloads `remote` to `local` in chunks, returning the number of bytes
/// transferred. Overwrites `local` if it exists.
pub async fn get(sftp: &SftpSession, remote: &str, local: &Path) -> Result<u64> {
    get_with(sftp, remote, local, &TransferOptions::default(), |_, _| {}).await
}

/// Uploads `local` to `remote` in chunks, returning the number of bytes
/// transferred. Creates or truncates `remote`.
pub async fn put(sftp: &SftpSession, local: &Path, remote: &str) -> Result<u64> {
    put_with(sftp, local, remote, &TransferOptions::default(), |_, _| {}).await
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

#[cfg(test)]
mod tests {
    use super::*;
    use russh_sftp::protocol::{
        Attrs, Data, FileAttributes, Handle, OpenFlags, Status, StatusCode, Version,
    };
    use russh_sftp::server::Handler;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(1);
            let path = std::env::temp_dir().join(format!(
                "maelstrom_sftp_test_{}_{}_{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct FakeSftpInner {
        files: HashMap<String, Vec<u8>>,
        handles: HashMap<String, (String, OpenFlags)>,
        next_handle: u64,
    }

    #[derive(Clone)]
    struct FakeSftp {
        inner: Arc<Mutex<FakeSftpInner>>,
    }

    impl FakeSftp {
        fn new(files: HashMap<String, Vec<u8>>) -> Self {
            Self {
                inner: Arc::new(Mutex::new(FakeSftpInner {
                    files,
                    handles: HashMap::new(),
                    next_handle: 1,
                })),
            }
        }

        fn get_file(&self, path: &str) -> Option<Vec<u8>> {
            self.inner.lock().unwrap().files.get(path).cloned()
        }
    }

    impl Handler for FakeSftp {
        type Error = StatusCode;

        fn unimplemented(&self) -> Self::Error {
            StatusCode::OpUnsupported
        }

        async fn init(
            &mut self,
            _version: u32,
            _extensions: HashMap<String, String>,
        ) -> std::result::Result<Version, Self::Error> {
            Ok(Version::new())
        }

        async fn open(
            &mut self,
            id: u32,
            filename: String,
            pflags: OpenFlags,
            _attrs: FileAttributes,
        ) -> std::result::Result<Handle, Self::Error> {
            let mut state = self.inner.lock().unwrap();
            if pflags.contains(OpenFlags::CREATE) {
                state.files.entry(filename.clone()).or_default();
            } else if !state.files.contains_key(&filename) {
                return Err(StatusCode::NoSuchFile);
            }

            if pflags.contains(OpenFlags::TRUNCATE) {
                state.files.insert(filename.clone(), Vec::new());
            }

            let handle = format!("h{}", state.next_handle);
            state.next_handle += 1;
            state.handles.insert(handle.clone(), (filename, pflags));
            Ok(Handle { id, handle })
        }

        async fn close(
            &mut self,
            id: u32,
            handle: String,
        ) -> std::result::Result<Status, Self::Error> {
            let mut state = self.inner.lock().unwrap();
            state.handles.remove(&handle);
            Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: String::new(),
                language_tag: String::new(),
            })
        }

        async fn read(
            &mut self,
            id: u32,
            handle: String,
            offset: u64,
            len: u32,
        ) -> std::result::Result<Data, Self::Error> {
            let state = self.inner.lock().unwrap();
            let (path, _) = state.handles.get(&handle).ok_or(StatusCode::Failure)?;
            let file = state.files.get(path).ok_or(StatusCode::NoSuchFile)?;
            if offset >= file.len() as u64 {
                return Err(StatusCode::Eof);
            }
            let start = offset as usize;
            let end = (start + len as usize).min(file.len());
            Ok(Data {
                id,
                data: file[start..end].to_vec(),
            })
        }

        async fn write(
            &mut self,
            id: u32,
            handle: String,
            offset: u64,
            data: Vec<u8>,
        ) -> std::result::Result<Status, Self::Error> {
            let mut state = self.inner.lock().unwrap();
            let path = state
                .handles
                .get(&handle)
                .ok_or(StatusCode::Failure)?
                .0
                .clone();
            let file = state.files.get_mut(&path).ok_or(StatusCode::NoSuchFile)?;
            let off = offset as usize;
            if file.len() < off + data.len() {
                file.resize(off + data.len(), 0);
            }
            file[off..off + data.len()].copy_from_slice(&data);
            Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: String::new(),
                language_tag: String::new(),
            })
        }

        async fn stat(&mut self, id: u32, path: String) -> std::result::Result<Attrs, Self::Error> {
            let state = self.inner.lock().unwrap();
            let file = state.files.get(&path).ok_or(StatusCode::NoSuchFile)?;
            let mut attrs = FileAttributes::empty();
            attrs.size = Some(file.len() as u64);
            attrs.set_regular(true);
            Ok(Attrs { id, attrs })
        }

        async fn fstat(
            &mut self,
            id: u32,
            handle: String,
        ) -> std::result::Result<Attrs, Self::Error> {
            let state = self.inner.lock().unwrap();
            let (path, _) = state.handles.get(&handle).ok_or(StatusCode::Failure)?;
            let file = state.files.get(path).ok_or(StatusCode::NoSuchFile)?;
            let mut attrs = FileAttributes::empty();
            attrs.size = Some(file.len() as u64);
            attrs.set_regular(true);
            Ok(Attrs { id, attrs })
        }
    }

    async fn setup_test_sftp(files: HashMap<String, Vec<u8>>) -> (SftpSession, FakeSftp) {
        let fake = FakeSftp::new(files);
        let (server_stream, client_stream) = tokio::io::duplex(64 * 1024);
        russh_sftp::server::run(server_stream, fake.clone()).await;
        let sftp = SftpSession::new(client_stream).await.unwrap();
        (sftp, fake)
    }

    #[tokio::test]
    async fn get_with_reports_progress_and_matches_bytes() {
        let dir = TempDir::new();
        let local_path = dir.path().join("downloaded.bin");

        let remote_data: Vec<u8> = (0..200 * 1024).map(|i| (i % 251) as u8).collect();
        let mut files = HashMap::new();
        files.insert("/large.bin".to_string(), remote_data.clone());
        let (sftp, _fake) = setup_test_sftp(files).await;

        let mut progress = Vec::new();
        let opts = TransferOptions::default();
        let transferred = get_with(&sftp, "/large.bin", &local_path, &opts, |done, total| {
            progress.push((done, total));
        })
        .await
        .unwrap();

        assert_eq!(transferred, remote_data.len() as u64);
        let local_data = std::fs::read(&local_path).unwrap();
        assert_eq!(local_data, remote_data);
        assert_eq!(progress.first(), Some(&(0, Some(remote_data.len() as u64))));
        assert_eq!(
            progress.last(),
            Some(&(remote_data.len() as u64, Some(remote_data.len() as u64)))
        );
    }

    #[tokio::test]
    async fn get_with_resumes_from_partial_local_file() {
        let dir = TempDir::new();
        let local_path = dir.path().join("partial.bin");

        let remote_data: Vec<u8> = (0..200 * 1024).map(|i| (i % 251) as u8).collect();
        let prefix_len = 80 * 1024;
        std::fs::write(&local_path, &remote_data[..prefix_len]).unwrap();

        let mut files = HashMap::new();
        files.insert("/partial.bin".to_string(), remote_data.clone());
        let (sftp, _fake) = setup_test_sftp(files).await;

        let mut progress = Vec::new();
        let opts = TransferOptions {
            resume: true,
            cancel: None,
        };
        let transferred = get_with(&sftp, "/partial.bin", &local_path, &opts, |done, total| {
            progress.push((done, total));
        })
        .await
        .unwrap();

        let expected_remaining = (remote_data.len() - prefix_len) as u64;
        assert_eq!(transferred, expected_remaining);
        let local_data = std::fs::read(&local_path).unwrap();
        assert_eq!(local_data, remote_data);
        assert_eq!(
            progress.first(),
            Some(&(prefix_len as u64, Some(remote_data.len() as u64)))
        );
        assert_eq!(
            progress.last(),
            Some(&(remote_data.len() as u64, Some(remote_data.len() as u64)))
        );
    }

    #[tokio::test]
    async fn get_with_resume_errors_when_local_larger_than_remote() {
        let dir = TempDir::new();
        let local_path = dir.path().join("oversized.bin");

        let remote_data = vec![1u8; 100];
        let local_data = vec![2u8; 200];
        std::fs::write(&local_path, &local_data).unwrap();

        let mut files = HashMap::new();
        files.insert("/file.bin".to_string(), remote_data);
        let (sftp, _fake) = setup_test_sftp(files).await;

        let opts = TransferOptions {
            resume: true,
            cancel: None,
        };
        let res = get_with(&sftp, "/file.bin", &local_path, &opts, |_, _| {}).await;
        assert!(res.is_err());
        let err_str = res.unwrap_err().to_string();
        assert!(err_str.contains("larger than remote file"));
        assert_eq!(std::fs::read(&local_path).unwrap(), local_data);
    }

    #[tokio::test]
    async fn get_with_resume_noop_when_already_complete() {
        let dir = TempDir::new();
        let local_path = dir.path().join("complete.bin");

        let data = vec![42u8; 150];
        std::fs::write(&local_path, &data).unwrap();

        let mut files = HashMap::new();
        files.insert("/complete.bin".to_string(), data.clone());
        let (sftp, _fake) = setup_test_sftp(files).await;

        let mut progress = Vec::new();
        let opts = TransferOptions {
            resume: true,
            cancel: None,
        };
        let transferred = get_with(&sftp, "/complete.bin", &local_path, &opts, |done, total| {
            progress.push((done, total));
        })
        .await
        .unwrap();

        assert_eq!(transferred, 0);
        assert_eq!(std::fs::read(&local_path).unwrap(), data);
        assert_eq!(progress.first(), Some(&(150, Some(150))));
    }

    #[tokio::test]
    async fn put_with_resumes_from_partial_remote_file() {
        let dir = TempDir::new();
        let local_path = dir.path().join("upload.bin");

        let full_data: Vec<u8> = (0..200 * 1024).map(|i| (i % 241) as u8).collect();
        std::fs::write(&local_path, &full_data).unwrap();

        let prefix_len = 50 * 1024;
        let mut files = HashMap::new();
        files.insert("/remote.bin".to_string(), full_data[..prefix_len].to_vec());
        let (sftp, fake) = setup_test_sftp(files).await;

        let mut progress = Vec::new();
        let opts = TransferOptions {
            resume: true,
            cancel: None,
        };
        let transferred = put_with(&sftp, &local_path, "/remote.bin", &opts, |done, total| {
            progress.push((done, total));
        })
        .await
        .unwrap();

        let expected_remaining = (full_data.len() - prefix_len) as u64;
        assert_eq!(transferred, expected_remaining);
        assert_eq!(fake.get_file("/remote.bin").unwrap(), full_data);
        assert_eq!(
            progress.first(),
            Some(&(prefix_len as u64, Some(full_data.len() as u64)))
        );
        assert_eq!(
            progress.last(),
            Some(&(full_data.len() as u64, Some(full_data.len() as u64)))
        );
    }

    #[tokio::test]
    async fn put_with_resume_errors_when_remote_larger_than_local() {
        let dir = TempDir::new();
        let local_path = dir.path().join("small.bin");

        let local_data = vec![1u8; 100];
        let remote_data = vec![2u8; 200];
        std::fs::write(&local_path, &local_data).unwrap();

        let mut files = HashMap::new();
        files.insert("/remote.bin".to_string(), remote_data.clone());
        let (sftp, fake) = setup_test_sftp(files).await;

        let opts = TransferOptions {
            resume: true,
            cancel: None,
        };
        let res = put_with(&sftp, &local_path, "/remote.bin", &opts, |_, _| {}).await;
        assert!(res.is_err());
        let err_str = res.unwrap_err().to_string();
        assert!(err_str.contains("larger than local file"));
        assert_eq!(fake.get_file("/remote.bin").unwrap(), remote_data);
    }

    #[tokio::test]
    async fn cancel_token_aborts_transfer() {
        let dir = TempDir::new();
        let local_path = dir.path().join("cancel.bin");

        let remote_data: Vec<u8> = (0..200 * 1024).map(|i| (i % 251) as u8).collect();
        let mut files = HashMap::new();
        files.insert("/cancel.bin".to_string(), remote_data);
        let (sftp, _fake) = setup_test_sftp(files).await;

        // 1. Pre-cancelled token
        let token = CancelToken::new();
        token.cancel();
        let opts = TransferOptions {
            resume: false,
            cancel: Some(token),
        };
        let res = get_with(&sftp, "/cancel.bin", &local_path, &opts, |_, _| {}).await;
        assert!(matches!(res, Err(Error::Cancelled)));

        // 2. Cancel during transfer callback
        let token = CancelToken::new();
        let token_clone = token.clone();
        let opts = TransferOptions {
            resume: false,
            cancel: Some(token),
        };
        let res = get_with(&sftp, "/cancel.bin", &local_path, &opts, move |_, _| {
            token_clone.cancel();
        })
        .await;
        assert!(matches!(res, Err(Error::Cancelled)));
    }
}
