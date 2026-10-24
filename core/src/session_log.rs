//! Session logs: everything a session prints, saved to a file (like
//! PuTTY's "All session output").

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Local};

use crate::error::{Error, Result};

/// The file name used when none is given: host (or device), date and time.
pub const DEFAULT_NAME: &str = "&H-&Y&M&D-&T.log";

/// An open log. Output is appended as it arrives; a closing line is written
/// when it is dropped.
pub struct SessionLog {
    file: File,
    path: PathBuf,
    /// Set after a write fails: later output is dropped and the session
    /// goes on.
    failed: bool,
    /// The failure, until [`take_error`](Self::take_error) reports it.
    error: Option<String>,
}

impl SessionLog {
    /// Opens `path` for appending (creating it, readable only by you) and
    /// writes a line saying what the log is of. `path` may use the
    /// placeholders of [`expand_name`]; a folder gets a file named by
    /// [`DEFAULT_NAME`].
    pub fn create(path: &Path, label: &str, host: &str, port: u16) -> Result<Self> {
        let now = Local::now();
        let mut template = crate::paths::expand_tilde(path);
        if template.is_dir() {
            template.push(DEFAULT_NAME);
        }
        let path = PathBuf::from(expand_name(&template.to_string_lossy(), host, port, now));
        let fail = |e: std::io::Error| {
            Error::Config(format!("cannot open the log file {}: {e}", path.display()))
        };
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(&path).map_err(fail)?;
        let header = format!(
            "=~=~= MaelstromSSH log: {label}, started {} =~=~=\n",
            now.format("%Y-%m-%d %H:%M:%S %z")
        );
        file.write_all(header.as_bytes()).map_err(fail)?;
        Ok(Self {
            file,
            path,
            failed: false,
            error: None,
        })
    }

    /// Opens a log in [`default_dir`] named by [`DEFAULT_NAME`], creating
    /// the folder if needed.
    pub fn create_default(label: &str, host: &str, port: u16) -> Result<Self> {
        let dir = default_dir()?;
        create_private_dir(&dir).map_err(|e| {
            Error::Config(format!(
                "cannot create the log folder {}: {e}",
                dir.display()
            ))
        })?;
        Self::create(&dir.join(DEFAULT_NAME), label, host, port)
    }

    /// Where the log is being written.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends session output. A failed write is remembered and returned
    /// once (from [`take_error`](Self::take_error)); later output is
    /// dropped.
    pub fn write(&mut self, data: &[u8]) {
        if self.failed || data.is_empty() {
            return;
        }
        if let Err(e) = self.file.write_all(data) {
            self.failed = true;
            self.error = Some(format!(
                "writing the log {} failed, logging stopped: {e}",
                self.path.display()
            ));
        }
    }

    /// The error from a failed write, once.
    pub fn take_error(&mut self) -> Option<String> {
        self.error.take()
    }
}

impl Drop for SessionLog {
    fn drop(&mut self) {
        if !self.failed {
            let footer = format!(
                "\n=~=~= MaelstromSSH log ended {} =~=~=\n",
                Local::now().format("%Y-%m-%d %H:%M:%S %z")
            );
            let _ = self.file.write_all(footer.as_bytes());
        }
    }
}

/// Where logs go when no file is given: `~/.local/share/maelstromssh/logs`.
pub fn default_dir() -> Result<PathBuf> {
    dirs::data_dir()
        .map(|d| crate::paths::app_dir(&d).join("logs"))
        .ok_or_else(|| Error::Config("cannot find your data folder ($HOME)".into()))
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)
}

/// Fills in PuTTY's log file placeholders: `&H` host (or device name), `&P`
/// port, `&Y` year, `&M` month, `&D` day, `&T` time (HHMMSS), `&&` a `&`.
/// For a device path, `&H` is the device's name, e.g. `ttyUSB0`.
pub fn expand_name(template: &str, host: &str, port: u16, now: DateTime<Local>) -> String {
    let host = host.rsplit('/').next().unwrap_or(host);
    let mut out = String::with_capacity(template.len() + 16);
    let mut chars = template.chars();
    while let Some(c) = chars.next() {
        if c != '&' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('H') => out.push_str(host),
            Some('P') => out.push_str(&port.to_string()),
            Some('Y') => out.push_str(&now.format("%Y").to_string()),
            Some('M') => out.push_str(&now.format("%m").to_string()),
            Some('D') => out.push_str(&now.format("%d").to_string()),
            Some('T') => out.push_str(&now.format("%H%M%S").to_string()),
            Some('&') => out.push('&'),
            Some(other) => {
                out.push('&');
                out.push(other);
            }
            None => out.push('&'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn placeholders() {
        let now = Local.with_ymd_and_hms(2026, 3, 4, 5, 6, 7).unwrap();
        assert_eq!(
            expand_name("&H-&P-&Y&M&D-&T.log", "/dev/ttyUSB0", 0, now),
            "ttyUSB0-0-20260304-050607.log"
        );
        assert_eq!(
            expand_name("/logs/&H&&&x&", "/tmp/ser-a", 22, now),
            "/logs/ser-a&&x&"
        );
    }

    #[test]
    fn appends_with_header_and_footer() {
        let dir = std::env::temp_dir().join(format!("maelstromssh-log-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("&H.log");
        for text in [&b"first\r\n"[..], b"second"] {
            let mut log = SessionLog::create(&path, "telnet sw:23", "sw", 23).unwrap();
            assert_eq!(log.path(), dir.join("sw.log"));
            log.write(text);
            assert!(log.take_error().is_none());
        }
        let got = std::fs::read_to_string(dir.join("sw.log")).unwrap();
        assert_eq!(
            got.matches("MaelstromSSH log: telnet sw:23, started")
                .count(),
            2
        );
        assert_eq!(got.matches("MaelstromSSH log ended").count(), 2);
        assert!(got.contains("first\r\n") && got.contains("second"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("sw.log"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let log = SessionLog::create(&dir, "x", "box", 22).unwrap();
        let name = log
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(name.starts_with("box-") && name.ends_with(".log"), "{name}");
        drop(log);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_folder_is_a_clear_error() {
        let e = SessionLog::create(Path::new("/nonexistent-dir/x.log"), "x", "x", 0)
            .err()
            .unwrap();
        assert!(
            e.to_string()
                .contains("cannot open the log file /nonexistent-dir/x.log"),
            "{e}"
        );
    }
}
