//! SFTP front-end: one-shot `get`/`put`/`ls`/… commands and an interactive
//! shell, both driving the `vortexssh_core::sftp` engine.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Subcommand;
use vortexssh_core::sftp::{self, DirEntry, SftpSession};
use vortexssh_core::ssh::Session;

/// The scriptable SFTP operation, when `vortexssh sftp <target> <op>` is used.
#[derive(Subcommand)]
pub enum SftpOp {
    /// Download a remote file (default local name = remote basename).
    Get {
        remote: String,
        local: Option<PathBuf>,
    },
    /// Upload a local file (default remote name = local basename).
    Put {
        local: PathBuf,
        remote: Option<String>,
    },
    /// List a remote directory.
    Ls { path: Option<String> },
    /// Remove a remote file.
    Rm { path: String },
    /// Create a remote directory.
    Mkdir { path: String },
    /// Rename a remote file or directory.
    Rename { from: String, to: String },
}

/// Runs a single scriptable operation against a fresh SFTP session.
pub async fn run(session: &mut Session, op: SftpOp) -> Result<()> {
    let sftp = sftp::open(session).await?;
    match op {
        SftpOp::Get { remote, local } => {
            let local = local.unwrap_or_else(|| PathBuf::from(remote_basename(&remote)));
            do_get(&sftp, &remote, &local).await
        }
        SftpOp::Put { local, remote } => {
            let remote = remote.unwrap_or_else(|| local_basename(&local));
            do_put(&sftp, &local, &remote).await
        }
        SftpOp::Ls { path } => do_ls(&sftp, path.as_deref().unwrap_or(".")).await,
        SftpOp::Rm { path } => do_rm(&sftp, &path).await,
        SftpOp::Mkdir { path } => do_mkdir(&sftp, &path).await,
        SftpOp::Rename { from, to } => do_rename(&sftp, &from, &to).await,
    }
}

// ---- shared operations (used by both one-shot and the shell) ------------

async fn do_get(sftp: &SftpSession, remote: &str, local: &Path) -> Result<()> {
    let n = sftp::get(sftp, remote, local).await?;
    eprintln!("Downloaded {n} bytes -> {}", local.display());
    Ok(())
}

async fn do_put(sftp: &SftpSession, local: &Path, remote: &str) -> Result<()> {
    let n = sftp::put(sftp, local, remote).await?;
    eprintln!("Uploaded {n} bytes -> {remote}");
    Ok(())
}

async fn do_ls(sftp: &SftpSession, path: &str) -> Result<()> {
    for entry in sftp::list(sftp, path).await? {
        print_entry(&entry);
    }
    Ok(())
}

fn print_entry(entry: &DirEntry) {
    let kind = if entry.is_dir { "d" } else { "-" };
    println!("{kind} {:>12} {}", entry.size, entry.name);
}

async fn do_rm(sftp: &SftpSession, path: &str) -> Result<()> {
    sftp::remove_file(sftp, path).await?;
    println!("Removed {path}");
    Ok(())
}

async fn do_mkdir(sftp: &SftpSession, path: &str) -> Result<()> {
    sftp::create_dir(sftp, path).await?;
    println!("Created directory {path}");
    Ok(())
}

async fn do_rename(sftp: &SftpSession, from: &str, to: &str) -> Result<()> {
    sftp::rename(sftp, from, to).await?;
    println!("Renamed {from} -> {to}");
    Ok(())
}

// ---- interactive shell ---------------------------------------------------

/// Runs the interactive SFTP shell: a prompt-driven REPL that keeps a single
/// SFTP session open and tracks a remote working directory.
pub async fn shell(session: &mut Session) -> Result<()> {
    let sftp = sftp::open(session).await?;
    let mut cwd = sftp::canonicalize(&sftp, ".").await?;
    eprintln!("Connected. Type 'help' for a list of commands.");

    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    loop {
        print!("sftp:{cwd}> ");
        std::io::stdout().flush().ok();
        let Some(Ok(line)) = lines.next() else {
            break;
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        match parse_repl(line) {
            Repl::Exit => break,
            Repl::Help => print_help(),
            Repl::Pwd => println!("{cwd}"),
            Repl::Cd(path) => {
                if path.is_empty() {
                    eprintln!("usage: cd <path>");
                    continue;
                }
                let target = resolve_remote(&cwd, &path);
                match sftp::canonicalize(&sftp, &target).await {
                    Ok(new) => cwd = new,
                    Err(e) => eprintln!("cd {path}: {e}"),
                }
            }
            Repl::Ls(path) => {
                let target = resolve_remote(&cwd, path.as_deref().unwrap_or("."));
                if let Err(e) = do_ls(&sftp, &target).await {
                    eprintln!("ls: {e}");
                }
            }
            Repl::Get { remote, local } => {
                if remote.is_empty() {
                    eprintln!("usage: get <remote> [local]");
                    continue;
                }
                let target = resolve_remote(&cwd, &remote);
                let local = local
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from(remote_basename(&remote)));
                if let Err(e) = do_get(&sftp, &target, &local).await {
                    eprintln!("get: {e}");
                }
            }
            Repl::Put { local, remote } => {
                if local.is_empty() {
                    eprintln!("usage: put <local> [remote]");
                    continue;
                }
                let local = PathBuf::from(&local);
                let target = remote
                    .map(|r| resolve_remote(&cwd, &r))
                    .unwrap_or_else(|| resolve_remote(&cwd, &local_basename(&local)));
                if let Err(e) = do_put(&sftp, &local, &target).await {
                    eprintln!("put: {e}");
                }
            }
            Repl::Rm(path) => {
                if path.is_empty() {
                    eprintln!("usage: rm <path>");
                    continue;
                }
                let target = resolve_remote(&cwd, &path);
                if let Err(e) = do_rm(&sftp, &target).await {
                    eprintln!("rm: {e}");
                }
            }
            Repl::Mkdir(path) => {
                if path.is_empty() {
                    eprintln!("usage: mkdir <path>");
                    continue;
                }
                let target = resolve_remote(&cwd, &path);
                if let Err(e) = do_mkdir(&sftp, &target).await {
                    eprintln!("mkdir: {e}");
                }
            }
            Repl::Rmdir(path) => {
                if path.is_empty() {
                    eprintln!("usage: rmdir <path>");
                    continue;
                }
                let target = resolve_remote(&cwd, &path);
                if let Err(e) = sftp::remove_dir(&sftp, &target).await {
                    eprintln!("rmdir: {e}");
                } else {
                    println!("Removed directory {target}");
                }
            }
            Repl::Rename { from, to } => {
                if from.is_empty() || to.is_empty() {
                    eprintln!("usage: rename <from> <to>");
                    continue;
                }
                let from = resolve_remote(&cwd, &from);
                let to = resolve_remote(&cwd, &to);
                if let Err(e) = do_rename(&sftp, &from, &to).await {
                    eprintln!("rename: {e}");
                }
            }
            Repl::Lls(path) => {
                if let Err(e) = list_local(path.as_deref()) {
                    eprintln!("lls: {e}");
                }
            }
            Repl::Lcd(path) => {
                if path.is_empty() {
                    eprintln!("usage: lcd <path>");
                    continue;
                }
                if let Err(e) = std::env::set_current_dir(&path) {
                    eprintln!("lcd {path}: {e}");
                }
            }
            Repl::Lpwd => match std::env::current_dir() {
                Ok(p) => println!("{}", p.display()),
                Err(e) => eprintln!("lpwd: {e}"),
            },
            Repl::Unknown(cmd) => eprintln!("unknown command '{cmd}' — try 'help'"),
        }
    }
    Ok(())
}

fn list_local(path: Option<&str>) -> std::io::Result<()> {
    let dir = path.unwrap_or(".");
    let mut entries: Vec<(String, bool, u64)> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        entries.push((
            entry.file_name().to_string_lossy().into_owned(),
            meta.is_dir(),
            meta.len(),
        ));
    }
    entries.sort();
    for (name, is_dir, size) in entries {
        let kind = if is_dir { "d" } else { "-" };
        println!("{kind} {:>12} {}", size, name);
    }
    Ok(())
}

fn print_help() {
    println!(
        "Commands:\n\
         \x20 get <remote> [local]   download a file\n\
         \x20 put <local> [remote]   upload a file\n\
         \x20 ls [path]              list a remote directory\n\
         \x20 cd <path>              change remote directory\n\
         \x20 pwd                    print remote directory\n\
         \x20 rm <path>              remove a remote file\n\
         \x20 mkdir <path>           create a remote directory\n\
         \x20 rmdir <path>           remove a remote directory\n\
         \x20 rename <from> <to>     rename a remote file/directory\n\
         \x20 lls [path]             list a local directory\n\
         \x20 lcd <path>             change local directory\n\
         \x20 lpwd                   print local directory\n\
         \x20 exit / quit            close the session"
    );
}

// ---- path & command-line helpers (pure, unit-tested) --------------------

/// Resolves a (possibly relative) remote path against `cwd`.
pub fn resolve_remote(cwd: &str, path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("{}/{}", cwd.trim_end_matches('/'), path)
    }
}

/// The final path component of a remote `/`-separated path.
pub fn remote_basename(path: &str) -> &str {
    path.rsplit('/')
        .find(|s| !s.is_empty())
        .unwrap_or(path)
}

fn local_basename(path: &Path) -> String {
    path.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("file")
        .to_string()
}

/// A parsed interactive-shell command line.
#[derive(Debug, PartialEq, Eq)]
pub enum Repl {
    Help,
    Ls(Option<String>),
    Cd(String),
    Pwd,
    Get { remote: String, local: Option<String> },
    Put { local: String, remote: Option<String> },
    Rm(String),
    Mkdir(String),
    Rmdir(String),
    Rename { from: String, to: String },
    Lls(Option<String>),
    Lcd(String),
    Lpwd,
    Exit,
    Unknown(String),
}

/// Parses a shell command line. Arguments beyond what a command expects are
/// ignored; missing arguments yield empty strings (the shell reports usage).
pub fn parse_repl(line: &str) -> Repl {
    let mut parts = line.split_whitespace();
    let Some(cmd) = parts.next() else {
        return Repl::Unknown(String::new());
    };
    let args: Vec<&str> = parts.collect();
    let arg = |i: usize| args.get(i).map(|s| s.to_string());

    match cmd {
        "help" | "?" => Repl::Help,
        "ls" | "dir" => Repl::Ls(arg(0)),
        "cd" => Repl::Cd(arg(0).unwrap_or_default()),
        "pwd" => Repl::Pwd,
        "get" => Repl::Get {
            remote: arg(0).unwrap_or_default(),
            local: arg(1),
        },
        "put" => Repl::Put {
            local: arg(0).unwrap_or_default(),
            remote: arg(1),
        },
        "rm" => Repl::Rm(arg(0).unwrap_or_default()),
        "mkdir" => Repl::Mkdir(arg(0).unwrap_or_default()),
        "rmdir" => Repl::Rmdir(arg(0).unwrap_or_default()),
        "rename" | "mv" => Repl::Rename {
            from: arg(0).unwrap_or_default(),
            to: arg(1).unwrap_or_default(),
        },
        "lls" => Repl::Lls(arg(0)),
        "lcd" => Repl::Lcd(arg(0).unwrap_or_default()),
        "lpwd" => Repl::Lpwd,
        "exit" | "quit" | "bye" => Repl::Exit,
        other => Repl::Unknown(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_relative_and_absolute_paths() {
        assert_eq!(resolve_remote("/home/u", "docs/a.txt"), "/home/u/docs/a.txt");
        assert_eq!(resolve_remote("/home/u/", "docs/a.txt"), "/home/u/docs/a.txt");
        assert_eq!(resolve_remote("/home/u", "/etc/passwd"), "/etc/passwd");
    }

    #[test]
    fn remote_basename_extracts_last_component() {
        assert_eq!(remote_basename("a/b/c.txt"), "c.txt");
        assert_eq!(remote_basename("c.txt"), "c.txt");
        assert_eq!(remote_basename("/a/b/"), "b");
    }

    #[test]
    fn parses_get_with_defaults() {
        assert_eq!(
            parse_repl("get foo.txt"),
            Repl::Get {
                remote: "foo.txt".into(),
                local: None,
            }
        );
        assert_eq!(
            parse_repl("get foo.txt local.bin"),
            Repl::Get {
                remote: "foo.txt".into(),
                local: Some("local.bin".into()),
            }
        );
    }

    #[test]
    fn parses_put_rename_and_misc() {
        assert_eq!(
            parse_repl("put x.bin"),
            Repl::Put {
                local: "x.bin".into(),
                remote: None,
            }
        );
        assert_eq!(
            parse_repl("rename a b"),
            Repl::Rename {
                from: "a".into(),
                to: "b".into(),
            }
        );
        assert_eq!(parse_repl("cd /var/log"), Repl::Cd("/var/log".into()));
        assert_eq!(parse_repl("ls -l"), Repl::Ls(Some("-l".into())));
        assert_eq!(parse_repl("pwd"), Repl::Pwd);
        assert_eq!(parse_repl("exit"), Repl::Exit);
        assert_eq!(parse_repl("quit"), Repl::Exit);
        assert_eq!(parse_repl("frobnicate"), Repl::Unknown("frobnicate".into()));
    }
}
