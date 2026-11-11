//! Bridge between the async session (background tokio task for SSH, serial,
//! Telnet or raw TCP) and the single-threaded GUI. The task owns the
//! connection and exchanges raw bytes and commands with the UI over unbounded
//! channels; the UI owns the core [`Terminal`] and feeds it the bytes it
//! receives.
//!
//! [`Terminal`]: maelstromssh_core::term::Terminal

use std::path::PathBuf;
use std::sync::{Arc, mpsc as std_mpsc};

use maelstromssh_core::config::{ForwardKind, ForwardRule, Protocol, forward_spec, parse_forward};
use maelstromssh_core::prompt::{KiPrompt, Prompter};
use maelstromssh_core::serial;
use maelstromssh_core::sftp::{self, DirEntry, SftpSession};
use maelstromssh_core::ssh::{ChannelMsg, KnownHosts, Session};
use maelstromssh_core::target::Target;
use maelstromssh_core::tcp::TcpLine;
use maelstromssh_core::tunnel::{ActiveForward, ForwardInfo, Forwarder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

#[derive(Clone)]
pub struct ForwardItem {
    pub id: u64,
    pub kind: ForwardKind,
    pub spec: String,
    pub listen: String,
    pub dest: String,
}

/// A command from the UI thread to the session task.
pub enum Cmd {
    /// Bytes to write to the remote side.
    Data(Vec<u8>),
    /// PTY resize (`window_change` or Telnet NAWS).
    WindowChange { cols: u32, rows: u32 },
    /// Send a serial or Telnet break signal.
    Break,
    /// Start a live port forward on the SSH session.
    ForwardAdd { kind: ForwardKind, spec: String },
    /// Stop a running port forward by id.
    ForwardStop { id: u64 },
    /// List a remote directory over SFTP.
    SftpList { path: String },
    /// Create a remote directory over SFTP.
    SftpMkdir { path: String },
    /// Remove a remote file or directory over SFTP.
    SftpRemove { path: String, is_dir: bool },
    /// Rename a remote file or directory over SFTP.
    SftpRename { from: String, to: String },
    /// Download a remote file to a local path over SFTP.
    SftpDownload { remote: String, local: PathBuf },
    /// Upload a local file to a remote path over SFTP.
    SftpUpload { local: PathBuf, remote: String },
}

/// An event from the SSH task to the UI thread.
pub enum Evt {
    /// The connect task needs an answer from the user.
    Ask(Question),
    /// The shell channel is open; terminal rendering can begin.
    Ready,
    /// Output from the shell (stdout/stderr merged).
    Data(Vec<u8>),
    /// Updated list of active port forwards (plus optional status/error message).
    Forwards {
        list: Vec<ForwardItem>,
        status: Option<(String, bool)>,
    },
    /// Updated SFTP directory listing.
    SftpListed {
        path: String,
        entries: Vec<DirEntry>,
        status: Option<(String, bool)>,
    },
    /// Status or error message for an SFTP operation.
    SftpStatus { message: String, is_error: bool },
    /// The connection failed or the channel closed.
    Closed(String),
}

/// A question from the connect task. The task blocks until `reply` is
/// answered (or dropped, which counts as cancel/reject).
pub enum Question {
    Secret {
        prompt: String,
        reply: std_mpsc::Sender<Option<String>>,
    },
    HostKey {
        host: String,
        port: u16,
        fingerprint: String,
        reply: std_mpsc::Sender<bool>,
    },
    KeyboardInteractive {
        name: String,
        instructions: String,
        prompts: Vec<KiPrompt>,
        reply: std_mpsc::Sender<Option<Vec<String>>>,
    },
}

/// Turns prompter calls into [`Question`]s for the UI.
struct GuiPrompter {
    evt_tx: mpsc::UnboundedSender<Evt>,
    notify: egui::Context,
}

impl GuiPrompter {
    fn ask<T>(&self, make: impl FnOnce(std_mpsc::Sender<T>) -> Question) -> Option<T> {
        let (tx, rx) = std_mpsc::channel();
        self.evt_tx.send(Evt::Ask(make(tx))).ok()?;
        self.notify.request_repaint();
        rx.recv().ok()
    }
}

impl Prompter for GuiPrompter {
    fn secret(&self, prompt: &str) -> Option<String> {
        self.ask(|reply| Question::Secret {
            prompt: prompt.to_string(),
            reply,
        })
        .flatten()
    }

    fn confirm_host_key(&self, host: &str, port: u16, fingerprint: &str) -> bool {
        self.ask(|reply| Question::HostKey {
            host: host.to_string(),
            port,
            fingerprint: fingerprint.to_string(),
            reply,
        })
        .unwrap_or(false)
    }

    fn keyboard_interactive(
        &self,
        name: &str,
        instructions: &str,
        prompts: &[KiPrompt],
    ) -> Option<Vec<String>> {
        self.ask(|reply| Question::KeyboardInteractive {
            name: name.to_string(),
            instructions: instructions.to_string(),
            prompts: prompts.to_vec(),
            reply,
        })
        .flatten()
    }
}

/// Connects and authenticates (asking the UI for anything it needs), opens
/// a shell or serial/TCP line, then drives it until it closes or the UI drops
/// its sender.
pub async fn connect_and_run(
    target: Target,
    term_type: String,
    cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    evt_tx: mpsc::UnboundedSender<Evt>,
    notify: egui::Context,
) {
    match target.protocol {
        Protocol::Ssh => {
            let prompter = Arc::new(GuiPrompter {
                evt_tx: evt_tx.clone(),
                notify: notify.clone(),
            });
            let result = Session::connect_via(
                &target.jump,
                &target.host,
                target.port,
                &target.user,
                &target.auth,
                prompter.clone(),
                Arc::new(KnownHosts { prompter }),
            )
            .await;

            match result {
                Ok(session) => {
                    run_connected(
                        session,
                        target.forwards,
                        cmd_rx,
                        &evt_tx,
                        &notify,
                        &term_type,
                    )
                    .await
                }
                Err(e) => {
                    let msg = match e.hint() {
                        Some(hint) => format!("{e}\nHint: {hint}"),
                        None => e.to_string(),
                    };
                    let _ = evt_tx.send(Evt::Closed(msg));
                    notify.request_repaint();
                }
            }
        }
        Protocol::Serial => run_serial(target, cmd_rx, &evt_tx, &notify).await,
        Protocol::Telnet | Protocol::Raw => {
            run_tcp(target, &term_type, cmd_rx, &evt_tx, &notify).await
        }
    }
}

struct RunningForward {
    item: ForwardItem,
    active: ActiveForward,
}

struct SshTools {
    session: Session,
    forwarder: Forwarder,
    forwards: Vec<RunningForward>,
    next_id: u64,
    sftp: Option<SftpSession>,
    sftp_dir: String,
}

impl SshTools {
    fn new(mut session: Session) -> Self {
        let forwarder = Forwarder::new(&mut session);
        Self {
            session,
            forwarder,
            forwards: Vec::new(),
            next_id: 1,
            sftp: None,
            sftp_dir: ".".to_string(),
        }
    }

    async fn start_rule(&mut self, rule: &ForwardRule) -> Result<String, String> {
        let active = self
            .forwarder
            .start(rule)
            .await
            .map_err(|e| e.to_string())?;
        let summary = active.info.to_string();
        let (listen, dest) = match &active.info {
            ForwardInfo::Local { local, dest } => (local.to_string(), dest.clone()),
            ForwardInfo::Remote { port, dest } => (format!("server :{port}"), dest.clone()),
            ForwardInfo::Dynamic { local } => (local.to_string(), "SOCKS5".to_string()),
        };
        let id = self.next_id;
        self.next_id += 1;
        self.forwards.push(RunningForward {
            item: ForwardItem {
                id,
                kind: rule.kind,
                spec: forward_spec(rule),
                listen,
                dest,
            },
            active,
        });
        Ok(summary)
    }

    fn forward_items(&self) -> Vec<ForwardItem> {
        self.forwards.iter().map(|f| f.item.clone()).collect()
    }

    async fn stop_forward(&mut self, id: u64) -> Result<String, String> {
        let Some(pos) = self.forwards.iter().position(|f| f.item.id == id) else {
            return Err("forward not found".into());
        };
        let f = self.forwards.remove(pos);
        let spec = f.item.spec;
        f.active.stop().await.map_err(|e| e.to_string())?;
        Ok(format!("Stopped forward {spec}"))
    }

    async fn stop_all_forwards(&mut self) {
        for f in self.forwards.drain(..) {
            let _ = f.active.stop().await;
        }
    }

    async fn ensure_sftp(&mut self) -> Result<&SftpSession, String> {
        if self.sftp.is_none() {
            let s = sftp::open(&self.session).await.map_err(|e| e.to_string())?;
            self.sftp = Some(s);
        }
        Ok(self.sftp.as_ref().expect("sftp initialized"))
    }

    async fn list_dir(&mut self, path: &str) -> Result<(String, Vec<DirEntry>), String> {
        let target = if path.is_empty() { "." } else { path };
        let sftp = self.ensure_sftp().await?;
        let canon = sftp::canonicalize(sftp, target)
            .await
            .map_err(|e| e.to_string())?;
        let mut entries = sftp::list(sftp, &canon).await.map_err(|e| e.to_string())?;
        entries.retain(|e| e.name != "." && e.name != "..");
        entries.sort_by(|a, b| {
            b.is_dir
                .cmp(&a.is_dir)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        self.sftp_dir = canon.clone();
        Ok((canon, entries))
    }
}

/// Drives an already-connected session's shell channel.
async fn run_connected(
    session: Session,
    initial_forwards: Vec<ForwardRule>,
    mut cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    evt_tx: &mpsc::UnboundedSender<Evt>,
    notify: &egui::Context,
    term_type: &str,
) {
    // The real size arrives as a WindowChange once the UI measures itself.
    let mut channel = match session.open_shell(term_type, 80, 24).await {
        Ok(c) => c,
        Err(e) => {
            let _ = evt_tx.send(Evt::Closed(format!("opening shell: {e}")));
            notify.request_repaint();
            let _ = session.disconnect().await;
            return;
        }
    };
    let mut tools = SshTools::new(session);
    let mut init_status = None;
    for rule in &initial_forwards {
        if let Err(e) = tools.start_rule(rule).await {
            init_status = Some((format!("forward {rule}: {e}"), true));
        }
    }
    let _ = evt_tx.send(Evt::Ready);
    let _ = evt_tx.send(Evt::Forwards {
        list: tools.forward_items(),
        status: init_status,
    });
    notify.request_repaint();

    loop {
        tokio::select! {
            msg = channel.wait() => {
                match msg {
                    Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                        if evt_tx.send(Evt::Data(data.to_vec())).is_err() {
                            break; // UI gone
                        }
                        notify.request_repaint();
                    }
                    Some(ChannelMsg::ExitStatus { .. }) | Some(ChannelMsg::Close) | None => {
                        let _ = evt_tx.send(Evt::Closed("connection closed".into()));
                        notify.request_repaint();
                        break;
                    }
                    _ => {}
                }
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(Cmd::Data(bytes)) => { channel.data(&bytes[..]).await.ok(); }
                    Some(Cmd::WindowChange { cols, rows }) => {
                        channel.window_change(cols, rows, 0, 0).await.ok();
                    }
                    Some(Cmd::Break) => {}
                    Some(Cmd::ForwardAdd { kind, spec }) => {
                        let status = match parse_forward(spec.trim(), kind) {
                            Ok(rule) => match tools.start_rule(&rule).await {
                                Ok(msg) => Some((msg, false)),
                                Err(e) => Some((e, true)),
                            },
                            Err(e) => Some((e.to_string(), true)),
                        };
                        let _ = evt_tx.send(Evt::Forwards {
                            list: tools.forward_items(),
                            status,
                        });
                        notify.request_repaint();
                    }
                    Some(Cmd::ForwardStop { id }) => {
                        let status = match tools.stop_forward(id).await {
                            Ok(msg) => Some((msg, false)),
                            Err(e) => Some((e, true)),
                        };
                        let _ = evt_tx.send(Evt::Forwards {
                            list: tools.forward_items(),
                            status,
                        });
                        notify.request_repaint();
                    }
                    Some(Cmd::SftpList { path }) => {
                        match tools.list_dir(&path).await {
                            Ok((canon, entries)) => {
                                let _ = evt_tx.send(Evt::SftpListed {
                                    path: canon,
                                    entries,
                                    status: None,
                                });
                            }
                            Err(e) => {
                                let _ = evt_tx.send(Evt::SftpStatus {
                                    message: e,
                                    is_error: true,
                                });
                            }
                        }
                        notify.request_repaint();
                    }
                    Some(Cmd::SftpMkdir { path }) => {
                        let res = async {
                            let sftp = tools.ensure_sftp().await?;
                            sftp::create_dir(sftp, &path)
                                .await
                                .map_err(|e| e.to_string())
                        }.await;
                        match res {
                            Ok(()) => {
                                let cur = tools.sftp_dir.clone();
                                if let Ok((canon, entries)) = tools.list_dir(&cur).await {
                                    let _ = evt_tx.send(Evt::SftpListed {
                                        path: canon,
                                        entries,
                                        status: Some((format!("Created folder {path}"), false)),
                                    });
                                }
                            }
                            Err(e) => {
                                let _ = evt_tx.send(Evt::SftpStatus {
                                    message: format!("mkdir failed: {e}"),
                                    is_error: true,
                                });
                            }
                        }
                        notify.request_repaint();
                    }
                    Some(Cmd::SftpRemove { path, is_dir }) => {
                        let res = async {
                            let sftp = tools.ensure_sftp().await?;
                            if is_dir {
                                sftp::remove_dir(sftp, &path).await.map_err(|e| e.to_string())
                            } else {
                                sftp::remove_file(sftp, &path).await.map_err(|e| e.to_string())
                            }
                        }.await;
                        match res {
                            Ok(()) => {
                                let cur = tools.sftp_dir.clone();
                                if let Ok((canon, entries)) = tools.list_dir(&cur).await {
                                    let _ = evt_tx.send(Evt::SftpListed {
                                        path: canon,
                                        entries,
                                        status: Some((format!("Deleted {path}"), false)),
                                    });
                                }
                            }
                            Err(e) => {
                                let _ = evt_tx.send(Evt::SftpStatus {
                                    message: format!("Delete failed: {e}"),
                                    is_error: true,
                                });
                            }
                        }
                        notify.request_repaint();
                    }
                    Some(Cmd::SftpRename { from, to }) => {
                        let res = async {
                            let sftp = tools.ensure_sftp().await?;
                            sftp::rename(sftp, &from, &to).await.map_err(|e| e.to_string())
                        }.await;
                        match res {
                            Ok(()) => {
                                let cur = tools.sftp_dir.clone();
                                if let Ok((canon, entries)) = tools.list_dir(&cur).await {
                                    let _ = evt_tx.send(Evt::SftpListed {
                                        path: canon,
                                        entries,
                                        status: Some((format!("Renamed to {to}"), false)),
                                    });
                                }
                            }
                            Err(e) => {
                                let _ = evt_tx.send(Evt::SftpStatus {
                                    message: format!("Rename failed: {e}"),
                                    is_error: true,
                                });
                            }
                        }
                        notify.request_repaint();
                    }
                    Some(Cmd::SftpDownload { remote, local }) => {
                        let res = async {
                            let sftp = tools.ensure_sftp().await?;
                            sftp::get(sftp, &remote, &local).await.map_err(|e| e.to_string())
                        }.await;
                        match res {
                            Ok(bytes) => {
                                let _ = evt_tx.send(Evt::SftpStatus {
                                    message: format!(
                                        "Downloaded {} ({bytes} B)",
                                        local.display()
                                    ),
                                    is_error: false,
                                });
                            }
                            Err(e) => {
                                let _ = evt_tx.send(Evt::SftpStatus {
                                    message: format!("Download failed: {e}"),
                                    is_error: true,
                                });
                            }
                        }
                        notify.request_repaint();
                    }
                    Some(Cmd::SftpUpload { local, remote }) => {
                        let res = async {
                            let sftp = tools.ensure_sftp().await?;
                            sftp::put(sftp, &local, &remote).await.map_err(|e| e.to_string())
                        }.await;
                        match res {
                            Ok(bytes) => {
                                let cur = tools.sftp_dir.clone();
                                if let Ok((canon, entries)) = tools.list_dir(&cur).await {
                                    let _ = evt_tx.send(Evt::SftpListed {
                                        path: canon,
                                        entries,
                                        status: Some((
                                            format!("Uploaded {remote} ({bytes} B)"),
                                            false,
                                        )),
                                    });
                                }
                            }
                            Err(e) => {
                                let _ = evt_tx.send(Evt::SftpStatus {
                                    message: format!("Upload failed: {e}"),
                                    is_error: true,
                                });
                            }
                        }
                        notify.request_repaint();
                    }
                    None => break, // UI dropped the sender: shut down
                }
            }
        }
    }

    tools.stop_all_forwards().await;
    let _ = tools.session.disconnect().await;
}

async fn run_serial(
    target: Target,
    mut cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    evt_tx: &mpsc::UnboundedSender<Evt>,
    notify: &egui::Context,
) {
    let settings = target.serial.unwrap_or_default();
    let device = target.host.clone();
    let line =
        match tokio::task::spawn_blocking(move || serial::Line::open(&device, &settings)).await {
            Ok(Ok(line)) => line,
            Ok(Err(e)) => {
                let _ = evt_tx.send(Evt::Closed(e.to_string()));
                notify.request_repaint();
                return;
            }
            Err(e) => {
                let _ = evt_tx.send(Evt::Closed(e.to_string()));
                notify.request_repaint();
                return;
            }
        };
    let serial::Line {
        mut reader,
        mut writer,
        breaker,
    } = line;
    let _ = evt_tx.send(Evt::Ready);
    notify.request_repaint();

    let mut buf = [0u8; 16 * 1024];
    loop {
        tokio::select! {
            r = reader.read(&mut buf) => match r {
                Ok(0) => {
                    let _ = evt_tx.send(Evt::Closed("serial port closed".into()));
                    notify.request_repaint();
                    break;
                }
                Ok(n) => {
                    if evt_tx.send(Evt::Data(buf[..n].to_vec())).is_err() {
                        break;
                    }
                    notify.request_repaint();
                }
                Err(e) => {
                    let _ = evt_tx.send(Evt::Closed(format!("reading serial port: {e}")));
                    notify.request_repaint();
                    break;
                }
            },
            cmd = cmd_rx.recv() => match cmd {
                Some(Cmd::Data(bytes)) => {
                    if writer.write_all(&bytes).await.is_err() || writer.flush().await.is_err() {
                        let _ = evt_tx.send(Evt::Closed("writing serial port failed".into()));
                        notify.request_repaint();
                        break;
                    }
                }
                Some(Cmd::Break) => {
                    let brk = breaker.clone();
                    let _ = tokio::task::spawn_blocking(move || brk.send()).await;
                }
                Some(_) => {}
                None => break,
            },
        }
    }
}

async fn run_tcp(
    target: Target,
    term_type: &str,
    mut cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    evt_tx: &mpsc::UnboundedSender<Evt>,
    notify: &egui::Context,
) {
    let line = match TcpLine::connect(
        target.protocol,
        &target.host,
        target.port,
        term_type,
        (80, 24),
    )
    .await
    {
        Ok(line) => line,
        Err(e) => {
            let _ = evt_tx.send(Evt::Closed(e.to_string()));
            notify.request_repaint();
            return;
        }
    };
    let TcpLine {
        mut reader,
        mut writer,
        mut filter,
    } = line;
    let _ = evt_tx.send(Evt::Ready);
    notify.request_repaint();

    let mut buf = [0u8; 16 * 1024];
    loop {
        tokio::select! {
            r = reader.read(&mut buf) => match r {
                Ok(0) => {
                    let _ = evt_tx.send(Evt::Closed("connection closed".into()));
                    notify.request_repaint();
                    break;
                }
                Ok(n) => {
                    let mut data = Vec::with_capacity(n);
                    let mut reply = Vec::new();
                    filter.receive(&buf[..n], &mut data, &mut reply);
                    if !reply.is_empty() && writer.write_all(&reply).await.is_ok() {
                        writer.flush().await.ok();
                    }
                    if !data.is_empty() {
                        if evt_tx.send(Evt::Data(data)).is_err() {
                            break;
                        }
                        notify.request_repaint();
                    }
                }
                Err(e) => {
                    let _ = evt_tx.send(Evt::Closed(format!("reading socket: {e}")));
                    notify.request_repaint();
                    break;
                }
            },
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { break };
                let out = match cmd {
                    Cmd::Data(bytes) => Some(filter.encode(&bytes)),
                    Cmd::WindowChange { cols, rows } => {
                        let c = cols.min(u16::MAX as u32) as u16;
                        let r = rows.min(u16::MAX as u32) as u16;
                        filter.resize(c, r)
                    }
                    Cmd::Break => filter.brk(),
                    _ => None,
                };
                if let Some(bytes) = out
                    && (writer.write_all(&bytes).await.is_err() || writer.flush().await.is_err())
                {
                    let _ = evt_tx.send(Evt::Closed("writing socket failed".into()));
                    notify.request_repaint();
                    break;
                }
            }
        }
    }
}
