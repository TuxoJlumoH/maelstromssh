//! The TUI event loop: connects a core [`Terminal`] to a live SSH shell
//! channel, serial port, or Telnet/raw TCP stream, forwarding keys/mouse/resize
//! to the remote side and remote output to the renderer, throttled to a steady
//! redraw cadence. On SSH sessions, `F12` opens an overlay for the SFTP file
//! browser and live port-forward manager.

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{
    Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEventKind,
};
use maelstromssh_core::config::{ForwardKind, ForwardRule, forward_spec, parse_forward};
use maelstromssh_core::serial;
use maelstromssh_core::session_log::SessionLog;
use maelstromssh_core::sftp::{self, DirEntry, SftpSession};
use maelstromssh_core::ssh::{Channel, ChannelMsg, Msg, Session};
use maelstromssh_core::tcp::{Filter, TcpLine};
use maelstromssh_core::term::Terminal;
use maelstromssh_core::tunnel::{ActiveForward, ForwardInfo, Forwarder};
use ratatui::Terminal as RatuiTerminal;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{self, EventStream};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::layout::{Constraint, Direction, Layout};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_stream::StreamExt;

use crate::input::{ScrollAction, encode_key, encode_sgr_mouse, scroll_action};
use crate::render::{FileRow, ForwardRow, GridView, OverlayTab, OverlayView, StatusBar};

pub struct RunningForward {
    pub kind: ForwardKind,
    pub spec: String,
    pub listen: String,
    pub dest: String,
    active: ActiveForward,
}

/// SSH session state: shell channel plus live port-forwarder and lazy SFTP.
pub struct SshBackend {
    session: Session,
    channel: Channel<Msg>,
    forwarder: Forwarder,
    pub forwards: Vec<RunningForward>,
    sftp: Option<SftpSession>,
    pub initial_error: Option<String>,
}

impl SshBackend {
    pub async fn new(
        mut session: Session,
        channel: Channel<Msg>,
        initial_rules: &[ForwardRule],
    ) -> Self {
        let forwarder = Forwarder::new(&mut session);
        let mut ssh = Self {
            session,
            channel,
            forwarder,
            forwards: Vec::new(),
            sftp: None,
            initial_error: None,
        };
        for rule in initial_rules {
            if let Err(e) = ssh.start_rule(rule).await {
                let msg = format!("forward {rule}: {e}");
                eprintln!("warning: {msg}");
                ssh.initial_error = Some(msg);
            }
        }
        ssh
    }

    pub async fn start_rule(&mut self, rule: &ForwardRule) -> std::result::Result<String, String> {
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
        self.forwards.push(RunningForward {
            kind: rule.kind,
            spec: forward_spec(rule),
            listen,
            dest,
            active,
        });
        Ok(summary)
    }

    pub async fn add_forward(
        &mut self,
        kind: ForwardKind,
        spec: &str,
    ) -> std::result::Result<String, String> {
        let rule = parse_forward(spec.trim(), kind).map_err(|e| e.to_string())?;
        self.start_rule(&rule).await
    }

    pub async fn stop_forward(&mut self, idx: usize) -> std::result::Result<String, String> {
        if idx >= self.forwards.len() {
            return Err("no forward selected".into());
        }
        let f = self.forwards.remove(idx);
        let spec = f.spec;
        f.active.stop().await.map_err(|e| e.to_string())?;
        Ok(format!("Stopped forward {spec}"))
    }

    pub async fn ensure_sftp(&mut self) -> std::result::Result<&SftpSession, String> {
        if self.sftp.is_none() {
            let s = sftp::open(&self.session).await.map_err(|e| e.to_string())?;
            self.sftp = Some(s);
        }
        Ok(self.sftp.as_ref().expect("sftp initialized"))
    }

    pub async fn shutdown(&mut self) {
        for f in self.forwards.drain(..) {
            let _ = f.active.stop().await;
        }
        let _ = self.session.disconnect().await;
    }
}

/// The underlying byte transport driven by the TUI event loop.
pub enum Backend {
    Ssh(Box<SshBackend>),
    Serial(serial::Line),
    Tcp(TcpLine),
}

impl Backend {
    fn is_ssh(&self) -> bool {
        matches!(self, Backend::Ssh(_))
    }

    fn supports_break(&self) -> bool {
        matches!(
            self,
            Backend::Serial(_)
                | Backend::Tcp(TcpLine {
                    filter: Filter::Telnet(_),
                    ..
                })
        )
    }

    fn forward_count(&self) -> usize {
        match self {
            Backend::Ssh(ssh) => ssh.forwards.len(),
            _ => 0,
        }
    }

    async fn send_bytes(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        match self {
            Backend::Ssh(ssh) => {
                ssh.channel.data(bytes).await.ok();
            }
            Backend::Serial(line) => {
                if line.writer.write_all(bytes).await.is_ok() {
                    line.writer.flush().await.ok();
                }
            }
            Backend::Tcp(line) => {
                let encoded = line.filter.encode(bytes);
                if line.writer.write_all(&encoded).await.is_ok() {
                    line.writer.flush().await.ok();
                }
            }
        }
    }

    async fn send_resize(&mut self, cols: u16, rows: u16) {
        match self {
            Backend::Ssh(ssh) => {
                ssh.channel
                    .window_change(cols as u32, rows as u32, 0, 0)
                    .await
                    .ok();
            }
            Backend::Serial(_) => {}
            Backend::Tcp(line) => {
                if let Some(raw) = line.filter.resize(cols, rows)
                    && line.writer.write_all(&raw).await.is_ok()
                {
                    line.writer.flush().await.ok();
                }
            }
        }
    }

    async fn send_break(&mut self) {
        match self {
            Backend::Ssh(_) => {}
            Backend::Serial(line) => {
                let breaker = line.breaker.clone();
                let _ = tokio::task::spawn_blocking(move || breaker.send()).await;
            }
            Backend::Tcp(line) => {
                if let Some(brk) = line.filter.brk()
                    && line.writer.write_all(&brk).await.is_ok()
                {
                    line.writer.flush().await.ok();
                }
            }
        }
    }

    /// Reads the next chunk of terminal output from the backend, returning
    /// `None` when the remote side closes the connection.
    async fn recv_output(&mut self, buf: &mut [u8]) -> Option<Vec<u8>> {
        match self {
            Backend::Ssh(ssh) => loop {
                match ssh.channel.wait().await {
                    Some(ChannelMsg::Data { data })
                    | Some(ChannelMsg::ExtendedData { data, .. }) => {
                        return Some(data.to_vec());
                    }
                    Some(ChannelMsg::ExitStatus { .. }) | Some(ChannelMsg::Close) | None => {
                        return None;
                    }
                    _ => {}
                }
            },
            Backend::Serial(line) => match line.reader.read(buf).await {
                Ok(0) | Err(_) => None,
                Ok(n) => Some(buf[..n].to_vec()),
            },
            Backend::Tcp(line) => loop {
                match line.reader.read(buf).await {
                    Ok(0) | Err(_) => return None,
                    Ok(n) => {
                        let mut data = Vec::with_capacity(n);
                        let mut reply = Vec::new();
                        line.filter.receive(&buf[..n], &mut data, &mut reply);
                        if !reply.is_empty() && line.writer.write_all(&reply).await.is_ok() {
                            line.writer.flush().await.ok();
                        }
                        if !data.is_empty() {
                            return Some(data);
                        }
                    }
                }
            },
        }
    }

    async fn shutdown(&mut self) {
        if let Backend::Ssh(ssh) = self {
            ssh.shutdown().await;
        }
    }
}

enum PromptMode {
    Download { remote_name: String, input: String },
    Upload { input: String },
    Mkdir { input: String },
    Rename { old_name: String, input: String },
    Goto { input: String },
    DeleteConfirm { name: String, is_dir: bool },
    ForwardAdd { kind: ForwardKind, input: String },
}

impl PromptMode {
    fn label_and_input(&self) -> (&'static str, &str) {
        match self {
            PromptMode::Download { input, .. } => ("Download to local path: ", input.as_str()),
            PromptMode::Upload { input } => ("Upload local file path: ", input.as_str()),
            PromptMode::Mkdir { input } => ("New folder name: ", input.as_str()),
            PromptMode::Rename { input, .. } => ("Rename to: ", input.as_str()),
            PromptMode::Goto { input } => ("Go to remote path: ", input.as_str()),
            PromptMode::DeleteConfirm { .. } => ("Confirm delete (y/n): ", ""),
            PromptMode::ForwardAdd { kind, input } => {
                let lbl = match kind {
                    ForwardKind::Local => "Local forward (-L [bind:]port:host:hostport): ",
                    ForwardKind::Remote => "Remote forward (-R [bind:]port:host:hostport): ",
                    ForwardKind::Dynamic => "SOCKS5 forward (-D [bind:]port): ",
                };
                (lbl, input.as_str())
            }
        }
    }

    fn input_mut(&mut self) -> Option<&mut String> {
        match self {
            PromptMode::Download { input, .. }
            | PromptMode::Upload { input }
            | PromptMode::Mkdir { input }
            | PromptMode::Rename { input, .. }
            | PromptMode::Goto { input }
            | PromptMode::ForwardAdd { input, .. } => Some(input),
            PromptMode::DeleteConfirm { .. } => None,
        }
    }
}

struct OverlayState {
    open: bool,
    tab: OverlayTab,
    sftp_path: String,
    files: Vec<FileRow>,
    file_selected: usize,
    forward_selected: usize,
    prompt: Option<PromptMode>,
    status: Option<(String, bool)>,
}

impl OverlayState {
    fn new(initial_error: Option<String>) -> Self {
        Self {
            open: false,
            tab: OverlayTab::Files,
            sftp_path: String::new(),
            files: Vec::new(),
            file_selected: 0,
            forward_selected: 0,
            prompt: None,
            status: initial_error.map(|e| (e, true)),
        }
    }

    async fn load_dir(&mut self, ssh: &mut SshBackend, target_path: &str) {
        let res: std::result::Result<(String, Vec<DirEntry>), String> = async {
            let sftp = ssh.ensure_sftp().await?;
            let path = if target_path.is_empty() {
                "."
            } else {
                target_path
            };
            let canon = sftp::canonicalize(sftp, path)
                .await
                .map_err(|e| e.to_string())?;
            let entries = sftp::list(sftp, &canon).await.map_err(|e| e.to_string())?;
            Ok((canon, entries))
        }
        .await;

        match res {
            Ok((canon, mut entries)) => {
                entries.retain(|e| e.name != "." && e.name != "..");
                entries.sort_by(|a, b| {
                    b.is_dir
                        .cmp(&a.is_dir)
                        .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                });
                let mut rows = Vec::with_capacity(entries.len() + 1);
                if canon != "/" {
                    rows.push(FileRow {
                        name: "..".to_string(),
                        is_dir: true,
                        is_symlink: false,
                        is_parent: true,
                        size: 0,
                    });
                }
                for e in entries {
                    rows.push(FileRow {
                        name: e.name,
                        is_dir: e.is_dir,
                        is_symlink: e.is_symlink,
                        is_parent: false,
                        size: e.size,
                    });
                }
                self.sftp_path = canon;
                self.files = rows;
                self.file_selected = 0;
            }
            Err(e) => {
                self.status = Some((format!("SFTP error: {e}"), true));
            }
        }
    }

    fn join_remote(&self, name: &str) -> String {
        if name.starts_with('/') || self.sftp_path.is_empty() || self.sftp_path == "." {
            name.to_string()
        } else if self.sftp_path.ends_with('/') {
            format!("{}{name}", self.sftp_path)
        } else {
            format!("{}/{name}", self.sftp_path)
        }
    }

    async fn handle_key(&mut self, k: &KeyEvent, ssh: &mut SshBackend) {
        if let Some(mut mode) = self.prompt.take() {
            match &mut mode {
                PromptMode::DeleteConfirm { name, is_dir } => match k.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                        let full = self.join_remote(name);
                        let dir = *is_dir;
                        let target_name = name.clone();
                        let res: std::result::Result<(), String> = async {
                            let sftp = ssh.ensure_sftp().await?;
                            if dir {
                                sftp::remove_dir(sftp, &full)
                                    .await
                                    .map_err(|e| e.to_string())
                            } else {
                                sftp::remove_file(sftp, &full)
                                    .await
                                    .map_err(|e| e.to_string())
                            }
                        }
                        .await;
                        match res {
                            Ok(()) => {
                                let cur = self.sftp_path.clone();
                                self.load_dir(ssh, &cur).await;
                                self.status = Some((format!("Deleted '{target_name}'"), false));
                            }
                            Err(e) => {
                                self.status = Some((format!("Delete failed: {e}"), true));
                            }
                        }
                    }
                    KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                        self.status = None;
                    }
                    _ => {
                        self.prompt = Some(mode);
                    }
                },
                _ => match k.code {
                    KeyCode::Esc => {
                        self.status = None;
                    }
                    KeyCode::Backspace => {
                        if let Some(input) = mode.input_mut() {
                            input.pop();
                        }
                        self.prompt = Some(mode);
                    }
                    KeyCode::Char(c)
                        if !k.modifiers.contains(KeyModifiers::CONTROL)
                            && !k.modifiers.contains(KeyModifiers::ALT) =>
                    {
                        if let Some(input) = mode.input_mut() {
                            input.push(c);
                        }
                        self.prompt = Some(mode);
                    }
                    KeyCode::Enter => {
                        self.execute_prompt(mode, ssh).await;
                    }
                    _ => {
                        self.prompt = Some(mode);
                    }
                },
            }
            return;
        }

        match k.code {
            KeyCode::Esc | KeyCode::F(12) => {
                self.open = false;
            }
            KeyCode::Tab | KeyCode::BackTab => {
                self.tab = match self.tab {
                    OverlayTab::Files => OverlayTab::Forwards,
                    OverlayTab::Forwards => OverlayTab::Files,
                };
                if self.tab == OverlayTab::Files && self.sftp_path.is_empty() {
                    self.load_dir(ssh, ".").await;
                }
            }
            _ => match self.tab {
                OverlayTab::Files => self.handle_files_key(k, ssh).await,
                OverlayTab::Forwards => self.handle_forwards_key(k, ssh).await,
            },
        }
    }

    async fn execute_prompt(&mut self, mode: PromptMode, ssh: &mut SshBackend) {
        match mode {
            PromptMode::Download { remote_name, input } => {
                let dest = input.trim();
                if dest.is_empty() {
                    return;
                }
                let remote = self.join_remote(&remote_name);
                let res: std::result::Result<u64, String> = async {
                    let sftp = ssh.ensure_sftp().await?;
                    sftp::get(sftp, &remote, Path::new(dest))
                        .await
                        .map_err(|e| e.to_string())
                }
                .await;
                match res {
                    Ok(bytes) => {
                        self.status = Some((
                            format!(
                                "Downloaded '{remote_name}' -> {dest} ({})",
                                crate::render::format_size(bytes)
                            ),
                            false,
                        ));
                    }
                    Err(e) => {
                        self.status = Some((format!("Download failed: {e}"), true));
                    }
                }
            }
            PromptMode::Upload { input } => {
                let local_str = input.trim();
                if local_str.is_empty() {
                    return;
                }
                let local_path = Path::new(local_str);
                let Some(file_name) = local_path.file_name().and_then(|n| n.to_str()) else {
                    self.status = Some(("Invalid local file path".into(), true));
                    return;
                };
                let remote = self.join_remote(file_name);
                let fname = file_name.to_string();
                let res: std::result::Result<u64, String> = async {
                    let sftp = ssh.ensure_sftp().await?;
                    sftp::put(sftp, local_path, &remote)
                        .await
                        .map_err(|e| e.to_string())
                }
                .await;
                match res {
                    Ok(bytes) => {
                        let cur = self.sftp_path.clone();
                        self.load_dir(ssh, &cur).await;
                        self.status = Some((
                            format!("Uploaded '{fname}' ({})", crate::render::format_size(bytes)),
                            false,
                        ));
                    }
                    Err(e) => {
                        self.status = Some((format!("Upload failed: {e}"), true));
                    }
                }
            }
            PromptMode::Mkdir { input } => {
                let name = input.trim();
                if name.is_empty() {
                    return;
                }
                let remote = self.join_remote(name);
                let folder = name.to_string();
                let res: std::result::Result<(), String> = async {
                    let sftp = ssh.ensure_sftp().await?;
                    sftp::create_dir(sftp, &remote)
                        .await
                        .map_err(|e| e.to_string())
                }
                .await;
                match res {
                    Ok(()) => {
                        let cur = self.sftp_path.clone();
                        self.load_dir(ssh, &cur).await;
                        self.status = Some((format!("Created folder '{folder}'"), false));
                    }
                    Err(e) => {
                        self.status = Some((format!("mkdir failed: {e}"), true));
                    }
                }
            }
            PromptMode::Rename { old_name, input } => {
                let new_name = input.trim();
                if new_name.is_empty() || new_name == old_name {
                    return;
                }
                let from = self.join_remote(&old_name);
                let to = self.join_remote(new_name);
                let target = new_name.to_string();
                let res: std::result::Result<(), String> = async {
                    let sftp = ssh.ensure_sftp().await?;
                    sftp::rename(sftp, &from, &to)
                        .await
                        .map_err(|e| e.to_string())
                }
                .await;
                match res {
                    Ok(()) => {
                        let cur = self.sftp_path.clone();
                        self.load_dir(ssh, &cur).await;
                        self.status = Some((format!("Renamed '{old_name}' -> '{target}'"), false));
                    }
                    Err(e) => {
                        self.status = Some((format!("Rename failed: {e}"), true));
                    }
                }
            }
            PromptMode::Goto { input } => {
                let path = input.trim().to_string();
                if !path.is_empty() {
                    self.load_dir(ssh, &path).await;
                }
            }
            PromptMode::ForwardAdd { kind, input } => {
                let spec = input.trim();
                if spec.is_empty() {
                    return;
                }
                match ssh.add_forward(kind, spec).await {
                    Ok(summary) => {
                        self.forward_selected = ssh.forwards.len().saturating_sub(1);
                        self.status = Some((summary, false));
                    }
                    Err(e) => {
                        self.status = Some((format!("Forward failed: {e}"), true));
                    }
                }
            }
            PromptMode::DeleteConfirm { .. } => {}
        }
    }

    async fn handle_files_key(&mut self, k: &KeyEvent, ssh: &mut SshBackend) {
        let len = self.files.len();
        match k.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.file_selected = self.file_selected.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if len > 0 {
                    self.file_selected = (self.file_selected + 1).min(len - 1);
                }
            }
            KeyCode::Home => {
                self.file_selected = 0;
            }
            KeyCode::End => {
                if len > 0 {
                    self.file_selected = len - 1;
                }
            }
            KeyCode::PageUp => {
                self.file_selected = self.file_selected.saturating_sub(10);
            }
            KeyCode::PageDown => {
                if len > 0 {
                    self.file_selected = (self.file_selected + 10).min(len - 1);
                }
            }
            KeyCode::Backspace => {
                if self.sftp_path != "/" && !self.sftp_path.is_empty() {
                    let parent = self.join_remote("..");
                    self.load_dir(ssh, &parent).await;
                }
            }
            KeyCode::Enter => {
                if let Some(row) = self.files.get(self.file_selected)
                    && (row.is_dir || row.is_parent)
                {
                    let next = self.join_remote(&row.name);
                    self.load_dir(ssh, &next).await;
                }
            }
            KeyCode::Char('d') => {
                if let Some(row) = self.files.get(self.file_selected)
                    && !row.is_dir
                    && !row.is_parent
                {
                    self.prompt = Some(PromptMode::Download {
                        remote_name: row.name.clone(),
                        input: format!("./{}", row.name),
                    });
                }
            }
            KeyCode::Char('u') => {
                self.prompt = Some(PromptMode::Upload {
                    input: String::new(),
                });
            }
            KeyCode::Char('m') => {
                self.prompt = Some(PromptMode::Mkdir {
                    input: String::new(),
                });
            }
            KeyCode::Char('r') => {
                if let Some(row) = self.files.get(self.file_selected)
                    && !row.is_parent
                {
                    self.prompt = Some(PromptMode::Rename {
                        old_name: row.name.clone(),
                        input: row.name.clone(),
                    });
                }
            }
            KeyCode::Char('x') | KeyCode::Delete => {
                if let Some(row) = self.files.get(self.file_selected)
                    && !row.is_parent
                {
                    let name = row.name.clone();
                    let is_dir = row.is_dir;
                    self.status = Some((format!("Delete '{name}'? Press y to confirm."), false));
                    self.prompt = Some(PromptMode::DeleteConfirm { name, is_dir });
                }
            }
            KeyCode::Char('g') => {
                self.prompt = Some(PromptMode::Goto {
                    input: self.sftp_path.clone(),
                });
            }
            KeyCode::Char('R') => {
                let cur = if self.sftp_path.is_empty() {
                    ".".to_string()
                } else {
                    self.sftp_path.clone()
                };
                self.load_dir(ssh, &cur).await;
                self.status = Some(("Refreshed directory".into(), false));
            }
            _ => {}
        }
    }

    async fn handle_forwards_key(&mut self, k: &KeyEvent, ssh: &mut SshBackend) {
        let len = ssh.forwards.len();
        match k.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.forward_selected = self.forward_selected.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if len > 0 {
                    self.forward_selected = (self.forward_selected + 1).min(len - 1);
                }
            }
            KeyCode::Char('l') => {
                self.prompt = Some(PromptMode::ForwardAdd {
                    kind: ForwardKind::Local,
                    input: String::new(),
                });
            }
            KeyCode::Char('r') => {
                self.prompt = Some(PromptMode::ForwardAdd {
                    kind: ForwardKind::Remote,
                    input: String::new(),
                });
            }
            KeyCode::Char('d') => {
                self.prompt = Some(PromptMode::ForwardAdd {
                    kind: ForwardKind::Dynamic,
                    input: String::new(),
                });
            }
            KeyCode::Char('x') | KeyCode::Delete if len > 0 => {
                let idx = self.forward_selected.min(len - 1);
                match ssh.stop_forward(idx).await {
                    Ok(msg) => {
                        if self.forward_selected >= ssh.forwards.len() && !ssh.forwards.is_empty() {
                            self.forward_selected = ssh.forwards.len() - 1;
                        }
                        self.status = Some((msg, false));
                    }
                    Err(e) => {
                        self.status = Some((format!("Stop forward failed: {e}"), true));
                    }
                }
            }
            _ => {}
        }
    }
}

/// Runs the interactive session. Returns when the remote closes the channel,
/// the user quits (Ctrl+]), or an error occurs. Always restores the terminal.
pub async fn run(
    mut backend: Backend,
    mut term: Terminal,
    endpoint: String,
    mut log: Option<SessionLog>,
) -> Result<()> {
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, event::EnableMouseCapture)?;
    enable_raw_mode()?;

    let ratui_backend = CrosstermBackend::new(stdout);
    let mut terminal = RatuiTerminal::new(ratui_backend)?;
    terminal.hide_cursor()?;

    let outcome = event_loop(&mut terminal, &mut term, &mut backend, &endpoint, &mut log).await;

    disable_raw_mode().ok();
    execute!(
        std::io::stdout(),
        LeaveAlternateScreen,
        event::DisableMouseCapture
    )
    .ok();
    terminal.show_cursor().ok();

    backend.shutdown().await;

    // Preserve the last screen: the alternate screen is gone, so write the
    // grid's text to the primary screen before returning.
    dump_screen(&term);
    outcome
}

async fn event_loop(
    terminal: &mut RatuiTerminal<CrosstermBackend<std::io::Stdout>>,
    term: &mut Terminal,
    backend: &mut Backend,
    endpoint: &str,
    log: &mut Option<SessionLog>,
) -> Result<()> {
    let mut events = EventStream::new();
    let mut redraw = tokio::time::interval(Duration::from_millis(33));
    redraw.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_gen = term.generation().wrapping_sub(1);
    let mut overlay_dirty = false;
    let mut connected = true;
    let mut quit = false;
    let mut read_buf = [0u8; 16 * 1024];
    let can_break = backend.supports_break();
    let is_ssh = backend.is_ssh();
    let logging = log.is_some();
    let initial_err = match backend {
        Backend::Ssh(ssh) => ssh.initial_error.take(),
        _ => None,
    };
    let mut overlay = OverlayState::new(initial_err);

    loop {
        tokio::select! {
            _ = redraw.tick() => {
                let current_gen = term.generation();
                if current_gen != last_gen || overlay_dirty {
                    last_gen = current_gen;
                    overlay_dirty = false;
                    draw_frame(
                        terminal,
                        term,
                        backend,
                        &overlay,
                        endpoint,
                        connected,
                        can_break,
                        is_ssh,
                        logging,
                    )?;
                }
            }
            ev = events.next() => {
                match ev {
                    Some(Ok(Event::Key(k))) if k.kind != KeyEventKind::Release => {
                        if k.code == KeyCode::Char(']')
                            && k.modifiers.contains(KeyModifiers::CONTROL)
                        {
                            quit = true;
                        } else if overlay.open {
                            if let Backend::Ssh(ssh) = backend {
                                overlay.handle_key(&k, ssh).await;
                                overlay_dirty = true;
                            } else {
                                overlay.open = false;
                                overlay_dirty = true;
                            }
                        } else if is_ssh && k.code == KeyCode::F(12) && k.modifiers.is_empty() {
                            overlay.open = true;
                            if overlay.tab == OverlayTab::Files
                                && overlay.sftp_path.is_empty()
                                && let Backend::Ssh(ssh) = backend
                            {
                                overlay.load_dir(ssh, ".").await;
                            }
                            overlay_dirty = true;
                        } else if can_break && k.code == KeyCode::F(12) && k.modifiers.is_empty() {
                            backend.send_break().await;
                        } else if let Some(action) = scroll_action(&k) {
                            apply_scroll(term, action);
                        } else if let Some(bytes) = encode_key(
                            &k,
                            term.application_cursor_keys(),
                            term.application_keypad(),
                        ) {
                            backend.send_bytes(&bytes).await;
                        }
                    }
                    Some(Ok(Event::Paste(text))) if !overlay.open => {
                        let mut out = Vec::new();
                        if term.bracketed_paste() {
                            out.extend_from_slice(b"\x1b[200~");
                            out.extend_from_slice(text.as_bytes());
                            out.extend_from_slice(b"\x1b[201~");
                        } else {
                            out.extend_from_slice(text.as_bytes());
                        }
                        backend.send_bytes(&out).await;
                    }
                    Some(Ok(Event::Mouse(m))) if !overlay.open => {
                        handle_mouse(term, backend, m).await;
                    }
                    Some(Ok(Event::Resize(w, h))) => {
                        let rows = h.saturating_sub(1).max(1);
                        term.resize(w as u32, rows as u32);
                        backend.send_resize(w, rows).await;
                        overlay_dirty = true;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => {}
                }
            }
            chunk = backend.recv_output(&mut read_buf) => {
                match chunk {
                    Some(data) => {
                        if let Some(l) = log.as_mut() {
                            l.write(&data);
                            if let Some(err) = l.take_error() {
                                tracing::warn!("{err}");
                            }
                        }
                        term.feed(&data);
                        send_responses(term, backend).await;
                    }
                    None => {
                        connected = false;
                    }
                }
            }
        }

        if quit || !connected {
            break;
        }
    }

    if !connected {
        overlay.open = false;
        // Keep the final screen up until the user has seen it.
        draw_frame(
            terminal, term, backend, &overlay, endpoint, false, can_break, is_ssh, logging,
        )?;
        while let Some(ev) = events.next().await {
            if matches!(ev, Ok(Event::Key(k)) if k.kind == KeyEventKind::Press) {
                break;
            }
        }
    }
    Ok(())
}

fn apply_scroll(term: &mut Terminal, action: ScrollAction) {
    match action {
        ScrollAction::Up(n) => term.scroll_up(n),
        ScrollAction::Down(n) => term.scroll_down(n),
        ScrollAction::Top => {
            let n = term.scrollback_len();
            term.scroll_up(n);
        }
        ScrollAction::Bottom => term.scroll_to_bottom(),
    }
}

async fn handle_mouse(term: &mut Terminal, backend: &mut Backend, m: crossterm::event::MouseEvent) {
    if term.mouse_sgr() {
        let (button, release, motion) = match m.kind {
            MouseEventKind::Down(b) => (mouse_button(b), false, false),
            MouseEventKind::Up(b) => (mouse_button(b), true, false),
            MouseEventKind::Drag(b) => (mouse_button(b), false, true),
            MouseEventKind::ScrollUp => (64, false, false),
            MouseEventKind::ScrollDown => (65, false, false),
            _ => return,
        };
        let bytes = encode_sgr_mouse(m.column, m.row, button, release, motion, m.modifiers);
        backend.send_bytes(&bytes).await;
    } else {
        match m.kind {
            MouseEventKind::ScrollUp => term.scroll_up(3),
            MouseEventKind::ScrollDown => term.scroll_down(3),
            _ => {}
        }
    }
}

fn mouse_button(b: MouseButton) -> u8 {
    match b {
        MouseButton::Left => 0,
        MouseButton::Middle => 1,
        MouseButton::Right => 2,
    }
}

async fn send_responses(term: &mut Terminal, backend: &mut Backend) {
    let resp = term.take_responses();
    if !resp.is_empty() {
        backend.send_bytes(&resp).await;
    }
}

#[allow(clippy::too_many_arguments)]
fn draw_frame(
    terminal: &mut RatuiTerminal<CrosstermBackend<std::io::Stdout>>,
    term: &Terminal,
    backend: &Backend,
    overlay: &OverlayState,
    endpoint: &str,
    connected: bool,
    can_break: bool,
    is_ssh: bool,
    logging: bool,
) -> Result<()> {
    let label = term
        .title()
        .map(str::to_string)
        .unwrap_or_else(|| endpoint.to_string());
    let offset = term.viewport_offset();
    let fwd_count = backend.forward_count();
    let right = if !connected {
        "closed — press any key to exit".to_string()
    } else {
        let mut parts = Vec::new();
        if offset > 0 {
            parts.push(format!("{offset} lines up"));
        }
        if fwd_count > 0 {
            parts.push(format!("{fwd_count} fwd"));
        }
        if logging {
            parts.push("logging".to_string());
        }
        if is_ssh {
            parts.push("F12 files/fwd".to_string());
        } else if can_break {
            parts.push("F12 break".to_string());
        }
        parts.push("Ctrl-] quit".to_string());
        parts.join(" · ")
    };

    let forward_rows: Vec<ForwardRow> = match backend {
        Backend::Ssh(ssh) => ssh
            .forwards
            .iter()
            .map(|f| ForwardRow {
                kind_label: match f.kind {
                    ForwardKind::Local => "LOCAL",
                    ForwardKind::Remote => "REMOTE",
                    ForwardKind::Dynamic => "DYNAMIC",
                },
                listen: f.listen.clone(),
                dest: f.dest.clone(),
            })
            .collect(),
        _ => Vec::new(),
    };

    let prompt_view = overlay.prompt.as_ref().map(PromptMode::label_and_input);
    let status_view = overlay
        .status
        .as_ref()
        .map(|(msg, is_err)| (msg.as_str(), *is_err));

    terminal.draw(|f| {
        let area = f.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(1)])
            .split(area);
        f.render_widget(
            GridView {
                term,
                show_cursor: connected && !overlay.open && term.cursor_visible(),
            },
            chunks[0],
        );
        f.render_widget(
            StatusBar {
                left: format!(" {label}"),
                right: format!("{right} "),
                active: connected,
            },
            chunks[1],
        );
        if overlay.open {
            f.render_widget(
                OverlayView {
                    tab: overlay.tab,
                    sftp_path: &overlay.sftp_path,
                    files: &overlay.files,
                    file_selected: overlay.file_selected,
                    forwards: &forward_rows,
                    forward_selected: overlay.forward_selected,
                    prompt: prompt_view,
                    status: status_view,
                },
                chunks[0],
            );
        }
    })?;
    Ok(())
}

/// Writes the grid's visible text to the primary screen so the tail of the
/// session survives the alternate-screen teardown.
fn dump_screen(term: &Terminal) {
    let mut out = std::io::stdout();
    for row in 0..term.rows() {
        let text = term.viewport_line(row).text();
        let _ = writeln!(out, "{text}");
    }
    let _ = out.flush();
}
