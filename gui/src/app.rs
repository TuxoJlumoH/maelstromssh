//! The egui application: shows a connect form when started without a
//! target, owns the core [`Terminal`], answers the connect task's questions (password, passphrase, host key, 2FA) in dialogs, and
//! paints the grid + status bar. The SSH session lives on a background tokio
//! task (see [`crate::ssh`]); this module is purely single-threaded.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use egui::{Align2, Color32, FontId, Pos2, Rect, Stroke, pos2, vec2};
use maelstromssh_core::config::{
    FlowControl, ForwardKind, ForwardRule, Parity, ProfileStore, Protocol, SerialSettings,
    SshConfig, forward_spec, parse_forward,
};
use maelstromssh_core::prompt::KiPrompt;
use maelstromssh_core::serial::{self, PortInfo};
use maelstromssh_core::session_log::SessionLog;
use maelstromssh_core::sftp::DirEntry;
use maelstromssh_core::target::{AuthChoice, Target, TargetArgs};
use maelstromssh_core::term::Terminal;
use tokio::sync::mpsc;

use crate::keys::{self, KeyOut};
use crate::manage::{self, KeysWindow, KnownHostsWindow};
use crate::paint::{self, Palette};
use crate::ssh::{self, Cmd, Evt, ForwardItem, Question, TransferKind, TransferState};

/// Startup arguments passed from `main`.
#[derive(Clone)]
pub struct LaunchArgs {
    pub target: TargetArgs,
    pub protocol: Protocol,
    pub serial: SerialSettings,
    pub local: Vec<String>,
    pub remote: Vec<String>,
    pub dynamic: Vec<String>,
    pub log: Option<PathBuf>,
}

const ERROR_RED: Color32 = Color32::from_rgb(240, 80, 80);
const OK_GREEN: Color32 = Color32::from_rgb(90, 210, 120);

enum State {
    /// The connect form, shown when no target was given (or to change it).
    Setup(Box<ConnectForm>),
    Connecting,
    Secret {
        prompt: String,
        input: String,
        reply: std::sync::mpsc::Sender<Option<String>>,
    },
    HostKey {
        host: String,
        port: u16,
        fingerprint: String,
        reply: std::sync::mpsc::Sender<bool>,
    },
    KeyboardInteractive {
        name: String,
        instructions: String,
        prompts: Vec<KiPrompt>,
        answers: Vec<String>,
        reply: std::sync::mpsc::Sender<Option<Vec<String>>>,
    },
    Running,
    Failed(String),
}

impl State {
    fn from_question(q: Question) -> Self {
        match q {
            Question::Secret { prompt, reply } => State::Secret {
                prompt,
                input: String::new(),
                reply,
            },
            Question::HostKey {
                host,
                port,
                fingerprint,
                reply,
            } => State::HostKey {
                host,
                port,
                fingerprint,
                reply,
            },
            Question::KeyboardInteractive {
                name,
                instructions,
                prompts,
                reply,
            } => State::KeyboardInteractive {
                answers: vec![String::new(); prompts.len()],
                name,
                instructions,
                prompts,
                reply,
            },
        }
    }
}

/// What a dialog decided this frame.
enum Outcome {
    Pending,
    Answered,
    Retry,
    /// Back to the connect form.
    Edit,
    Quit,
}

/// The connect form's fields, plus the choices offered next to them.
struct ConnectForm {
    protocol: Protocol,
    target: String,
    profile: Option<String>,
    port: String,
    identity: String,
    jump: String,
    forwards: String,
    /// `None`: auto, or whatever the profile says.
    auth: Option<AuthChoice>,
    serial_baud: String,
    serial_data_bits: u8,
    serial_parity: Parity,
    serial_stop_bits: u8,
    serial_flow: FlowControl,
    log_enabled: bool,
    log_path: String,
    error: Option<String>,
    profiles: Vec<String>,
    aliases: Vec<String>,
    serial_ports: Vec<PortInfo>,
}

impl Default for ConnectForm {
    fn default() -> Self {
        let s = SerialSettings::default();
        Self {
            protocol: Protocol::Ssh,
            target: String::new(),
            profile: None,
            port: String::new(),
            identity: String::new(),
            jump: String::new(),
            forwards: String::new(),
            auth: None,
            serial_baud: s.baud.to_string(),
            serial_data_bits: s.data_bits,
            serial_parity: s.parity,
            serial_stop_bits: s.stop_bits,
            serial_flow: s.flow_control,
            log_enabled: false,
            log_path: String::new(),
            error: None,
            profiles: Vec::new(),
            aliases: Vec::new(),
            serial_ports: Vec::new(),
        }
    }
}

impl ConnectForm {
    fn new() -> Self {
        let mut form = Self::default();
        match ProfileStore::default_location().and_then(|s| s.list()) {
            Ok(profiles) => form.profiles = profiles,
            Err(e) => form.error = Some(format!("cannot list profiles: {e}")),
        }
        match SshConfig::load_user() {
            Ok(config) => form.aliases = config.host_aliases(),
            Err(e) => form.error = Some(e.to_string()),
        }
        if let Ok(ports) = serial::list_ports() {
            form.serial_ports = ports;
        }
        form
    }

    fn from_launch(launch: &LaunchArgs) -> Self {
        let args = &launch.target;
        let mut form = Self::new();
        form.protocol = launch.protocol;
        form.target = args.target.clone().unwrap_or_default();
        form.profile = args.profile.clone().filter(|p| form.profiles.contains(p));
        form.port = args.port.map(|p| p.to_string()).unwrap_or_default();
        form.identity = args
            .identity
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        form.jump = args.jump.clone().unwrap_or_default();
        let mut fwds = Vec::new();
        for s in &launch.local {
            fwds.push(format!("L {s}"));
        }
        for s in &launch.remote {
            fwds.push(format!("R {s}"));
        }
        for s in &launch.dynamic {
            fwds.push(format!("D {s}"));
        }
        form.forwards = fwds.join(", ");
        form.auth = args.auth;
        form.serial_baud = launch.serial.baud.to_string();
        form.serial_data_bits = launch.serial.data_bits;
        form.serial_parity = launch.serial.parity;
        form.serial_stop_bits = launch.serial.stop_bits;
        form.serial_flow = launch.serial.flow_control;
        if let Some(ref p) = launch.log {
            form.log_enabled = true;
            form.log_path = p.display().to_string();
        }
        form
    }

    /// Prefills the form from the target that was just tried.
    fn from_target(
        target: &Target,
        profile: Option<String>,
        log_spec: &Option<Option<PathBuf>>,
    ) -> Self {
        let mut form = Self::new();
        if let Some(inner) = log_spec {
            form.log_enabled = true;
            if let Some(p) = inner {
                form.log_path = p.display().to_string();
            }
        }
        if profile.is_some() {
            form.profile = profile;
        } else {
            form.protocol = target.protocol;
            match target.protocol {
                Protocol::Ssh => {
                    form.target = format!("{}@{}", target.user, target.host);
                    if target.port != 22 {
                        form.port = target.port.to_string();
                    }
                    if !target.jump.is_empty() {
                        form.jump = target
                            .jump
                            .iter()
                            .map(|j| {
                                if j.port == 22 {
                                    format!("{}@{}", j.user, j.host)
                                } else {
                                    format!("{}@{}:{}", j.user, j.host, j.port)
                                }
                            })
                            .collect::<Vec<_>>()
                            .join(",");
                    }
                    form.forwards = format_forward_list(&target.forwards);
                }
                Protocol::Serial => {
                    form.target = target.host.clone();
                    let s = target.serial.unwrap_or_default();
                    form.serial_baud = s.baud.to_string();
                    form.serial_data_bits = s.data_bits;
                    form.serial_parity = s.parity;
                    form.serial_stop_bits = s.stop_bits;
                    form.serial_flow = s.flow_control;
                }
                Protocol::Telnet | Protocol::Raw => {
                    form.target = target.host.clone();
                    if Some(target.port) != target.protocol.default_port() {
                        form.port = target.port.to_string();
                    }
                }
            }
        }
        form
    }

    fn resolve(&self) -> Result<Target, String> {
        let port = match self.port.trim() {
            "" => None,
            p => Some(
                p.parse::<u16>()
                    .ok()
                    .filter(|&p| p != 0)
                    .ok_or_else(|| format!("'{p}' is not a valid port"))?,
            ),
        };
        let extra_forwards = parse_forward_list(&self.forwards)?;
        if self.profile.is_some() {
            let identity = self.identity.trim();
            let jump = self.jump.trim();
            let mut target = TargetArgs {
                target: None,
                port,
                identity: (!identity.is_empty()).then(|| identity.into()),
                profile: self.profile.clone(),
                auth: self.auth,
                jump: (!jump.is_empty()).then(|| jump.to_string()),
            }
            .resolve_any()
            .map_err(|e| e.to_string())?;
            if !extra_forwards.is_empty() && target.protocol != Protocol::Ssh {
                return Err("port forwards need an SSH connection".into());
            }
            target.forwards.extend(extra_forwards);
            return Ok(target);
        }

        let target = self.target.trim();
        match self.protocol {
            Protocol::Ssh => {
                if target.is_empty() {
                    return Err("enter user@host, a host, or an ssh_config alias".into());
                }
                let identity = self.identity.trim();
                let jump = self.jump.trim();
                let mut resolved = TargetArgs {
                    target: Some(target.to_string()),
                    port,
                    identity: (!identity.is_empty()).then(|| identity.into()),
                    profile: None,
                    auth: self.auth,
                    jump: (!jump.is_empty()).then(|| jump.to_string()),
                }
                .resolve_any()
                .map_err(|e| e.to_string())?;
                resolved.forwards.extend(extra_forwards);
                Ok(resolved)
            }
            Protocol::Serial => {
                if target.is_empty() {
                    return Err("enter a serial device path, e.g. /dev/ttyUSB0".into());
                }
                let baud = self
                    .serial_baud
                    .trim()
                    .parse::<u32>()
                    .ok()
                    .filter(|&b| b > 0)
                    .ok_or_else(|| format!("'{}' is not a valid baud rate", self.serial_baud))?;
                let settings = SerialSettings {
                    baud,
                    data_bits: self.serial_data_bits,
                    parity: self.serial_parity,
                    stop_bits: self.serial_stop_bits,
                    flow_control: self.serial_flow,
                };
                settings.check().map_err(|e| e.to_string())?;
                Ok(Target::serial(target, settings))
            }
            Protocol::Telnet | Protocol::Raw => {
                if target.is_empty() {
                    return Err("enter a host".into());
                }
                let resolved_port = port
                    .or_else(|| self.protocol.default_port())
                    .ok_or_else(|| "enter a port (1-65535)".to_string())?;
                Ok(Target::tcp(self.protocol, target, resolved_port))
            }
        }
    }

    fn log_spec(&self) -> Option<Option<PathBuf>> {
        if !self.log_enabled {
            return None;
        }
        let trimmed = self.log_path.trim();
        if trimmed.is_empty() {
            Some(None)
        } else {
            Some(Some(PathBuf::from(trimmed)))
        }
    }
}

fn parse_forward_list(input: &str) -> Result<Vec<ForwardRule>, String> {
    let mut rules = Vec::new();
    for raw in input.split(',') {
        let item = raw.trim();
        if item.is_empty() {
            continue;
        }
        let (kind, spec) = if let Some(rest) = item
            .strip_prefix("-L ")
            .or_else(|| item.strip_prefix("L "))
            .or_else(|| item.strip_prefix("local "))
            .or_else(|| item.strip_prefix("local:"))
        {
            (ForwardKind::Local, rest.trim())
        } else if let Some(rest) = item
            .strip_prefix("-R ")
            .or_else(|| item.strip_prefix("R "))
            .or_else(|| item.strip_prefix("remote "))
            .or_else(|| item.strip_prefix("remote:"))
        {
            (ForwardKind::Remote, rest.trim())
        } else if let Some(rest) = item
            .strip_prefix("-D ")
            .or_else(|| item.strip_prefix("D "))
            .or_else(|| item.strip_prefix("dynamic "))
            .or_else(|| item.strip_prefix("dynamic:"))
            .or_else(|| item.strip_prefix("socks5 "))
        {
            (ForwardKind::Dynamic, rest.trim())
        } else if item.split(':').count() <= 2 {
            (ForwardKind::Dynamic, item)
        } else {
            (ForwardKind::Local, item)
        };
        let rule = parse_forward(spec, kind).map_err(|e| e.to_string())?;
        rules.push(rule);
    }
    Ok(rules)
}

fn format_forward_list(rules: &[ForwardRule]) -> String {
    rules
        .iter()
        .map(|r| {
            let prefix = match r.kind {
                ForwardKind::Local => "L",
                ForwardKind::Remote => "R",
                ForwardKind::Dynamic => "D",
            };
            format!("{prefix} {}", forward_spec(r))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

const AUTH_CHOICES: [(AuthChoice, &str); 5] = [
    (AuthChoice::Auto, "auto"),
    (AuthChoice::Password, "password"),
    (AuthChoice::Key, "key file only"),
    (AuthChoice::Agent, "ssh-agent only"),
    (AuthChoice::KeyboardInteractive, "keyboard-interactive"),
];

fn auth_label(choice: Option<AuthChoice>, profile: bool) -> &'static str {
    match choice {
        None if profile => "from profile",
        None => "auto (agent, keys, password)",
        Some(c) => AUTH_CHOICES
            .iter()
            .find(|(v, _)| *v == c)
            .map_or("?", |(_, l)| l),
    }
}

#[derive(Clone, Copy)]
struct RenderMetrics {
    font_size: f32,
    palette: Palette,
    grid_rect: Rect,
    char_w: f32,
    row_h: f32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SessionAction {
    None,
    CloseTab,
}

struct Session {
    id: u64,
    target: Option<Target>,
    profile: Option<String>,
    log_spec: Option<Option<PathBuf>>,
    log: Option<SessionLog>,
    cmd_tx: Option<mpsc::UnboundedSender<Cmd>>,
    evt_rx: Option<mpsc::UnboundedReceiver<Evt>>,

    state: State,
    attention: bool,

    term: Terminal,
    cols: u32,
    rows: u32,

    pending_scroll: f32,
    pointer_cell: Option<(u16, u16)>,
    drag_button: Option<u8>,

    // In-session SSH tool windows (SFTP & Port Forwards)
    show_sftp: bool,
    sftp_path: String,
    sftp_path_input: String,
    sftp_entries: Vec<DirEntry>,
    sftp_selected: Option<usize>,
    sftp_status: Option<(String, bool)>,
    sftp_local_path: String,
    sftp_mkdir_name: String,
    sftp_rename_to: String,
    sftp_resume: bool,
    sftp_transfers: Vec<TransferEntry>,
    sftp_next_transfer_id: u64,

    show_forwards: bool,
    forwards: Vec<ForwardItem>,
    forward_kind: ForwardKind,
    forward_spec: String,
    forward_status: Option<(String, bool)>,
}

struct TransferEntry {
    id: u64,
    kind: TransferKind,
    remote: String,
    local: PathBuf,
    display_name: String,
    done: u64,
    total: Option<u64>,
    state: TransferState,
    speed_bps: f64,
    speed_sample_at: Option<Instant>,
    speed_sample_bytes: u64,
}

pub fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;

    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

pub fn format_speed(bps: f64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * KIB;
    const GIB: f64 = 1024.0 * MIB;

    if bps >= GIB {
        format!("{:.1} GiB/s", bps / GIB)
    } else if bps >= MIB {
        format!("{:.1} MiB/s", bps / MIB)
    } else if bps >= KIB {
        format!("{:.1} KiB/s", bps / KIB)
    } else {
        format!("{:.0} B/s", bps)
    }
}

impl Session {
    fn from_launch(id: u64, launch: &LaunchArgs) -> Self {
        let profile = launch.target.profile.clone();
        let form = ConnectForm::from_launch(launch);
        let log_spec = form.log_spec();
        let (target, state) = if launch.target.target.is_some() || profile.is_some() {
            match form.resolve() {
                Ok(target) => (Some(target), State::Connecting),
                Err(e) => {
                    let mut form = form;
                    form.error = Some(e);
                    (None, State::Setup(Box::new(form)))
                }
            }
        } else {
            (None, State::Setup(Box::new(form)))
        };
        Self {
            id,
            target,
            profile,
            log_spec,
            log: None,
            cmd_tx: None,
            evt_rx: None,
            state,
            attention: false,
            term: Terminal::new(80, 24),
            cols: 80,
            rows: 24,
            pending_scroll: 0.0,
            pointer_cell: None,
            drag_button: None,
            show_sftp: false,
            sftp_path: String::new(),
            sftp_path_input: String::new(),
            sftp_entries: Vec::new(),
            sftp_selected: None,
            sftp_status: None,
            sftp_local_path: String::new(),
            sftp_mkdir_name: String::new(),
            sftp_rename_to: String::new(),
            sftp_resume: false,
            sftp_transfers: Vec::new(),
            sftp_next_transfer_id: 1,
            show_forwards: false,
            forwards: Vec::new(),
            forward_kind: ForwardKind::Local,
            forward_spec: String::new(),
            forward_status: None,
        }
    }

    fn new_setup(id: u64) -> Self {
        let form = ConnectForm::new();
        Self {
            id,
            target: None,
            profile: None,
            log_spec: None,
            log: None,
            cmd_tx: None,
            evt_rx: None,
            state: State::Setup(Box::new(form)),
            attention: false,
            term: Terminal::new(80, 24),
            cols: 80,
            rows: 24,
            pending_scroll: 0.0,
            pointer_cell: None,
            drag_button: None,
            show_sftp: false,
            sftp_path: String::new(),
            sftp_path_input: String::new(),
            sftp_entries: Vec::new(),
            sftp_selected: None,
            sftp_status: None,
            sftp_local_path: String::new(),
            sftp_mkdir_name: String::new(),
            sftp_rename_to: String::new(),
            sftp_resume: false,
            sftp_transfers: Vec::new(),
            sftp_next_transfer_id: 1,
            show_forwards: false,
            forwards: Vec::new(),
            forward_kind: ForwardKind::Local,
            forward_spec: String::new(),
            forward_status: None,
        }
    }

    fn start_connect(
        &mut self,
        term_type: &str,
        handle: &tokio::runtime::Handle,
        ctx: &egui::Context,
    ) {
        let Some(target) = self.target.clone() else {
            return;
        };
        self.log = match &self.log_spec {
            None => None,
            Some(Some(path)) => {
                match SessionLog::create(path, &target.label(), &target.host, target.port) {
                    Ok(l) => Some(l),
                    Err(e) => {
                        self.state = State::Failed(e.to_string());
                        return;
                    }
                }
            }
            Some(None) => {
                match SessionLog::create_default(&target.label(), &target.host, target.port) {
                    Ok(l) => Some(l),
                    Err(e) => {
                        self.state = State::Failed(e.to_string());
                        return;
                    }
                }
            }
        };
        self.show_sftp = false;
        self.sftp_path.clear();
        self.sftp_path_input.clear();
        self.sftp_entries.clear();
        self.sftp_selected = None;
        self.sftp_status = None;
        self.sftp_resume = false;
        self.sftp_transfers.clear();
        self.sftp_next_transfer_id = 1;
        self.show_forwards = false;
        self.forwards.clear();
        self.forward_status = None;

        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (evt_tx, evt_rx) = mpsc::unbounded_channel();
        handle.spawn(ssh::connect_and_run(
            target,
            term_type.to_string(),
            cmd_rx,
            evt_tx,
            ctx.clone(),
        ));
        self.cmd_tx = Some(cmd_tx);
        self.evt_rx = Some(evt_rx);
        self.term = Terminal::new(self.cols, self.rows);
        self.state = State::Connecting;
    }

    fn drain_events(&mut self, is_active: bool) -> bool {
        let mut received = false;
        let mut responses: Vec<u8> = Vec::new();
        if let Some(rx) = self.evt_rx.as_mut() {
            while let Ok(evt) = rx.try_recv() {
                received = true;
                match evt {
                    Evt::Ask(q) => {
                        self.state = State::from_question(q);
                        if !is_active {
                            self.attention = true;
                        }
                    }
                    Evt::Ready => self.state = State::Running,
                    Evt::Data(data) => {
                        if let Some(log) = self.log.as_mut() {
                            log.write(&data);
                            if let Some(err) = log.take_error() {
                                tracing::warn!("{err}");
                            }
                        }
                        self.term.feed(&data);
                        responses.extend(self.term.take_responses());
                    }
                    Evt::Forwards { list, status } => {
                        self.forwards = list;
                        if status.is_some() {
                            self.forward_status = status;
                        }
                    }
                    Evt::SftpListed {
                        path,
                        entries,
                        status,
                    } => {
                        self.sftp_path = path.clone();
                        self.sftp_path_input = path;
                        self.sftp_entries = entries;
                        self.sftp_selected = None;
                        if status.is_some() {
                            self.sftp_status = status;
                        }
                    }
                    Evt::SftpTransferProgress { id, done, total } => {
                        if let Some(entry) = self.sftp_transfers.iter_mut().find(|e| e.id == id) {
                            entry.done = done;
                            entry.total = total;
                            let now = Instant::now();
                            match entry.speed_sample_at {
                                None => {
                                    entry.speed_sample_at = Some(now);
                                    entry.speed_sample_bytes = done;
                                }
                                Some(prev_time) => {
                                    let elapsed = now.duration_since(prev_time).as_secs_f64();
                                    if elapsed >= 0.5 {
                                        let transferred =
                                            done.saturating_sub(entry.speed_sample_bytes);
                                        let sample_bps = (transferred as f64) / elapsed;
                                        entry.speed_bps = if entry.speed_bps == 0.0 {
                                            sample_bps
                                        } else {
                                            0.7 * entry.speed_bps + 0.3 * sample_bps
                                        };
                                        entry.speed_sample_at = Some(now);
                                        entry.speed_sample_bytes = done;
                                    }
                                }
                            }
                        }
                    }
                    Evt::SftpTransferState { id, state, bytes } => {
                        if let Some(entry) = self.sftp_transfers.iter_mut().find(|e| e.id == id) {
                            entry.state = state.clone();
                            match &state {
                                TransferState::Running => {
                                    entry.speed_sample_at = None;
                                    entry.speed_bps = 0.0;
                                }
                                TransferState::Done => {
                                    if entry.kind == TransferKind::Upload
                                        && self.show_sftp
                                        && !self.sftp_path.is_empty()
                                        && let Some(tx) = &self.cmd_tx
                                    {
                                        let _ = tx.send(Cmd::SftpList {
                                            path: self.sftp_path.clone(),
                                        });
                                    }
                                    let verb = match entry.kind {
                                        TransferKind::Download => "Downloaded",
                                        TransferKind::Upload => "Uploaded",
                                    };
                                    self.sftp_status = Some((
                                        format!(
                                            "{verb} {} ({})",
                                            entry.display_name,
                                            format_bytes(bytes)
                                        ),
                                        false,
                                    ));
                                }
                                TransferState::Cancelled => {
                                    self.sftp_status =
                                        Some((format!("Cancelled {}", entry.display_name), false));
                                }
                                TransferState::Failed(err) => {
                                    self.sftp_status = Some((
                                        format!("Transfer failed ({}): {err}", entry.display_name),
                                        true,
                                    ));
                                }
                                TransferState::Queued => {}
                            }
                        }
                    }
                    Evt::SftpStatus { message, is_error } => {
                        self.sftp_status = Some((message, is_error));
                    }
                    Evt::Closed(msg) => {
                        self.log = None;
                        self.show_sftp = false;
                        self.show_forwards = false;
                        self.attention = false;
                        self.state = State::Failed(msg);
                    }
                }
            }
        }
        if !responses.is_empty() {
            self.send_data(responses);
        }
        received
    }

    fn title(&self) -> String {
        self.term
            .title()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or_else(|| self.target.as_ref().map(Target::label))
            .unwrap_or_else(|| "New tab".to_string())
    }

    fn window_title(&self) -> String {
        self.term
            .title()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or_else(|| self.target.as_ref().map(Target::label))
            .unwrap_or_else(|| "MaelstromSSH".to_string())
    }

    fn is_connected(&self) -> bool {
        matches!(self.state, State::Running)
    }

    fn status_color(&self) -> Color32 {
        match self.state {
            State::Running => OK_GREEN,
            State::Connecting
            | State::Secret { .. }
            | State::HostKey { .. }
            | State::KeyboardInteractive { .. } => Color32::from_rgb(230, 180, 60),
            State::Failed(_) => ERROR_RED,
            State::Setup(_) => Color32::from_gray(140),
        }
    }

    fn queue_transfer(&mut self, kind: TransferKind, remote: String, local: PathBuf, resume: bool) {
        let id = self.sftp_next_transfer_id;
        self.sftp_next_transfer_id += 1;
        let display_name = match kind {
            TransferKind::Download => remote.rsplit('/').next().unwrap_or(&remote).to_string(),
            TransferKind::Upload => local
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file")
                .to_string(),
        };
        self.sftp_transfers.push(TransferEntry {
            id,
            kind,
            remote: remote.clone(),
            local: local.clone(),
            display_name,
            done: 0,
            total: None,
            state: TransferState::Queued,
            speed_bps: 0.0,
            speed_sample_at: None,
            speed_sample_bytes: 0,
        });
        if let Some(tx) = &self.cmd_tx {
            let cmd = match kind {
                TransferKind::Download => Cmd::SftpDownload {
                    id,
                    remote,
                    local,
                    resume,
                },
                TransferKind::Upload => Cmd::SftpUpload {
                    id,
                    local,
                    remote,
                    resume,
                },
            };
            let _ = tx.send(cmd);
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

    fn ui_setup(
        &mut self,
        ui: &mut egui::Ui,
        tab_count: usize,
        keys_window: &mut KeysWindow,
        known_hosts_window: &mut KnownHostsWindow,
        term_type: &str,
        handle: &tokio::runtime::Handle,
    ) -> SessionAction {
        let State::Setup(form) = &mut self.state else {
            return SessionAction::None;
        };
        let enter = ui.input(|i| i.key_pressed(egui::Key::Enter));
        let mut submit = false;
        let mut close_tab = false;

        ui.heading("MaelstromSSH");
        ui.label("New connection");
        ui.add_space(8.0);

        egui::Grid::new(("connect_form", self.id))
            .num_columns(2)
            .spacing([12.0, 8.0])
            .show(ui, |ui| {
                if !form.profiles.is_empty() {
                    ui.label("Profile");
                    egui::ComboBox::from_id_salt(("profile", self.id))
                        .selected_text(form.profile.as_deref().unwrap_or("(none)"))
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut form.profile, None, "(none)");
                            for name in &form.profiles {
                                ui.selectable_value(
                                    &mut form.profile,
                                    Some(name.clone()),
                                    name.as_str(),
                                );
                            }
                        });
                    ui.end_row();
                }

                if form.profile.is_none() {
                    ui.label("Protocol");
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut form.protocol, Protocol::Ssh, "SSH");
                        ui.radio_value(&mut form.protocol, Protocol::Serial, "Serial");
                        ui.radio_value(&mut form.protocol, Protocol::Telnet, "Telnet");
                        ui.radio_value(&mut form.protocol, Protocol::Raw, "Raw TCP");
                    });
                    ui.end_row();
                }

                match form.protocol {
                    Protocol::Serial if form.profile.is_none() => {
                        ui.label("Device");
                        let dev = ui.add(
                            egui::TextEdit::singleline(&mut form.target)
                                .hint_text("/dev/ttyUSB0")
                                .desired_width(280.0),
                        );
                        if !ui.memory(|m| m.focused().is_some()) {
                            dev.request_focus();
                        }
                        ui.end_row();

                        ui.label("Baud rate");
                        ui.add(
                            egui::TextEdit::singleline(&mut form.serial_baud)
                                .hint_text("9600")
                                .desired_width(100.0),
                        );
                        ui.end_row();

                        ui.label("Line");
                        ui.horizontal(|ui| {
                            egui::ComboBox::from_id_salt(("data_bits", self.id))
                                .selected_text(format!("{} data", form.serial_data_bits))
                                .show_ui(ui, |ui| {
                                    for b in [8u8, 7, 6, 5] {
                                        ui.selectable_value(
                                            &mut form.serial_data_bits,
                                            b,
                                            format!("{b} data"),
                                        );
                                    }
                                });
                            egui::ComboBox::from_id_salt(("parity", self.id))
                                .selected_text(match form.serial_parity {
                                    Parity::None => "no parity",
                                    Parity::Odd => "odd parity",
                                    Parity::Even => "even parity",
                                })
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(
                                        &mut form.serial_parity,
                                        Parity::None,
                                        "no parity",
                                    );
                                    ui.selectable_value(
                                        &mut form.serial_parity,
                                        Parity::Even,
                                        "even parity",
                                    );
                                    ui.selectable_value(
                                        &mut form.serial_parity,
                                        Parity::Odd,
                                        "odd parity",
                                    );
                                });
                            egui::ComboBox::from_id_salt(("stop_bits", self.id))
                                .selected_text(format!("{} stop", form.serial_stop_bits))
                                .show_ui(ui, |ui| {
                                    for s in [1u8, 2] {
                                        ui.selectable_value(
                                            &mut form.serial_stop_bits,
                                            s,
                                            format!("{s} stop"),
                                        );
                                    }
                                });
                            egui::ComboBox::from_id_salt(("flow", self.id))
                                .selected_text(match form.serial_flow {
                                    FlowControl::None => "no flow ctrl",
                                    FlowControl::Software => "XON/XOFF",
                                    FlowControl::Hardware => "RTS/CTS",
                                })
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(
                                        &mut form.serial_flow,
                                        FlowControl::None,
                                        "no flow ctrl",
                                    );
                                    ui.selectable_value(
                                        &mut form.serial_flow,
                                        FlowControl::Software,
                                        "XON/XOFF",
                                    );
                                    ui.selectable_value(
                                        &mut form.serial_flow,
                                        FlowControl::Hardware,
                                        "RTS/CTS",
                                    );
                                });
                        });
                        ui.end_row();
                    }
                    Protocol::Telnet | Protocol::Raw if form.profile.is_none() => {
                        ui.label("Host");
                        let host = ui.add(
                            egui::TextEdit::singleline(&mut form.target)
                                .hint_text("host or IP address")
                                .desired_width(280.0),
                        );
                        if !ui.memory(|m| m.focused().is_some()) {
                            host.request_focus();
                        }
                        ui.end_row();

                        ui.label("Port");
                        let hint = if form.protocol == Protocol::Telnet {
                            "23"
                        } else {
                            "1-65535"
                        };
                        ui.add(
                            egui::TextEdit::singleline(&mut form.port)
                                .hint_text(hint)
                                .desired_width(80.0),
                        );
                        ui.end_row();
                    }
                    _ => {
                        ui.label("Host");
                        let host = ui.add_enabled(
                            form.profile.is_none(),
                            egui::TextEdit::singleline(&mut form.target)
                                .hint_text("user@host or ssh_config alias")
                                .desired_width(280.0),
                        );
                        if form.profile.is_none() && !ui.memory(|m| m.focused().is_some()) {
                            host.request_focus();
                        }
                        ui.end_row();

                        ui.label("Port");
                        ui.add(
                            egui::TextEdit::singleline(&mut form.port)
                                .hint_text("22")
                                .desired_width(80.0),
                        );
                        ui.end_row();

                        ui.label("Key file");
                        ui.add(
                            egui::TextEdit::singleline(&mut form.identity)
                                .hint_text("optional, e.g. ~/.ssh/id_ed25519")
                                .desired_width(280.0),
                        );
                        ui.end_row();

                        ui.label("Jump host");
                        ui.add(
                            egui::TextEdit::singleline(&mut form.jump)
                                .hint_text("optional, e.g. user@bastion:22")
                                .desired_width(280.0),
                        );
                        ui.end_row();

                        ui.label("Port forwards");
                        ui.add(
                            egui::TextEdit::singleline(&mut form.forwards)
                                .hint_text("optional, e.g. L 8080:localhost:80, D 1080")
                                .desired_width(280.0),
                        );
                        ui.end_row();

                        ui.label("Authentication");
                        let is_profile = form.profile.is_some();
                        egui::ComboBox::from_id_salt(("auth", self.id))
                            .selected_text(auth_label(form.auth, is_profile))
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut form.auth,
                                    None,
                                    auth_label(None, is_profile),
                                );
                                for (choice, label) in AUTH_CHOICES.iter().skip(1) {
                                    ui.selectable_value(&mut form.auth, Some(*choice), *label);
                                }
                            });
                        ui.end_row();
                    }
                }

                ui.label("Session log");
                ui.horizontal(|ui| {
                    ui.checkbox(&mut form.log_enabled, "Save output");
                    if form.log_enabled {
                        ui.add(
                            egui::TextEdit::singleline(&mut form.log_path)
                                .hint_text("optional path (blank = default log folder)")
                                .desired_width(200.0),
                        );
                    }
                });
                ui.end_row();
            });

        if form.profile.is_none() && form.protocol == Protocol::Ssh && !form.aliases.is_empty() {
            ui.add_space(8.0);
            ui.label("Hosts from ~/.ssh/config:");
            ui.horizontal_wrapped(|ui| {
                for alias in &form.aliases {
                    if ui.small_button(alias.as_str()).clicked() {
                        form.target = alias.clone();
                    }
                }
            });
        }

        if form.profile.is_none()
            && form.protocol == Protocol::Serial
            && !form.serial_ports.is_empty()
        {
            ui.add_space(8.0);
            ui.label("Detected serial ports:");
            ui.horizontal_wrapped(|ui| {
                for p in &form.serial_ports {
                    let label = if p.description.is_empty() {
                        p.path.clone()
                    } else {
                        format!("{} ({})", p.path, p.description)
                    };
                    if ui.small_button(label).clicked() {
                        form.target = p.path.clone();
                    }
                }
            });
        }

        if let Some(err) = &form.error {
            ui.add_space(8.0);
            ui.colored_label(ERROR_RED, err.as_str());
        }

        ui.add_space(12.0);
        ui.horizontal(|ui| {
            submit |= ui.button("Connect").clicked() || enter;
            let close_label = if tab_count > 1 { "Close tab" } else { "Quit" };
            close_tab |= ui.button(close_label).clicked();
            ui.add_space(12.0);
            if ui.button("SSH keys…").clicked() {
                keys_window.open();
            }
            if ui.button("Known hosts…").clicked() {
                known_hosts_window.open();
            }
        });

        if close_tab {
            SessionAction::CloseTab
        } else {
            if submit {
                match form.resolve() {
                    Ok(target) => {
                        for warning in &target.warnings {
                            tracing::warn!("{warning}");
                        }
                        self.profile = form.profile.clone();
                        self.log_spec = form.log_spec();
                        self.target = Some(target);
                        self.start_connect(term_type, handle, ui.ctx());
                    }
                    Err(e) => form.error = Some(e),
                }
            }
            SessionAction::None
        }
    }

    fn ui_dialog(
        &mut self,
        ui: &mut egui::Ui,
        tab_count: usize,
        term_type: &str,
        handle: &tokio::runtime::Handle,
    ) -> SessionAction {
        let mut state = std::mem::replace(&mut self.state, State::Connecting);
        let label = self.target.as_ref().map(Target::label).unwrap_or_default();
        let enter = ui.input(|i| i.key_pressed(egui::Key::Enter));

        ui.heading("MaelstromSSH");
        ui.label(format!("Connecting to {label}"));
        for warning in self.target.iter().flat_map(|t| &t.warnings) {
            ui.colored_label(
                Color32::from_rgb(230, 180, 60),
                format!("warning: {warning}"),
            );
        }
        ui.add_space(8.0);

        let outcome = match &mut state {
            State::Connecting => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Connecting…");
                });
                Outcome::Pending
            }
            State::Secret { prompt, input, .. } => {
                ui.label(prompt.trim_end_matches([':', ' ']));
                ui.add(egui::TextEdit::singleline(input).password(true))
                    .request_focus();
                submit_buttons(ui, enter)
            }
            State::KeyboardInteractive {
                name,
                instructions,
                prompts,
                answers,
                ..
            } => {
                if !name.is_empty() {
                    ui.strong(name.as_str());
                }
                if !instructions.is_empty() {
                    ui.label(instructions.as_str());
                }
                for (i, (p, answer)) in prompts.iter().zip(answers.iter_mut()).enumerate() {
                    ui.label(p.text.trim_end_matches([':', ' ']));
                    let field = ui.add(egui::TextEdit::singleline(answer).password(!p.echo));
                    if i == 0 && !ui.memory(|m| m.focused().is_some()) {
                        field.request_focus();
                    }
                }
                submit_buttons(ui, enter)
            }
            State::HostKey {
                host,
                port,
                fingerprint,
                ..
            } => {
                ui.strong("Unknown host key");
                ui.label(format!(
                    "The authenticity of '{host}:{port}' can't be established."
                ));
                ui.monospace(fingerprint.as_str());
                ui.label("Only accept if this matches the fingerprint you expect.");
                ui.add_space(8.0);
                let mut out = Outcome::Pending;
                ui.horizontal(|ui| {
                    if ui.button("Accept").clicked() {
                        out = Outcome::Answered;
                    }
                    if ui.button("Reject").clicked() {
                        out = Outcome::Quit;
                    }
                });
                out
            }
            State::Failed(msg) => {
                ui.colored_label(ERROR_RED, format!("Connection failed: {msg}"));
                ui.add_space(8.0);
                let mut out = Outcome::Pending;
                ui.horizontal(|ui| {
                    if ui.button("Retry").clicked() {
                        out = Outcome::Retry;
                    }
                    if ui.button("Change…").clicked() {
                        out = Outcome::Edit;
                    }
                    let close_label = if tab_count > 1 { "Close tab" } else { "Quit" };
                    if ui.button(close_label).clicked() {
                        out = Outcome::Quit;
                    }
                });
                out
            }
            State::Running | State::Setup(_) => Outcome::Pending,
        };

        match outcome {
            Outcome::Pending => {
                self.state = state;
                SessionAction::None
            }
            Outcome::Answered => {
                answer(state, true);
                SessionAction::None
            }
            Outcome::Quit => {
                let failed = matches!(state, State::Failed(_));
                answer(state, false);
                // Rejecting a prompt cancels the connection; the task then
                // reports the failure. Quitting from the failure screen closes tab/exits.
                if failed {
                    SessionAction::CloseTab
                } else {
                    SessionAction::None
                }
            }
            Outcome::Retry => {
                self.start_connect(term_type, handle, ui.ctx());
                SessionAction::None
            }
            Outcome::Edit => {
                let form = match &self.target {
                    Some(t) => ConnectForm::from_target(t, self.profile.clone(), &self.log_spec),
                    None => ConnectForm::new(),
                };
                self.log = None;
                self.cmd_tx = None;
                self.evt_rx = None;
                self.state = State::Setup(Box::new(form));
                SessionAction::None
            }
        }
    }

    fn ui_running(
        &mut self,
        ui: &mut egui::Ui,
        metrics: &mut RenderMetrics,
        keys_window: &mut KeysWindow,
        modal_open: bool,
    ) {
        let full = ui.available_rect_before_wrap();
        let status_h = 22.0;
        let grid_rect = Rect::from_min_max(
            full.min,
            pos2(full.max.x, (full.max.y - status_h).max(full.min.y)),
        );
        let status_rect = Rect::from_min_max(pos2(full.min.x, full.max.y - status_h), full.max);

        // Measure the monospace cell and resize the emulator to match.
        let font = FontId::monospace(metrics.font_size);
        let (cw, rh) = ui
            .ctx()
            .fonts_mut(|f| (f.glyph_width(&font, 'M'), f.row_height(&font)));
        let cols = ((grid_rect.width() / cw).floor() as u32).max(1);
        let rows = ((grid_rect.height() / rh).floor() as u32).max(1);
        if cols != self.cols || rows != self.rows {
            self.cols = cols;
            self.rows = rows;
            self.term.resize(cols, rows);
            if let Some(tx) = &self.cmd_tx {
                let _ = tx.send(Cmd::WindowChange { cols, rows });
            }
        }
        metrics.grid_rect = grid_rect;
        metrics.char_w = cw;
        metrics.row_h = rh;

        let ctx = ui.ctx().clone();
        if self.show_sftp {
            self.ui_sftp_window(&ctx);
        }
        if self.show_forwards {
            self.ui_forwards_window(&ctx);
        }

        if !modal_open {
            self.handle_input(ui, metrics);
        }
        self.paint(ui, status_rect, metrics, keys_window);
    }

    fn ui_sftp_window(&mut self, ctx: &egui::Context) {
        let mut open = self.show_sftp;
        egui::Window::new("SFTP File Browser")
            .id(egui::Id::unique(("sftp_window", self.id)))
            .open(&mut open)
            .default_size([560.0, 420.0])
            .resizable(true)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if ui.button("Up (..)").clicked()
                        && !self.sftp_path.is_empty()
                        && self.sftp_path != "/"
                    {
                        let parent = self.join_remote("..");
                        if let Some(tx) = &self.cmd_tx {
                            let _ = tx.send(Cmd::SftpList { path: parent });
                        }
                    }
                    let path_edit = ui.add(
                        egui::TextEdit::singleline(&mut self.sftp_path_input)
                            .hint_text("/remote/path")
                            .desired_width(300.0),
                    );
                    let enter =
                        path_edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if ui.button("Go").clicked() || enter {
                        let target = self.sftp_path_input.trim().to_string();
                        if let Some(tx) = &self.cmd_tx {
                            let _ = tx.send(Cmd::SftpList { path: target });
                        }
                    }
                    if ui.button("Refresh").clicked() {
                        let cur = if self.sftp_path.is_empty() {
                            ".".to_string()
                        } else {
                            self.sftp_path.clone()
                        };
                        if let Some(tx) = &self.cmd_tx {
                            let _ = tx.send(Cmd::SftpList { path: cur });
                        }
                    }
                });

                ui.separator();

                let mut cd_into: Option<String> = None;
                egui::ScrollArea::vertical()
                    .id_salt(("sftp_file_list", self.id))
                    .max_height(210.0)
                    .show(ui, |ui| {
                        if self.sftp_entries.is_empty() {
                            ui.label("(empty directory)");
                        }
                        for (i, entry) in self.sftp_entries.iter().enumerate() {
                            let tag = if entry.is_dir {
                                "[DIR]"
                            } else if entry.is_symlink {
                                "[LNK]"
                            } else {
                                "     "
                            };
                            let suffix = if entry.is_dir { "/" } else { "" };
                            let label = if entry.is_dir {
                                format!("{tag} {}{suffix}", entry.name)
                            } else {
                                format!("{tag} {}  ({} B)", entry.name, entry.size)
                            };
                            let selected = self.sftp_selected == Some(i);
                            let resp = ui.selectable_label(selected, label);
                            if resp.clicked() {
                                self.sftp_selected = Some(i);
                                self.sftp_rename_to = entry.name.clone();
                                if !entry.is_dir {
                                    self.sftp_local_path = format!("./{}", entry.name);
                                }
                            }
                            if resp.double_clicked() && entry.is_dir {
                                cd_into = Some(self.join_remote(&entry.name));
                            }
                        }
                    });

                if let Some(next_dir) = cd_into
                    && let Some(tx) = &self.cmd_tx
                {
                    let _ = tx.send(Cmd::SftpList { path: next_dir });
                }

                ui.separator();

                // Selected entry actions
                if let Some(sel_idx) = self.sftp_selected
                    && let Some(entry) = self.sftp_entries.get(sel_idx).cloned()
                {
                    ui.horizontal(|ui| {
                        ui.strong(format!("Selected: {}", entry.name));
                        if entry.is_dir && ui.button("Open folder").clicked() {
                            let next = self.join_remote(&entry.name);
                            if let Some(tx) = &self.cmd_tx {
                                let _ = tx.send(Cmd::SftpList { path: next });
                            }
                        }
                        if ui.button("Delete").clicked() {
                            let full = self.join_remote(&entry.name);
                            if let Some(tx) = &self.cmd_tx {
                                let _ = tx.send(Cmd::SftpRemove {
                                    path: full,
                                    is_dir: entry.is_dir,
                                });
                            }
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label("Rename to:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.sftp_rename_to)
                                .desired_width(180.0),
                        );
                        if ui.button("Rename").clicked() {
                            let new_name = self.sftp_rename_to.trim();
                            if !new_name.is_empty() && new_name != entry.name {
                                let from = self.join_remote(&entry.name);
                                let to = self.join_remote(new_name);
                                if let Some(tx) = &self.cmd_tx {
                                    let _ = tx.send(Cmd::SftpRename { from, to });
                                }
                            }
                        }
                    });
                }

                ui.horizontal(|ui| {
                    ui.label("Local file path:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.sftp_local_path)
                            .hint_text("./filename or /path/to/local/file")
                            .desired_width(220.0),
                    );
                    ui.checkbox(&mut self.sftp_resume, "Resume partial file");
                });

                ui.horizontal(|ui| {
                    let can_download = self
                        .sftp_selected
                        .and_then(|i| self.sftp_entries.get(i))
                        .is_some_and(|e| !e.is_dir);
                    if ui
                        .add_enabled(can_download, egui::Button::new("Download selected"))
                        .clicked()
                        && let Some(entry) =
                            self.sftp_selected.and_then(|i| self.sftp_entries.get(i))
                    {
                        let local = if self.sftp_local_path.trim().is_empty() {
                            PathBuf::from(&entry.name)
                        } else {
                            PathBuf::from(self.sftp_local_path.trim())
                        };
                        let remote = self.join_remote(&entry.name);
                        self.queue_transfer(
                            TransferKind::Download,
                            remote,
                            local,
                            self.sftp_resume,
                        );
                    }
                    if ui.button("Upload to current dir").clicked() {
                        let local_str = self.sftp_local_path.trim();
                        if !local_str.is_empty() {
                            let local = PathBuf::from(local_str);
                            if let Some(fname) = local.file_name().and_then(|n| n.to_str()) {
                                let remote = self.join_remote(fname);
                                self.queue_transfer(
                                    TransferKind::Upload,
                                    remote,
                                    local,
                                    self.sftp_resume,
                                );
                            } else {
                                self.sftp_status =
                                    Some(("Enter a valid local file path".into(), true));
                            }
                        }
                    }
                });

                // Partial file hints and resume buttons
                let partial_download = if let Some(entry) =
                    self.sftp_selected.and_then(|i| self.sftp_entries.get(i))
                {
                    if !entry.is_dir {
                        let local = if self.sftp_local_path.trim().is_empty() {
                            PathBuf::from(&entry.name)
                        } else {
                            PathBuf::from(self.sftp_local_path.trim())
                        };
                        if let Ok(meta) = std::fs::metadata(&local) {
                            let local_len = meta.len();
                            if local_len > 0 && local_len < entry.size {
                                Some((entry.name.clone(), local, local_len, entry.size))
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                if let Some((remote_name, local, local_len, entry_size)) = partial_download {
                    let mut resume_clicked = false;
                    ui.horizontal(|ui| {
                        ui.label(format!(
                            "Partial local file ({} / {})",
                            format_bytes(local_len),
                            format_bytes(entry_size)
                        ));
                        if ui.small_button("Resume download").clicked() {
                            resume_clicked = true;
                        }
                    });
                    if resume_clicked {
                        let remote = self.join_remote(&remote_name);
                        self.queue_transfer(TransferKind::Download, remote, local, true);
                    }
                }

                let partial_upload = {
                    let local_str = self.sftp_local_path.trim();
                    if !local_str.is_empty() {
                        let local = PathBuf::from(local_str);
                        if let Ok(meta) = std::fs::metadata(&local) {
                            let local_len = meta.len();
                            if let Some(fname) = local.file_name().and_then(|n| n.to_str()) {
                                if let Some(remote_entry) = self
                                    .sftp_entries
                                    .iter()
                                    .find(|e| e.name == fname && !e.is_dir)
                                {
                                    if remote_entry.size > 0 && remote_entry.size < local_len {
                                        Some((
                                            fname.to_string(),
                                            local,
                                            remote_entry.size,
                                            local_len,
                                        ))
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                };

                if let Some((fname, local, remote_size, local_len)) = partial_upload {
                    let mut resume_clicked = false;
                    ui.horizontal(|ui| {
                        ui.label(format!(
                            "Partial remote file ({} / {})",
                            format_bytes(remote_size),
                            format_bytes(local_len)
                        ));
                        if ui.small_button("Resume upload").clicked() {
                            resume_clicked = true;
                        }
                    });
                    if resume_clicked {
                        let remote = self.join_remote(&fname);
                        self.queue_transfer(TransferKind::Upload, remote, local, true);
                    }
                }

                ui.horizontal(|ui| {
                    ui.label("New folder:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.sftp_mkdir_name)
                            .hint_text("folder name")
                            .desired_width(180.0),
                    );
                    if ui.button("Create folder").clicked() {
                        let name = self.sftp_mkdir_name.trim().to_string();
                        if !name.is_empty() {
                            let full = self.join_remote(&name);
                            self.sftp_mkdir_name.clear();
                            if let Some(tx) = &self.cmd_tx {
                                let _ = tx.send(Cmd::SftpMkdir { path: full });
                            }
                        }
                    }
                });

                if let Some((ref msg, is_err)) = self.sftp_status {
                    ui.add_space(4.0);
                    let color = if is_err { ERROR_RED } else { OK_GREEN };
                    ui.colored_label(color, msg.as_str());
                }

                if !self.sftp_transfers.is_empty() {
                    ui.add_space(8.0);
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.strong("Transfers");
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("Clear finished").clicked() {
                                self.sftp_transfers.retain(|e| {
                                    matches!(
                                        e.state,
                                        TransferState::Queued | TransferState::Running
                                    )
                                });
                            }
                        });
                    });

                    let mut to_resume = None;
                    egui::ScrollArea::vertical()
                        .id_salt(("sftp_transfers", self.id))
                        .max_height(140.0)
                        .show(ui, |ui| {
                            for entry in &mut self.sftp_transfers {
                                ui.horizontal(|ui| {
                                    let arrow = match entry.kind {
                                        TransferKind::Download => "↓",
                                        TransferKind::Upload => "↑",
                                    };
                                    ui.label(format!("{arrow} {}", entry.display_name));
                                    let (state_str, color) = match &entry.state {
                                        TransferState::Queued => ("Queued", egui::Color32::GRAY),
                                        TransferState::Running => {
                                            ("Running", egui::Color32::LIGHT_BLUE)
                                        }
                                        TransferState::Done => ("Done", OK_GREEN),
                                        TransferState::Cancelled => {
                                            ("Cancelled", egui::Color32::GOLD)
                                        }
                                        TransferState::Failed(_) => ("Failed", ERROR_RED),
                                    };
                                    ui.colored_label(color, state_str);

                                    let frac = match entry.total {
                                        Some(total) if total > 0 => {
                                            (entry.done as f32 / total as f32).clamp(0.0, 1.0)
                                        }
                                        _ => 0.0,
                                    };
                                    let bar = egui::ProgressBar::new(frac)
                                        .show_percentage()
                                        .desired_width(140.0)
                                        .animate(matches!(entry.state, TransferState::Running));
                                    ui.add(bar);

                                    let bytes_str = match entry.total {
                                        Some(total) => format!(
                                            "{} / {}",
                                            format_bytes(entry.done),
                                            format_bytes(total)
                                        ),
                                        None => format_bytes(entry.done),
                                    };
                                    if matches!(entry.state, TransferState::Running)
                                        && entry.speed_bps > 0.0
                                    {
                                        ui.label(format!(
                                            "{bytes_str} · {}",
                                            format_speed(entry.speed_bps)
                                        ));
                                    } else {
                                        ui.label(bytes_str);
                                    }

                                    match &entry.state {
                                        TransferState::Queued | TransferState::Running => {
                                            if ui.small_button("Cancel").clicked()
                                                && let Some(tx) = &self.cmd_tx
                                            {
                                                let _ = tx.send(Cmd::SftpCancel { id: entry.id });
                                            }
                                        }
                                        TransferState::Cancelled | TransferState::Failed(_) => {
                                            if ui.small_button("Resume").clicked() {
                                                to_resume = Some((
                                                    entry.kind,
                                                    entry.remote.clone(),
                                                    entry.local.clone(),
                                                ));
                                            }
                                        }
                                        TransferState::Done => {}
                                    }
                                });
                            }
                        });
                    if let Some((kind, remote, local)) = to_resume {
                        self.queue_transfer(kind, remote, local, true);
                    }
                }
            });
        self.show_sftp = open;
    }

    fn ui_forwards_window(&mut self, ctx: &egui::Context) {
        let mut open = self.show_forwards;
        egui::Window::new("Port Forwards")
            .id(egui::Id::unique(("forwards_window", self.id)))
            .open(&mut open)
            .default_size([480.0, 280.0])
            .resizable(true)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    egui::ComboBox::from_id_salt(("fwd_kind", self.id))
                        .selected_text(match self.forward_kind {
                            ForwardKind::Local => "Local (-L)",
                            ForwardKind::Remote => "Remote (-R)",
                            ForwardKind::Dynamic => "Dynamic / SOCKS5 (-D)",
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.forward_kind,
                                ForwardKind::Local,
                                "Local (-L)",
                            );
                            ui.selectable_value(
                                &mut self.forward_kind,
                                ForwardKind::Remote,
                                "Remote (-R)",
                            );
                            ui.selectable_value(
                                &mut self.forward_kind,
                                ForwardKind::Dynamic,
                                "Dynamic / SOCKS5 (-D)",
                            );
                        });
                    let hint = match self.forward_kind {
                        ForwardKind::Local | ForwardKind::Remote => "[bind:]port:host:hostport",
                        ForwardKind::Dynamic => "[bind:]port",
                    };
                    let edit = ui.add(
                        egui::TextEdit::singleline(&mut self.forward_spec)
                            .hint_text(hint)
                            .desired_width(200.0),
                    );
                    let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if ui.button("Add").clicked() || enter {
                        let spec = self.forward_spec.trim().to_string();
                        if !spec.is_empty() {
                            self.forward_spec.clear();
                            if let Some(tx) = &self.cmd_tx {
                                let _ = tx.send(Cmd::ForwardAdd {
                                    kind: self.forward_kind,
                                    spec,
                                });
                            }
                        }
                    }
                });

                ui.separator();

                let mut to_stop = None;
                egui::ScrollArea::vertical()
                    .id_salt(("forwards_list", self.id))
                    .max_height(160.0)
                    .show(ui, |ui| {
                        if self.forwards.is_empty() {
                            ui.label("No active port forwards.");
                        }
                        for f in &self.forwards {
                            ui.horizontal(|ui| {
                                let kind_str = match f.kind {
                                    ForwardKind::Local => "LOCAL",
                                    ForwardKind::Remote => "REMOTE",
                                    ForwardKind::Dynamic => "DYNAMIC",
                                };
                                ui.monospace(format!("[{kind_str}] {} -> {}", f.listen, f.dest));
                                if ui.small_button("Stop").clicked() {
                                    to_stop = Some(f.id);
                                }
                            });
                        }
                    });

                if let Some(id) = to_stop
                    && let Some(tx) = &self.cmd_tx
                {
                    let _ = tx.send(Cmd::ForwardStop { id });
                }

                if let Some((ref msg, is_err)) = self.forward_status {
                    ui.add_space(4.0);
                    let color = if is_err { ERROR_RED } else { OK_GREEN };
                    ui.colored_label(color, msg.as_str());
                }
            });
        self.show_forwards = open;
    }

    fn handle_input(&mut self, ui: &mut egui::Ui, metrics: &RenderMetrics) {
        let kb_captured = ui.ctx().egui_wants_keyboard_input();
        let ptr_captured = ui.ctx().is_pointer_over_egui();
        let events: Vec<egui::Event> = ui.input(|i| i.events.clone());
        let app_cursor = self.term.application_cursor_keys();
        for evt in events {
            match evt {
                egui::Event::Text(text) if !kb_captured => self.send_data(text.into_bytes()),
                // egui's winit layer turns Ctrl+C/Ctrl+X (without Shift) into clipboard
                // commands and never emits the Key events, so translate them
                // back into the control bytes a terminal expects.
                egui::Event::Copy if !kb_captured => self.send_data(vec![0x03]),
                egui::Event::Cut if !kb_captured => self.send_data(vec![0x18]),
                egui::Event::Paste(text) if !kb_captured => {
                    let mut out = Vec::new();
                    if self.term.bracketed_paste() {
                        out.extend_from_slice(b"[200~");
                        out.extend_from_slice(text.as_bytes());
                        out.extend_from_slice(b"[201~");
                    } else {
                        out.extend_from_slice(text.as_bytes());
                    }
                    self.send_data(out);
                }
                egui::Event::Key {
                    key,
                    pressed: true,
                    modifiers,
                    ..
                } if !kb_captured => match keys::encode(key, modifiers, app_cursor) {
                    KeyOut::Bytes(b) => self.send_data(b),
                    KeyOut::Quit
                    | KeyOut::NewTab
                    | KeyOut::CloseTab
                    | KeyOut::PrevTab
                    | KeyOut::NextTab => {
                        // Handled globally in GuiApp::handle_global_shortcuts
                    }
                    KeyOut::Paste => ui
                        .ctx()
                        .send_viewport_cmd(egui::ViewportCommand::RequestPaste),
                    KeyOut::Ignore => {}
                },
                egui::Event::MouseWheel { delta, .. } if !ptr_captured => {
                    self.handle_wheel(delta);
                }
                egui::Event::PointerButton {
                    pos,
                    button,
                    pressed,
                    modifiers,
                } if !ptr_captured => self.handle_pointer(pos, button, pressed, modifiers, metrics),
                egui::Event::PointerMoved(pos) if !ptr_captured => self.handle_motion(pos, metrics),
                egui::Event::PointerGone => self.drag_button = None,
                _ => {}
            }
        }

        if !self.term.mouse_sgr() && !ptr_captured {
            let dy = ui.input(|i| i.smooth_scroll_delta.y);
            self.pending_scroll += dy;
            let lines = (self.pending_scroll / metrics.row_h).floor() as i64;
            if lines != 0 {
                self.pending_scroll -= lines as f32 * metrics.row_h;
                if lines > 0 {
                    self.term.scroll_up(lines as usize);
                } else {
                    self.term.scroll_down((-lines) as usize);
                }
            }
        }
    }

    fn send_data(&self, bytes: Vec<u8>) {
        if let Some(tx) = &self.cmd_tx {
            let _ = tx.send(Cmd::Data(bytes));
        }
    }

    fn handle_wheel(&mut self, delta: egui::Vec2) {
        if !self.term.mouse_sgr() {
            return;
        }
        let n = (delta.y.abs().ceil() as u32).clamp(1, 5);
        let button = if delta.y > 0.0 { 64 } else { 65 };
        let (col, row) = self.pointer_cell.unwrap_or((0, 0));
        for _ in 0..n {
            let bytes = keys::sgr_mouse(col, row, button, false, false, egui::Modifiers::NONE);
            self.send_data(bytes);
        }
    }

    fn handle_pointer(
        &mut self,
        pos: Pos2,
        button: egui::PointerButton,
        pressed: bool,
        modifiers: egui::Modifiers,
        metrics: &RenderMetrics,
    ) {
        self.pointer_cell = self.cell_at(pos, metrics);
        if !self.term.mouse_sgr() {
            return;
        }
        let Some((col, row)) = self.pointer_cell else {
            return;
        };
        let code = match button {
            egui::PointerButton::Primary => 0,
            egui::PointerButton::Middle => 1,
            egui::PointerButton::Secondary => 2,
            _ => return,
        };
        let bytes = keys::sgr_mouse(col, row, code, !pressed, false, modifiers);
        self.send_data(bytes);
        self.drag_button = if pressed { Some(code) } else { None };
    }

    fn handle_motion(&mut self, pos: Pos2, metrics: &RenderMetrics) {
        self.pointer_cell = self.cell_at(pos, metrics);
        if !self.term.mouse_sgr() {
            return;
        }
        if let (Some(button), Some((col, row))) = (self.drag_button, self.pointer_cell) {
            let bytes = keys::sgr_mouse(col, row, button, false, true, egui::Modifiers::NONE);
            self.send_data(bytes);
        }
    }

    fn cell_at(&self, pos: Pos2, metrics: &RenderMetrics) -> Option<(u16, u16)> {
        if !metrics.grid_rect.contains(pos) {
            return None;
        }
        let col = (((pos.x - metrics.grid_rect.min.x) / metrics.char_w).floor() as u32)
            .min(self.cols - 1) as u16;
        let row = (((pos.y - metrics.grid_rect.min.y) / metrics.row_h).floor() as u32)
            .min(self.rows - 1) as u16;
        Some((col, row))
    }

    fn paint(
        &mut self,
        ui: &mut egui::Ui,
        status_rect: Rect,
        metrics: &RenderMetrics,
        keys_window: &mut KeysWindow,
    ) {
        let painter = ui.painter();
        painter.rect_filled(metrics.grid_rect, 0.0, metrics.palette.bg);
        let font = FontId::monospace(metrics.font_size);

        let live = self.term.viewport_offset() == 0;
        let (c_row, c_col) = self.term.cursor_position();
        let show_cursor = live && self.term.cursor_visible();

        for row in 0..self.rows {
            let line = self.term.viewport_line(row);
            let y0 = metrics.grid_rect.min.y + row as f32 * metrics.row_h;
            for run in paint::build_runs(line.cells(), &metrics.palette) {
                let x0 = metrics.grid_rect.min.x + run.start_cell as f32 * metrics.char_w;
                let w = run.cell_len as f32 * metrics.char_w;
                if run.bg != metrics.palette.bg {
                    painter.rect_filled(
                        Rect::from_min_size(pos2(x0, y0), vec2(w, metrics.row_h)),
                        0.0,
                        run.bg,
                    );
                }
                let text_pos = pos2(x0, y0);
                painter.text(
                    text_pos,
                    Align2::LEFT_TOP,
                    run.text.as_str(),
                    font.clone(),
                    run.fg,
                );
                if run.bold {
                    painter.text(
                        pos2(x0 + 0.6, y0),
                        Align2::LEFT_TOP,
                        run.text.as_str(),
                        font.clone(),
                        run.fg,
                    );
                }
                if run.underline {
                    painter.line_segment(
                        [
                            pos2(x0, y0 + metrics.row_h - 1.0),
                            pos2(x0 + w, y0 + metrics.row_h - 1.0),
                        ],
                        Stroke::new(1.0, run.fg),
                    );
                }
                if run.strikethrough {
                    let my = y0 + metrics.row_h * 0.5;
                    painter
                        .line_segment([pos2(x0, my), pos2(x0 + w, my)], Stroke::new(1.0, run.fg));
                }
            }

            if show_cursor && row == c_row {
                let cx = metrics.grid_rect.min.x + c_col as f32 * metrics.char_w;
                let rect = Rect::from_min_size(pos2(cx, y0), vec2(metrics.char_w, metrics.row_h));
                painter.rect_filled(rect, 0.0, metrics.palette.fg);
                let ch = line.cells()[c_col as usize].ch;
                if ch != ' ' {
                    painter.text(
                        pos2(cx, y0),
                        Align2::LEFT_TOP,
                        ch.to_string(),
                        font.clone(),
                        metrics.palette.bg,
                    );
                }
            }
        }

        self.paint_status(ui, status_rect, keys_window);
    }

    fn paint_status(&mut self, ui: &mut egui::Ui, rect: Rect, keys_window: &mut KeysWindow) {
        let painter = ui.painter();
        painter.rect_filled(rect, 0.0, Color32::from_rgb(30, 30, 36));

        let label = self
            .term
            .title()
            .map(str::to_string)
            .or_else(|| self.target.as_ref().map(Target::label))
            .unwrap_or_default();
        let mut details = Vec::new();
        if self.term.viewport_offset() > 0 {
            details.push(format!("↑ {} lines", self.term.viewport_offset()));
        }
        if let Some(ref log) = self.log {
            details.push(format!("Logging ({})", log.path().display()));
        }
        details.push("Ctrl+Shift+Q to quit".to_string());
        let status = format!("{label}    {}", details.join("  ·  "));
        painter.text(
            pos2(rect.min.x + 6.0, rect.center().y),
            Align2::LEFT_CENTER,
            status,
            FontId::monospace(12.0),
            Color32::from_gray(180),
        );

        let protocol = self.target.as_ref().map(|t| t.protocol);
        let btn_rect = Rect::from_min_max(
            pos2((rect.max.x - 300.0).max(rect.min.x), rect.min.y),
            rect.max,
        );
        ui.scope_builder(
            egui::UiBuilder::new()
                .max_rect(btn_rect)
                .layout(egui::Layout::right_to_left(egui::Align::Center)),
            |ui| {
                ui.add_space(6.0);
                match protocol {
                    Some(Protocol::Ssh) => {
                        let fwd_label = if self.forwards.is_empty() {
                            "Forwards".to_string()
                        } else {
                            format!("Forwards ({})", self.forwards.len())
                        };
                        if ui.small_button(fwd_label).clicked() {
                            self.show_forwards = !self.show_forwards;
                        }
                        let active_transfers = self
                            .sftp_transfers
                            .iter()
                            .filter(|t| {
                                matches!(t.state, TransferState::Queued | TransferState::Running)
                            })
                            .count();
                        let sftp_label = if active_transfers > 0 {
                            format!("Files (SFTP) ({active_transfers})")
                        } else {
                            "Files (SFTP)".to_string()
                        };
                        if ui.small_button(sftp_label).clicked() {
                            self.show_sftp = !self.show_sftp;
                            if self.show_sftp
                                && self.sftp_path.is_empty()
                                && let Some(tx) = &self.cmd_tx
                            {
                                let _ = tx.send(Cmd::SftpList {
                                    path: ".".to_string(),
                                });
                            }
                        }
                        if ui.small_button("Keys").clicked() {
                            if keys_window.open {
                                keys_window.open = false;
                            } else {
                                keys_window.open();
                            }
                        }
                    }
                    Some(Protocol::Serial | Protocol::Telnet) => {
                        let clicked = ui.small_button("Send break").clicked();
                        if clicked && let Some(tx) = &self.cmd_tx {
                            let _ = tx.send(Cmd::Break);
                        }
                    }
                    _ => {}
                }
            },
        );
    }
}

fn next_tab_index(active: usize, count: usize) -> usize {
    if count == 0 { 0 } else { (active + 1) % count }
}

fn prev_tab_index(active: usize, count: usize) -> usize {
    if count == 0 {
        0
    } else if active == 0 {
        count - 1
    } else {
        active - 1
    }
}

fn active_after_close(closing: usize, active: usize, new_count: usize) -> usize {
    if new_count == 0 {
        0
    } else if closing < active {
        active.saturating_sub(1)
    } else if active >= new_count {
        new_count - 1
    } else {
        active
    }
}

fn truncate_tab_title(title: &str, max_chars: usize) -> String {
    if title.chars().count() <= max_chars {
        title.to_string()
    } else {
        let mut s: String = title.chars().take(max_chars.saturating_sub(1)).collect();
        s.push('…');
        s
    }
}

pub struct GuiApp {
    sessions: Vec<Session>,
    active: usize,
    next_session_id: u64,
    confirm_close: Option<u64>,
    last_window_title: String,

    term_type: String,
    handle: tokio::runtime::Handle,

    font_size: f32,
    palette: Palette,
    grid_rect: Rect,
    char_w: f32,
    row_h: f32,

    quit: bool,
    keys_window: KeysWindow,
    known_hosts_window: KnownHostsWindow,
}

impl GuiApp {
    /// Connects straight away when `launch` names a target or profile;
    /// otherwise (or if they don't resolve) starts on the connect form,
    /// prefilled from `launch`.
    pub fn new(launch: LaunchArgs, term_type: String, handle: tokio::runtime::Handle) -> Self {
        let session = Session::from_launch(1, &launch);
        Self {
            sessions: vec![session],
            active: 0,
            next_session_id: 2,
            confirm_close: None,
            last_window_title: String::new(),
            term_type,
            handle,
            font_size: 14.0,
            palette: Palette::default(),
            grid_rect: Rect::NOTHING,
            char_w: 8.0,
            row_h: 14.0,
            quit: false,
            keys_window: KeysWindow::default(),
            known_hosts_window: KnownHostsWindow::default(),
        }
    }

    fn add_tab(&mut self) {
        let id = self.next_session_id;
        self.next_session_id += 1;
        self.sessions.push(Session::new_setup(id));
        self.active = self.sessions.len() - 1;
    }

    fn switch_tab(&mut self, idx: usize) {
        if idx < self.sessions.len() {
            self.active = idx;
            self.sessions[idx].attention = false;
        }
    }

    fn next_tab(&mut self) {
        if !self.sessions.is_empty() {
            let next = next_tab_index(self.active, self.sessions.len());
            self.switch_tab(next);
        }
    }

    fn prev_tab(&mut self) {
        if !self.sessions.is_empty() {
            let prev = prev_tab_index(self.active, self.sessions.len());
            self.switch_tab(prev);
        }
    }

    fn request_close_tab(&mut self, idx: usize) {
        if let Some(session) = self.sessions.get(idx) {
            if session.is_connected() {
                self.confirm_close = Some(session.id);
            } else {
                self.close_tab_at(idx);
            }
        }
    }

    fn close_tab_by_id(&mut self, id: u64) {
        if self.confirm_close == Some(id) {
            self.confirm_close = None;
        }
        if let Some(pos) = self.sessions.iter().position(|s| s.id == id) {
            self.close_tab_at(pos);
        }
    }

    fn close_tab_at(&mut self, idx: usize) {
        if self.sessions.len() <= 1 {
            self.quit = true;
            return;
        }
        if idx < self.sessions.len() {
            let removed = self.sessions.remove(idx);
            if self.confirm_close == Some(removed.id) {
                self.confirm_close = None;
            }
            self.active = active_after_close(idx, self.active, self.sessions.len());
            if let Some(active_session) = self.sessions.get_mut(self.active) {
                active_session.attention = false;
            }
        }
    }

    fn handle_global_shortcuts(&mut self, ui: &mut egui::Ui) {
        let mut actions = Vec::new();
        ui.input_mut(|i| {
            i.events.retain(|evt| {
                if let egui::Event::Key {
                    key,
                    pressed: true,
                    modifiers,
                    ..
                } = evt
                {
                    match keys::encode(*key, *modifiers, false) {
                        KeyOut::Quit => {
                            actions.push(KeyOut::Quit);
                            false
                        }
                        KeyOut::NewTab => {
                            actions.push(KeyOut::NewTab);
                            false
                        }
                        KeyOut::CloseTab => {
                            actions.push(KeyOut::CloseTab);
                            false
                        }
                        KeyOut::PrevTab => {
                            actions.push(KeyOut::PrevTab);
                            false
                        }
                        KeyOut::NextTab => {
                            actions.push(KeyOut::NextTab);
                            false
                        }
                        _ => true,
                    }
                } else {
                    true
                }
            });
        });

        for act in actions {
            match act {
                KeyOut::Quit => self.quit = true,
                KeyOut::NewTab if self.confirm_close.is_none() => self.add_tab(),
                KeyOut::CloseTab if self.confirm_close.is_none() => {
                    self.request_close_tab(self.active);
                }
                KeyOut::PrevTab if self.confirm_close.is_none() => self.prev_tab(),
                KeyOut::NextTab if self.confirm_close.is_none() => self.next_tab(),
                _ => {}
            }
        }
    }
}

impl eframe::App for GuiApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let mut any_events = false;
        for (idx, session) in self.sessions.iter_mut().enumerate() {
            let is_active = idx == self.active;
            if session.evt_rx.is_none()
                && !matches!(session.state, State::Setup(_) | State::Failed(_))
            {
                session.start_connect(&self.term_type, &self.handle, ctx);
            }
            if session.drain_events(is_active) {
                any_events = true;
            }
        }
        if any_events {
            ctx.request_repaint();
        }

        // Steady redraw for cursor blink; the session task also pokes repaint.
        ctx.request_repaint_after(Duration::from_millis(16));
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if let Some(active) = self.sessions.get(self.active) {
            let title = active.window_title();
            if title != self.last_window_title {
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::Title(title.clone()));
                self.last_window_title = title;
            }
        }

        self.handle_global_shortcuts(ui);

        let mut switch_to = None;
        let mut close_idx = None;
        let mut new_tab = false;

        let tab_bar_frame = egui::Frame::new()
            .fill(Color32::from_rgb(24, 24, 30))
            .inner_margin(egui::Margin::symmetric(6, 4));

        egui::Panel::top("tab_bar")
            .frame(tab_bar_frame)
            .show(ui, |ui| {
                egui::ScrollArea::horizontal()
                    .id_salt("tab_bar_scroll")
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            for (idx, session) in self.sessions.iter().enumerate() {
                                let is_active = idx == self.active;
                                let bg = if is_active {
                                    Color32::from_rgb(46, 48, 60)
                                } else {
                                    Color32::from_rgb(32, 32, 40)
                                };
                                let pill = egui::Frame::new()
                                    .fill(bg)
                                    .corner_radius(4.0)
                                    .inner_margin(egui::Margin::symmetric(8, 3));

                                pill.show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.spacing_mut().item_spacing = vec2(5.0, 0.0);
                                        ui.colored_label(session.status_color(), "●");
                                        if session.attention {
                                            ui.colored_label(Color32::from_rgb(250, 200, 50), "!")
                                                .on_hover_text("Prompt waiting");
                                        }
                                        let title = truncate_tab_title(&session.title(), 28);
                                        let title_btn = egui::Button::new(title).frame(false);
                                        if ui.add(title_btn).clicked() {
                                            switch_to = Some(idx);
                                        }
                                        let close_btn = egui::Button::new("×").frame(false);
                                        if ui.add(close_btn).on_hover_text("Close tab").clicked() {
                                            close_idx = Some(idx);
                                        }
                                    });
                                });
                            }
                            if ui
                                .button("+")
                                .on_hover_text("New tab (Ctrl+Shift+T)")
                                .clicked()
                            {
                                new_tab = true;
                            }
                        });
                    });
            });

        if let Some(idx) = switch_to {
            self.switch_tab(idx);
        }
        if let Some(idx) = close_idx {
            self.request_close_tab(idx);
        }
        if new_tab && self.confirm_close.is_none() {
            self.add_tab();
        }

        let tab_count = self.sessions.len();
        let modal_open = self.confirm_close.is_some();
        let mut session_action = SessionAction::None;

        let mut metrics = RenderMetrics {
            font_size: self.font_size,
            palette: self.palette,
            grid_rect: self.grid_rect,
            char_w: self.char_w,
            row_h: self.row_h,
        };

        egui::CentralPanel::default()
            .frame(egui::Frame::NONE)
            .show(ui, |ui| {
                if let Some(session) = self.sessions.get_mut(self.active) {
                    match session.state {
                        State::Running => {
                            session.ui_running(ui, &mut metrics, &mut self.keys_window, modal_open);
                        }
                        State::Setup(_) => {
                            egui::Frame::NONE
                                .inner_margin(egui::Margin::same(16))
                                .show(ui, |ui| {
                                    session_action = session.ui_setup(
                                        ui,
                                        tab_count,
                                        &mut self.keys_window,
                                        &mut self.known_hosts_window,
                                        &self.term_type,
                                        &self.handle,
                                    );
                                });
                        }
                        _ => {
                            egui::Frame::NONE
                                .inner_margin(egui::Margin::same(16))
                                .show(ui, |ui| {
                                    session_action = session.ui_dialog(
                                        ui,
                                        tab_count,
                                        &self.term_type,
                                        &self.handle,
                                    );
                                });
                        }
                    }
                }
            });

        self.grid_rect = metrics.grid_rect;
        self.char_w = metrics.char_w;
        self.row_h = metrics.row_h;

        if session_action == SessionAction::CloseTab {
            self.close_tab_at(self.active);
        }

        let ctx = ui.ctx().clone();
        manage::show_keys_window(&ctx, &mut self.keys_window);
        manage::show_known_hosts_window(&ctx, &mut self.known_hosts_window);

        if let Some(confirm_id) = self.confirm_close {
            let session = self.sessions.iter().find(|s| s.id == confirm_id);
            if let Some(session) = session {
                let mut close_confirmed = false;
                let mut close_cancelled = false;
                let title = session.title();
                egui::Window::new("Close session?")
                    .id(egui::Id::unique("confirm_close_dialog"))
                    .collapsible(false)
                    .resizable(false)
                    .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(&ctx, |ui| {
                        ui.label(format!("Disconnect from {title}?"));
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            if ui.button("Disconnect").clicked() {
                                close_confirmed = true;
                            }
                            if ui.button("Cancel").clicked() {
                                close_cancelled = true;
                            }
                        });
                        if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                            close_cancelled = true;
                        }
                    });
                if close_confirmed {
                    self.confirm_close = None;
                    self.close_tab_by_id(confirm_id);
                } else if close_cancelled {
                    self.confirm_close = None;
                }
            } else {
                self.confirm_close = None;
            }
        }

        if self.quit {
            self.sessions.clear();
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }
}

/// OK/Cancel row for text prompts. Enter submits.
fn submit_buttons(ui: &mut egui::Ui, enter: bool) -> Outcome {
    let mut out = if enter {
        Outcome::Answered
    } else {
        Outcome::Pending
    };
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        if ui.button("OK").clicked() {
            out = Outcome::Answered;
        }
        if ui.button("Cancel").clicked() {
            out = Outcome::Quit;
        }
    });
    out
}

/// Sends the dialog's answer back to the waiting connect task. `accept =
/// false` means cancel/reject.
fn answer(state: State, accept: bool) {
    match state {
        State::Secret { input, reply, .. } => {
            let _ = reply.send(accept.then_some(input));
        }
        State::HostKey { reply, .. } => {
            let _ = reply.send(accept);
        }
        State::KeyboardInteractive { answers, reply, .. } => {
            let _ = reply.send(accept.then_some(answers));
        }
        State::Setup(_) | State::Connecting | State::Running | State::Failed(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maelstromssh_core::config::AuthMethod;

    #[test]
    fn forward_list_round_trips_local_remote_dynamic() {
        let parsed =
            parse_forward_list("L 8080:localhost:80, R 9000:127.0.0.1:3000, D 1080").unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].kind, ForwardKind::Local);
        assert_eq!(parsed[0].bind_port, 8080);
        assert_eq!(parsed[1].kind, ForwardKind::Remote);
        assert_eq!(parsed[1].bind_port, 9000);
        assert_eq!(parsed[2].kind, ForwardKind::Dynamic);
        assert_eq!(parsed[2].bind_port, 1080);

        let formatted = format_forward_list(&parsed);
        let reparsed = parse_forward_list(&formatted).unwrap();
        assert_eq!(reparsed, parsed);
    }

    #[test]
    fn format_bytes_and_speed_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1536), "1.5 KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(format_bytes(5 * 1024 * 1024 * 1024), "5.0 GiB");

        assert_eq!(format_speed(0.0), "0 B/s");
        assert_eq!(format_speed(500.0), "500 B/s");
        assert_eq!(format_speed(1536.0), "1.5 KiB/s");
        assert_eq!(format_speed(2.5 * 1024.0 * 1024.0), "2.5 MiB/s");
        assert_eq!(format_speed(1.2 * 1024.0 * 1024.0 * 1024.0), "1.2 GiB/s");
    }

    fn test_session(id: u64, state: State) -> Session {
        Session {
            id,
            target: None,
            profile: None,
            log_spec: None,
            log: None,
            cmd_tx: None,
            evt_rx: None,
            state,
            attention: false,
            term: Terminal::new(80, 24),
            cols: 80,
            rows: 24,
            pending_scroll: 0.0,
            pointer_cell: None,
            drag_button: None,
            show_sftp: false,
            sftp_path: String::new(),
            sftp_path_input: String::new(),
            sftp_entries: Vec::new(),
            sftp_selected: None,
            sftp_status: None,
            sftp_local_path: String::new(),
            sftp_mkdir_name: String::new(),
            sftp_rename_to: String::new(),
            sftp_resume: false,
            sftp_transfers: Vec::new(),
            sftp_next_transfer_id: 1,
            show_forwards: false,
            forwards: Vec::new(),
            forward_kind: ForwardKind::Local,
            forward_spec: String::new(),
            forward_status: None,
        }
    }

    #[test]
    fn tab_index_navigation_wraps() {
        assert_eq!(next_tab_index(0, 1), 0);
        assert_eq!(prev_tab_index(0, 1), 0);

        assert_eq!(next_tab_index(0, 3), 1);
        assert_eq!(next_tab_index(1, 3), 2);
        assert_eq!(next_tab_index(2, 3), 0);

        assert_eq!(prev_tab_index(0, 3), 2);
        assert_eq!(prev_tab_index(1, 3), 0);
        assert_eq!(prev_tab_index(2, 3), 1);

        assert_eq!(next_tab_index(0, 0), 0);
        assert_eq!(prev_tab_index(0, 0), 0);
    }

    #[test]
    fn active_index_after_close() {
        assert_eq!(active_after_close(0, 2, 2), 1);
        assert_eq!(active_after_close(1, 1, 2), 1);
        assert_eq!(active_after_close(2, 2, 2), 1);
        assert_eq!(active_after_close(2, 1, 2), 1);
        assert_eq!(active_after_close(0, 0, 0), 0);
    }

    #[test]
    fn tab_title_selection_priority() {
        let mut session = test_session(1, State::Connecting);
        assert_eq!(session.title(), "New tab");
        assert_eq!(session.window_title(), "MaelstromSSH");

        let target = Target {
            protocol: Protocol::Ssh,
            host: "server.example.com".to_string(),
            port: 22,
            user: "alice".to_string(),
            auth: AuthMethod::Auto {
                identities: Vec::new(),
            },
            jump: Vec::new(),
            forwards: Vec::new(),
            serial: None,
            warnings: Vec::new(),
        };
        session.target = Some(target);
        assert_eq!(session.title(), "alice@server.example.com:22");
        assert_eq!(session.window_title(), "alice@server.example.com:22");

        session.term.feed(b"\x1b]0;remote-shell\x07");
        assert_eq!(session.title(), "remote-shell");
        assert_eq!(session.window_title(), "remote-shell");

        session.term.feed(b"\x1b]0;   \x07");
        assert_eq!(session.title(), "alice@server.example.com:22");
        assert_eq!(session.window_title(), "alice@server.example.com:22");
    }

    #[test]
    fn truncate_tab_title_handles_utf8() {
        assert_eq!(truncate_tab_title("short", 10), "short");
        assert_eq!(truncate_tab_title("exactlength", 11), "exactlength");
        assert_eq!(truncate_tab_title("longerthanthelimit", 10), "longertha…");
        assert_eq!(truncate_tab_title("🦀🦀🦀🦀🦀", 4), "🦀🦀🦀…");
    }

    #[test]
    fn session_connected_and_status_state() {
        let s_run = test_session(1, State::Running);
        assert!(s_run.is_connected());
        assert_eq!(s_run.status_color(), OK_GREEN);

        let s_conn = test_session(2, State::Connecting);
        assert!(!s_conn.is_connected());
        assert_eq!(s_conn.status_color(), Color32::from_rgb(230, 180, 60));

        let s_fail = test_session(3, State::Failed("refused".into()));
        assert!(!s_fail.is_connected());
        assert_eq!(s_fail.status_color(), ERROR_RED);

        let (reply, _) = std::sync::mpsc::channel();
        let s_secret = test_session(
            4,
            State::Secret {
                prompt: "Password:".into(),
                input: String::new(),
                reply,
            },
        );
        assert!(!s_secret.is_connected());
        assert_eq!(s_secret.status_color(), Color32::from_rgb(230, 180, 60));
    }

    #[test]
    fn tab_lifecycle_add_switch_close() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let mut app = GuiApp {
            sessions: vec![
                test_session(1, State::Running),
                test_session(2, State::Failed("err".into())),
            ],
            active: 0,
            next_session_id: 3,
            confirm_close: None,
            last_window_title: String::new(),
            term_type: "xterm-256color".into(),
            handle: rt.handle().clone(),
            font_size: 14.0,
            palette: Palette::default(),
            grid_rect: Rect::NOTHING,
            char_w: 8.0,
            row_h: 14.0,
            quit: false,
            keys_window: KeysWindow::default(),
            known_hosts_window: KnownHostsWindow::default(),
        };

        app.sessions[1].attention = true;
        app.switch_tab(1);
        assert_eq!(app.active, 1);
        assert!(!app.sessions[1].attention);

        app.next_tab();
        assert_eq!(app.active, 0);
        app.prev_tab();
        assert_eq!(app.active, 1);

        app.sessions.push(test_session(
            app.next_session_id,
            State::Failed("new".into()),
        ));
        app.next_session_id += 1;
        app.active = app.sessions.len() - 1;
        assert_eq!(app.active, 2);
        assert_eq!(app.sessions.len(), 3);

        app.request_close_tab(2);
        assert_eq!(app.sessions.len(), 2);
        assert!(app.confirm_close.is_none());

        app.request_close_tab(0);
        assert_eq!(app.confirm_close, Some(1));
        assert_eq!(app.sessions.len(), 2);

        app.close_tab_by_id(1);
        assert_eq!(app.confirm_close, None);
        assert_eq!(app.sessions.len(), 1);

        app.close_tab_at(0);
        assert!(app.quit);
    }
}
