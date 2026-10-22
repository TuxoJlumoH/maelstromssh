//! The egui application: shows a connect form when started without a
//! target, owns the core [`Terminal`], answers the connect task's questions (password, passphrase, host key, 2FA) in dialogs, and
//! paints the grid + status bar. The SSH session lives on a background tokio
//! task (see [`crate::ssh`]); this module is purely single-threaded.

use std::time::Duration;

use egui::{pos2, vec2, Align2, Color32, FontId, Pos2, Rect, Stroke};
use tokio::sync::mpsc;
use vortexssh_core::config::{ProfileStore, SshConfig};
use vortexssh_core::prompt::KiPrompt;
use vortexssh_core::target::{AuthChoice, Target, TargetArgs};
use vortexssh_core::term::Terminal;

use crate::keys::{self, KeyOut};
use crate::paint::{self, Palette};
use crate::ssh::{self, Cmd, Evt, Question};

const ERROR_RED: Color32 = Color32::from_rgb(240, 80, 80);

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
#[derive(Default)]
struct ConnectForm {
    target: String,
    profile: Option<String>,
    port: String,
    identity: String,
    /// `None`: auto, or whatever the profile says.
    auth: Option<AuthChoice>,
    error: Option<String>,
    profiles: Vec<String>,
    aliases: Vec<String>,
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
        form
    }

    fn from_args(args: &TargetArgs) -> Self {
        let mut form = Self::new();
        form.target = args.target.clone().unwrap_or_default();
        form.profile = args.profile.clone().filter(|p| form.profiles.contains(p));
        form.port = args.port.map(|p| p.to_string()).unwrap_or_default();
        form.identity = args
            .identity
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        form.auth = args.auth;
        form
    }

    /// Prefills the form from the target that was just tried.
    fn from_target(target: &Target, profile: Option<String>) -> Self {
        let mut form = Self::new();
        if profile.is_some() {
            form.profile = profile;
        } else {
            form.target = format!("{}@{}", target.user, target.host);
            if target.port != 22 {
                form.port = target.port.to_string();
            }
        }
        form
    }

    fn args(&self) -> Result<TargetArgs, String> {
        let port = match self.port.trim() {
            "" => None,
            p => Some(
                p.parse::<u16>()
                    .ok()
                    .filter(|&p| p != 0)
                    .ok_or_else(|| format!("'{p}' is not a valid port"))?,
            ),
        };
        let target = self.target.trim();
        if self.profile.is_none() && target.is_empty() {
            return Err("enter user@host, a host, or an ssh_config alias".into());
        }
        let identity = self.identity.trim();
        Ok(TargetArgs {
            target: self.profile.is_none().then(|| target.to_string()),
            port,
            identity: (!identity.is_empty()).then(|| identity.into()),
            profile: self.profile.clone(),
            auth: self.auth,
        })
    }
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

pub struct GuiApp {
    /// `None` until the connect form has been filled in.
    target: Option<Target>,
    /// The profile the target came from, to prefill the form again.
    profile: Option<String>,
    term_type: String,
    handle: tokio::runtime::Handle,
    cmd_tx: Option<mpsc::UnboundedSender<Cmd>>,
    evt_rx: Option<mpsc::UnboundedReceiver<Evt>>,

    state: State,

    term: Terminal,
    cols: u32,
    rows: u32,
    font_size: f32,
    palette: Palette,

    grid_rect: Rect,
    char_w: f32,
    row_h: f32,

    pending_scroll: f32,
    pointer_cell: Option<(u16, u16)>,
    drag_button: Option<u8>,
    quit: bool,
}

impl GuiApp {
    /// Connects straight away when `args` name a target or profile;
    /// otherwise (or if they don't resolve) starts on the connect form,
    /// prefilled from `args`.
    pub fn new(args: TargetArgs, term_type: String, handle: tokio::runtime::Handle) -> Self {
        let profile = args.profile.clone();
        let (target, state) = if args.target.is_some() || profile.is_some() {
            match args.clone().resolve() {
                Ok(target) => (Some(target), State::Connecting),
                Err(e) => {
                    let mut form = ConnectForm::from_args(&args);
                    form.error = Some(e.to_string());
                    (None, State::Setup(Box::new(form)))
                }
            }
        } else {
            (None, State::Setup(Box::new(ConnectForm::from_args(&args))))
        };
        Self {
            target,
            profile,
            term_type,
            handle,
            cmd_tx: None,
            evt_rx: None,
            state,
            term: Terminal::new(80, 24),
            cols: 80,
            rows: 24,
            font_size: 14.0,
            palette: Palette::default(),
            grid_rect: Rect::NOTHING,
            char_w: 8.0,
            row_h: 14.0,
            pending_scroll: 0.0,
            pointer_cell: None,
            drag_button: None,
            quit: false,
        }
    }

    /// Spawns a fresh connect task with its own channels.
    fn start_connect(&mut self, ctx: &egui::Context) {
        let Some(target) = self.target.clone() else {
            return;
        };
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (evt_tx, evt_rx) = mpsc::unbounded_channel();
        self.handle.spawn(ssh::connect_and_run(
            target,
            self.term_type.clone(),
            cmd_rx,
            evt_tx,
            ctx.clone(),
        ));
        self.cmd_tx = Some(cmd_tx);
        self.evt_rx = Some(evt_rx);
        self.term = Terminal::new(self.cols, self.rows);
        self.state = State::Connecting;
    }
}

impl eframe::App for GuiApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.evt_rx.is_none() && !matches!(self.state, State::Setup(_)) {
            self.start_connect(ctx);
        }

        // Drain SSH events, feeding output into the emulator and sending any
        // terminal responses (cursor reports etc.) back.
        let mut responses: Vec<u8> = Vec::new();
        if let Some(rx) = self.evt_rx.as_mut() {
            while let Ok(evt) = rx.try_recv() {
                match evt {
                    Evt::Ask(q) => self.state = State::from_question(q),
                    Evt::Ready => self.state = State::Running,
                    Evt::Data(data) => {
                        self.term.feed(&data);
                        responses.extend(self.term.take_responses());
                    }
                    Evt::Closed(msg) => self.state = State::Failed(msg),
                }
            }
        }
        if !responses.is_empty() {
            self.send_data(responses);
        }

        // Steady redraw for cursor blink; the SSH task also pokes repaint.
        ctx.request_repaint_after(Duration::from_millis(16));
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if matches!(self.state, State::Running) {
            self.ui_running(ui);
        } else {
            egui::Frame::NONE
                .inner_margin(egui::Margin::same(16))
                .show(ui, |ui| {
                    if matches!(self.state, State::Setup(_)) {
                        self.ui_setup(ui);
                    } else {
                        self.ui_dialog(ui);
                    }
                });
        }

        if self.quit {
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }
}

impl GuiApp {
    fn ui_setup(&mut self, ui: &mut egui::Ui) {
        let State::Setup(form) = &mut self.state else {
            return;
        };
        let enter = ui.input(|i| i.key_pressed(egui::Key::Enter));
        let mut submit = false;
        let mut quit = false;

        ui.heading("VortexSSH");
        ui.label("New connection");
        ui.add_space(8.0);

        egui::Grid::new("connect_form")
            .num_columns(2)
            .spacing([12.0, 8.0])
            .show(ui, |ui| {
                if !form.profiles.is_empty() {
                    ui.label("Profile");
                    egui::ComboBox::from_id_salt("profile")
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

                ui.label("Authentication");
                let is_profile = form.profile.is_some();
                egui::ComboBox::from_id_salt("auth")
                    .selected_text(auth_label(form.auth, is_profile))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut form.auth, None, auth_label(None, is_profile));
                        for (choice, label) in AUTH_CHOICES.iter().skip(1) {
                            ui.selectable_value(&mut form.auth, Some(*choice), *label);
                        }
                    });
                ui.end_row();
            });

        if form.profile.is_none() && !form.aliases.is_empty() {
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

        if let Some(err) = &form.error {
            ui.add_space(8.0);
            ui.colored_label(ERROR_RED, err.as_str());
        }

        ui.add_space(12.0);
        ui.horizontal(|ui| {
            submit |= ui.button("Connect").clicked() || enter;
            quit |= ui.button("Quit").clicked();
        });

        if quit {
            self.quit = true;
        } else if submit {
            let resolved = form
                .args()
                .and_then(|args| args.resolve().map_err(|e| e.to_string()));
            match resolved {
                Ok(target) => {
                    for warning in &target.warnings {
                        tracing::warn!("{warning}");
                    }
                    self.profile = form.profile.clone();
                    self.target = Some(target);
                    self.start_connect(ui.ctx());
                }
                Err(e) => form.error = Some(e),
            }
        }
    }

    /// Renders whichever pre-session screen the state calls for. The state is
    /// taken out for the frame and put back unless the dialog was answered.
    fn ui_dialog(&mut self, ui: &mut egui::Ui) {
        let mut state = std::mem::replace(&mut self.state, State::Connecting);
        let label = self.target.as_ref().map(Target::label).unwrap_or_default();
        let enter = ui.input(|i| i.key_pressed(egui::Key::Enter));

        ui.heading("VortexSSH");
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
                    if ui.button("Quit").clicked() {
                        out = Outcome::Quit;
                    }
                });
                out
            }
            State::Running | State::Setup(_) => Outcome::Pending,
        };

        match outcome {
            Outcome::Pending => self.state = state,
            Outcome::Answered => answer(state, true),
            Outcome::Quit => {
                let failed = matches!(state, State::Failed(_));
                answer(state, false);
                // Rejecting a prompt cancels the connection; the task then
                // reports the failure. Quitting from the failure screen exits.
                if failed {
                    self.quit = true;
                }
            }
            Outcome::Retry => self.start_connect(ui.ctx()),
            Outcome::Edit => {
                let form = match &self.target {
                    Some(t) => ConnectForm::from_target(t, self.profile.clone()),
                    None => ConnectForm::new(),
                };
                self.cmd_tx = None;
                self.evt_rx = None;
                self.state = State::Setup(Box::new(form));
            }
        }
    }

    fn ui_running(&mut self, ui: &mut egui::Ui) {
        let full = ui.available_rect_before_wrap();
        let status_h = 20.0;
        let grid_rect = Rect::from_min_max(
            full.min,
            pos2(full.max.x, (full.max.y - status_h).max(full.min.y)),
        );
        let status_rect = Rect::from_min_max(pos2(full.min.x, full.max.y - status_h), full.max);

        // Measure the monospace cell and resize the emulator to match.
        let font = FontId::monospace(self.font_size);
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
        self.grid_rect = grid_rect;
        self.char_w = cw;
        self.row_h = rh;

        self.handle_input(ui);
        self.paint(ui, status_rect);
    }

    fn handle_input(&mut self, ui: &mut egui::Ui) {
        let events: Vec<egui::Event> = ui.input(|i| i.events.clone());
        let app_cursor = self.term.application_cursor_keys();
        for evt in events {
            match evt {
                egui::Event::Text(text) => self.send_data(text.into_bytes()),
                // egui's winit layer turns Ctrl+C/Ctrl+X into clipboard
                // commands and never emits the Key events, so translate them
                // back into the control bytes a terminal expects.
                egui::Event::Copy => self.send_data(vec![0x03]),
                egui::Event::Cut => self.send_data(vec![0x18]),
                egui::Event::Paste(text) => {
                    let mut out = Vec::new();
                    if self.term.bracketed_paste() {
                        out.extend_from_slice(b"\x1b[200~");
                        out.extend_from_slice(text.as_bytes());
                        out.extend_from_slice(b"\x1b[201~");
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
                } => match keys::encode(key, modifiers, app_cursor) {
                    KeyOut::Bytes(b) => self.send_data(b),
                    KeyOut::Quit => self.quit = true,
                    KeyOut::Ignore => {}
                },
                egui::Event::MouseWheel { delta, .. } => self.handle_wheel(delta),
                egui::Event::PointerButton {
                    pos,
                    button,
                    pressed,
                    modifiers,
                } => self.handle_pointer(pos, button, pressed, modifiers),
                egui::Event::PointerMoved(pos) => self.handle_motion(pos),
                egui::Event::PointerGone => self.drag_button = None,
                _ => {}
            }
        }

        if !self.term.mouse_sgr() {
            let dy = ui.input(|i| i.smooth_scroll_delta.y);
            self.pending_scroll += dy;
            let lines = (self.pending_scroll / self.row_h).floor() as i64;
            if lines != 0 {
                self.pending_scroll -= lines as f32 * self.row_h;
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
    ) {
        self.pointer_cell = self.cell_at(pos);
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

    fn handle_motion(&mut self, pos: Pos2) {
        self.pointer_cell = self.cell_at(pos);
        if !self.term.mouse_sgr() {
            return;
        }
        if let (Some(button), Some((col, row))) = (self.drag_button, self.pointer_cell) {
            let bytes = keys::sgr_mouse(col, row, button, false, true, egui::Modifiers::NONE);
            self.send_data(bytes);
        }
    }

    fn cell_at(&self, pos: Pos2) -> Option<(u16, u16)> {
        if !self.grid_rect.contains(pos) {
            return None;
        }
        let col = (((pos.x - self.grid_rect.min.x) / self.char_w).floor() as u32).min(self.cols - 1)
            as u16;
        let row = (((pos.y - self.grid_rect.min.y) / self.row_h).floor() as u32).min(self.rows - 1)
            as u16;
        Some((col, row))
    }

    fn paint(&self, ui: &egui::Ui, status_rect: Rect) {
        let painter = ui.painter();
        painter.rect_filled(self.grid_rect, 0.0, self.palette.bg);
        let font = FontId::monospace(self.font_size);

        let live = self.term.viewport_offset() == 0;
        let (c_row, c_col) = self.term.cursor_position();
        let show_cursor = live && self.term.cursor_visible();

        for row in 0..self.rows {
            let line = self.term.viewport_line(row);
            let y0 = self.grid_rect.min.y + row as f32 * self.row_h;
            for run in paint::build_runs(line.cells(), &self.palette) {
                let x0 = self.grid_rect.min.x + run.start_cell as f32 * self.char_w;
                let w = run.cell_len as f32 * self.char_w;
                if run.bg != self.palette.bg {
                    painter.rect_filled(
                        Rect::from_min_size(pos2(x0, y0), vec2(w, self.row_h)),
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
                            pos2(x0, y0 + self.row_h - 1.0),
                            pos2(x0 + w, y0 + self.row_h - 1.0),
                        ],
                        Stroke::new(1.0, run.fg),
                    );
                }
                if run.strikethrough {
                    let my = y0 + self.row_h * 0.5;
                    painter
                        .line_segment([pos2(x0, my), pos2(x0 + w, my)], Stroke::new(1.0, run.fg));
                }
            }

            if show_cursor && row == c_row {
                let cx = self.grid_rect.min.x + c_col as f32 * self.char_w;
                let rect = Rect::from_min_size(pos2(cx, y0), vec2(self.char_w, self.row_h));
                painter.rect_filled(rect, 0.0, self.palette.fg);
                let ch = line.cells()[c_col as usize].ch;
                if ch != ' ' {
                    painter.text(
                        pos2(cx, y0),
                        Align2::LEFT_TOP,
                        ch.to_string(),
                        font.clone(),
                        self.palette.bg,
                    );
                }
            }
        }

        self.paint_status(ui, status_rect);
    }

    fn paint_status(&self, ui: &egui::Ui, rect: Rect) {
        let painter = ui.painter();
        painter.rect_filled(rect, 0.0, Color32::from_rgb(30, 30, 36));

        let label = self
            .term
            .title()
            .map(str::to_string)
            .or_else(|| self.target.as_ref().map(Target::label))
            .unwrap_or_default();
        let status = if self.term.viewport_offset() > 0 {
            format!("{label}    ↑ {} lines", self.term.viewport_offset())
        } else {
            format!("{label}    Ctrl+Shift+Q to quit")
        };
        painter.text(
            pos2(rect.min.x + 6.0, rect.center().y),
            Align2::LEFT_CENTER,
            status,
            FontId::monospace(12.0),
            Color32::from_gray(180),
        );
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
