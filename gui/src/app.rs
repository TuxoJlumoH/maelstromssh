//! The egui application: owns the core [`Terminal`], drives authentication
//! dialogs (password/passphrase/host-key), and paints the grid + status bar.
//! The SSH session lives on a background tokio task (see [`crate::ssh`]);
//! this module is purely single-threaded.

use std::sync::Arc;
use std::time::Duration;

use egui::{pos2, vec2, Align2, Color32, FontId, Pos2, Rect, Stroke};
use vortexssh_core::config::AuthMethod;
use vortexssh_core::ssh::HostKeyVerifier;
use vortexssh_core::term::Terminal;

use crate::keys::{self, KeyOut};
use crate::paint::{self, Palette};
use crate::ssh::{self, Cmd, ConnectSpec, Evt};

/// A host-key confirmation passed from the background connect task to the UI.
pub struct HostKeyQuestion {
    pub host: String,
    pub port: u16,
    pub fingerprint: String,
    pub reply: std::sync::mpsc::Sender<bool>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Prompt,
    Connecting,
    HostKey,
    Running,
    Failed,
}

enum State {
    Prompt {
        password: String,
        passphrase: String,
        error: Option<String>,
    },
    Connecting,
    HostKey {
        host: String,
        port: u16,
        fingerprint: String,
        reply: std::sync::mpsc::Sender<bool>,
    },
    Running,
    Failed(String),
}

pub struct GuiApp {
    spec: ConnectSpec,
    handle: tokio::runtime::Handle,
    verifier: Arc<dyn HostKeyVerifier>,
    question_rx: std::sync::mpsc::Receiver<HostKeyQuestion>,
    evt_rx: tokio::sync::mpsc::UnboundedReceiver<Evt>,
    cmd_tx: tokio::sync::mpsc::UnboundedSender<Cmd>,
    cmd_rx: Option<tokio::sync::mpsc::UnboundedReceiver<Cmd>>,
    evt_tx: Option<tokio::sync::mpsc::UnboundedSender<Evt>>,

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
    pub fn new(
        spec: ConnectSpec,
        handle: tokio::runtime::Handle,
        verifier: Arc<dyn HostKeyVerifier>,
        question_rx: std::sync::mpsc::Receiver<HostKeyQuestion>,
        channels: ssh::Channels,
    ) -> Self {
        let ssh::Channels {
            cmd_tx,
            cmd_rx,
            evt_tx,
            evt_rx,
        } = channels;
        let (needs_password, needs_passphrase) = auth_prompts(&spec.auth);
        let state = if needs_password || needs_passphrase {
            State::Prompt {
                password: String::new(),
                passphrase: String::new(),
                error: None,
            }
        } else {
            State::Connecting // agent: auto-connect on first logic()
        };
        Self {
            spec,
            handle,
            verifier,
            question_rx,
            evt_rx,
            cmd_tx,
            cmd_rx: Some(cmd_rx),
            evt_tx: Some(evt_tx),
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

    fn phase(&self) -> Phase {
        match &self.state {
            State::Prompt { .. } => Phase::Prompt,
            State::Connecting => Phase::Connecting,
            State::HostKey { .. } => Phase::HostKey,
            State::Running => Phase::Running,
            State::Failed(_) => Phase::Failed,
        }
    }

    fn label(&self) -> String {
        format!("{}@{}:{}", self.spec.user, self.spec.host, self.spec.port)
    }

    fn start_connect(
        &mut self,
        ctx: &egui::Context,
        password: Option<String>,
        passphrase: Option<String>,
    ) {
        let (Some(cmd_rx), Some(evt_tx)) = (self.cmd_rx.take(), self.evt_tx.take()) else {
            return;
        };
        let handle = self.handle.clone();
        let spec = self.spec.clone();
        let verifier = self.verifier.clone();
        let notify = ctx.clone();
        handle.spawn(ssh::connect_and_run(
            spec,
            password,
            passphrase,
            verifier,
            cmd_rx,
            evt_tx,
            notify,
        ));
        self.state = State::Connecting;
    }
}

impl eframe::App for GuiApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Auto-connect for methods that need no prompt (ssh-agent).
        if self.phase() == Phase::Connecting && self.cmd_rx.is_some() {
            self.start_connect(ctx, None, None);
        }

        // Host-key question from the background connect task.
        if let Ok(q) = self.question_rx.try_recv() {
            self.state = State::HostKey {
                host: q.host,
                port: q.port,
                fingerprint: q.fingerprint,
                reply: q.reply,
            };
        }

        // Drain SSH output into the emulator, forwarding any responses back.
        let mut responses: Vec<u8> = Vec::new();
        while let Ok(evt) = self.evt_rx.try_recv() {
            match evt {
                Evt::Ready => self.state = State::Running,
                Evt::Data(data) => {
                    self.term.feed(&data);
                    responses.extend(self.term.take_responses());
                }
                Evt::Closed(msg) => self.state = State::Failed(msg),
            }
        }
        if !responses.is_empty() {
            let _ = self.cmd_tx.send(Cmd::Data(responses));
        }

        // Steady redraw for cursor blink; the SSH task also pokes repaint.
        ctx.request_repaint_after(Duration::from_millis(16));
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        match self.phase() {
            Phase::Prompt => self.ui_prompt(ui),
            Phase::Connecting => self.ui_connecting(ui),
            Phase::HostKey => self.ui_hostkey(ui),
            Phase::Running => self.ui_running(ui),
            Phase::Failed => self.ui_failed(ui),
        }

        if self.quit {
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }
}

impl GuiApp {
    fn ui_prompt(&mut self, ui: &mut egui::Ui) {
        let (needs_password, needs_passphrase) = auth_prompts(&self.spec.auth);
        let mut password = String::new();
        let mut passphrase = String::new();
        let mut error = None;
        if let State::Prompt {
            password: p,
            passphrase: pp,
            error: e,
        } = std::mem::replace(&mut self.state, State::Connecting)
        {
            password = p;
            passphrase = pp;
            error = e;
        }

        ui.heading("VortexSSH");
        ui.label(format!("Connecting to {}", self.label()));
        ui.add_space(8.0);

        let mut connect = false;
        if needs_password {
            ui.add(
                egui::TextEdit::singleline(&mut password)
                    .password(true)
                    .hint_text("password"),
            );
        }
        if needs_passphrase {
            ui.add(
                egui::TextEdit::singleline(&mut passphrase)
                    .password(true)
                    .hint_text("passphrase (blank if none)"),
            );
        }
        if let Some(e) = &error {
            ui.colored_label(Color32::from_rgb(240, 80, 80), e);
        }

        ui.horizontal(|ui| {
            if ui.button("Connect").clicked() {
                connect = true;
            }
            if ui.button("Cancel").clicked() {
                self.quit = true;
            }
        });

        if connect {
            self.start_connect(
                ui.ctx(),
                needs_password.then_some(password),
                needs_passphrase.then_some(passphrase).filter(|s| !s.is_empty()),
            );
        } else {
            self.state = State::Prompt {
                password,
                passphrase,
                error: None,
            };
        }
    }

    fn ui_connecting(&self, ui: &mut egui::Ui) {
        ui.centered_and_justified(|ui| {
            ui.spinner();
            ui.label(format!("Connecting to {}…", self.label()));
        });
    }

    fn ui_hostkey(&mut self, ui: &mut egui::Ui) {
        let (host, port, fingerprint) = match &self.state {
            State::HostKey {
                host,
                port,
                fingerprint,
                ..
            } => (host.clone(), *port, fingerprint.clone()),
            _ => return,
        };

        ui.heading("Unknown host key");
        ui.label(format!("The authenticity of host '{host}:{port}' can't be established."));
        ui.label(format!("Key fingerprint: {fingerprint}"));
        ui.add_space(8.0);

        let mut answer = None;
        ui.horizontal(|ui| {
            if ui.button("Accept").clicked() {
                answer = Some(true);
            }
            if ui.button("Reject").clicked() {
                answer = Some(false);
            }
        });

        if let Some(a) = answer {
            if let State::HostKey { reply, .. } = std::mem::replace(&mut self.state, State::Connecting) {
                let _ = reply.send(a);
            }
        }
    }

    fn ui_failed(&mut self, ui: &mut egui::Ui) {
        let msg = match &self.state {
            State::Failed(m) => m.clone(),
            _ => String::new(),
        };
        ui.heading("Connection failed");
        ui.colored_label(Color32::from_rgb(240, 80, 80), &msg);
        if ui.button("Back").clicked() {
            let (needs_password, needs_passphrase) = auth_prompts(&self.spec.auth);
            self.state = if needs_password || needs_passphrase {
                State::Prompt {
                    password: String::new(),
                    passphrase: String::new(),
                    error: Some(msg),
                }
            } else {
                // agent: restart immediately
                State::Connecting
            };
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
        let (cw, rh) = ui.ctx().fonts_mut(|f| (f.glyph_width(&font, 'M'), f.row_height(&font)));
        let cols = ((grid_rect.width() / cw).floor() as u32).max(1);
        let rows = ((grid_rect.height() / rh).floor() as u32).max(1);
        if cols != self.cols || rows != self.rows {
            self.cols = cols;
            self.rows = rows;
            self.term.resize(cols, rows);
            let _ = self.cmd_tx.send(Cmd::WindowChange { cols, rows });
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
        let _ = self.cmd_tx.send(Cmd::Data(bytes));
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
        let col = (((pos.x - self.grid_rect.min.x) / self.char_w).floor() as u32)
            .min(self.cols - 1) as u16;
        let row = (((pos.y - self.grid_rect.min.y) / self.row_h).floor() as u32)
            .min(self.rows - 1) as u16;
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
                painter.text(text_pos, Align2::LEFT_TOP, run.text.as_str(), font.clone(), run.fg);
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
                        [pos2(x0, y0 + self.row_h - 1.0), pos2(x0 + w, y0 + self.row_h - 1.0)],
                        Stroke::new(1.0, run.fg),
                    );
                }
                if run.strikethrough {
                    let my = y0 + self.row_h * 0.5;
                    painter.line_segment(
                        [pos2(x0, my), pos2(x0 + w, my)],
                        Stroke::new(1.0, run.fg),
                    );
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
            .unwrap_or_else(|| self.label());
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

/// Which secrets a given auth method needs the user to supply.
pub fn auth_prompts(auth: &AuthMethod) -> (bool, bool) {
    match auth {
        AuthMethod::Password | AuthMethod::KeyboardInteractive => (true, false),
        AuthMethod::PublicKey { .. } => (false, true),
        AuthMethod::Agent => (false, false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompts_for_password_methods() {
        assert_eq!(auth_prompts(&AuthMethod::Password), (true, false));
        assert_eq!(
            auth_prompts(&AuthMethod::KeyboardInteractive),
            (true, false)
        );
    }

    #[test]
    fn prompts_for_passphrase_only_for_keys() {
        let key = AuthMethod::PublicKey {
            key_path: "id_ed25519".into(),
        };
        assert_eq!(auth_prompts(&key), (false, true));
    }

    #[test]
    fn no_prompt_for_agent() {
        assert_eq!(auth_prompts(&AuthMethod::Agent), (false, false));
    }
}
