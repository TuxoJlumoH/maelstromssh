//! The TUI event loop: connects a core [`Terminal`] to a live SSH shell
//! channel, serial port, or Telnet/raw TCP stream, forwarding keys/mouse/resize
//! to the remote side and remote output to the renderer, throttled to a steady
//! redraw cadence.

use std::io::Write;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers, MouseButton, MouseEventKind};
use maelstromssh_core::serial;
use maelstromssh_core::session_log::SessionLog;
use maelstromssh_core::ssh::{Channel, ChannelMsg, Msg};
use maelstromssh_core::tcp::{Filter, TcpLine};
use maelstromssh_core::term::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{self, EventStream};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::Terminal as RatuiTerminal;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_stream::StreamExt;

use crate::input::{encode_key, encode_sgr_mouse, scroll_action, ScrollAction};
use crate::render::{GridView, StatusBar};

/// The underlying byte transport driven by the TUI event loop.
pub enum Backend {
    Ssh(Channel<Msg>),
    Serial(serial::Line),
    Tcp(TcpLine),
}

impl Backend {
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

    async fn send_bytes(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        match self {
            Backend::Ssh(ch) => {
                ch.data(bytes).await.ok();
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
            Backend::Ssh(ch) => {
                ch.window_change(cols as u32, rows as u32, 0, 0).await.ok();
            }
            Backend::Serial(_) => {}
            Backend::Tcp(line) => {
                if let Some(raw) = line.filter.resize(cols, rows) {
                    if line.writer.write_all(&raw).await.is_ok() {
                        line.writer.flush().await.ok();
                    }
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
                if let Some(brk) = line.filter.brk() {
                    if line.writer.write_all(&brk).await.is_ok() {
                        line.writer.flush().await.ok();
                    }
                }
            }
        }
    }

    /// Reads the next chunk of terminal output from the backend, returning
    /// `None` when the remote side closes the connection.
    async fn recv_output(&mut self, buf: &mut [u8]) -> Option<Vec<u8>> {
        match self {
            Backend::Ssh(ch) => loop {
                match ch.wait().await {
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
    let mut connected = true;
    let mut quit = false;
    let mut read_buf = [0u8; 16 * 1024];
    let can_break = backend.supports_break();
    let logging = log.is_some();

    loop {
        tokio::select! {
            _ = redraw.tick() => {
                let gen = term.generation();
                if gen != last_gen {
                    last_gen = gen;
                    draw_frame(terminal, term, endpoint, connected, can_break, logging)?;
                }
            }
            ev = events.next() => {
                match ev {
                    Some(Ok(Event::Key(k))) if k.kind != KeyEventKind::Release => {
                        if k.code == KeyCode::Char(']')
                            && k.modifiers.contains(KeyModifiers::CONTROL)
                        {
                            quit = true;
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
                    Some(Ok(Event::Paste(text))) => {
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
                    Some(Ok(Event::Mouse(m))) => handle_mouse(term, backend, m).await,
                    Some(Ok(Event::Resize(w, h))) => {
                        let rows = h.saturating_sub(1).max(1);
                        term.resize(w as u32, rows as u32);
                        backend.send_resize(w, rows).await;
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
        // Keep the final screen up until the user has seen it.
        draw_frame(terminal, term, endpoint, false, can_break, logging)?;
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

fn draw_frame(
    terminal: &mut RatuiTerminal<CrosstermBackend<std::io::Stdout>>,
    term: &Terminal,
    endpoint: &str,
    connected: bool,
    can_break: bool,
    logging: bool,
) -> Result<()> {
    let label = term
        .title()
        .map(str::to_string)
        .unwrap_or_else(|| endpoint.to_string());
    let offset = term.viewport_offset();
    let right = if !connected {
        "closed — press any key to exit".to_string()
    } else {
        let mut parts = Vec::new();
        if offset > 0 {
            parts.push(format!("{offset} lines up"));
        }
        if logging {
            parts.push("logging".to_string());
        }
        if can_break {
            parts.push("F12 break".to_string());
        }
        parts.push("Ctrl-] quit".to_string());
        parts.join(" · ")
    };

    terminal.draw(|f| {
        let area = f.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(1)])
            .split(area);
        f.render_widget(
            GridView {
                term,
                show_cursor: connected && term.cursor_visible(),
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
