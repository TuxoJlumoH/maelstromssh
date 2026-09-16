//! The TUI event loop: connects a core [`Terminal`] to a live SSH shell
//! channel, forwarding keys/mouse/resize to the host and host output to the
//! renderer, throttled to a steady redraw cadence.

use std::io::Write;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{Event, KeyEventKind, MouseButton, MouseEventKind};
use vortexssh_core::ssh::{Channel, ChannelMsg, Msg};
use vortexssh_core::term::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{self, EventStream};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::Terminal as RatuiTerminal;
use tokio_stream::StreamExt;

use crate::input::{encode_key, encode_sgr_mouse, scroll_action, ScrollAction};
use crate::render::{GridView, StatusBar};

/// Connection label shown in the status bar.
pub struct Endpoint {
    pub user: String,
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    fn label(&self) -> String {
        format!("{}@{}:{}", self.user, self.host, self.port)
    }
}

/// Runs the interactive session. Returns when the remote closes the channel,
/// the user quits (Ctrl+]), or an error occurs. Always restores the terminal.
pub async fn run(mut channel: Channel<Msg>, mut term: Terminal, endpoint: Endpoint) -> Result<()> {
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, event::EnableMouseCapture)?;
    enable_raw_mode()?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = RatuiTerminal::new(backend)?;
    terminal.hide_cursor()?;

    let outcome = event_loop(&mut terminal, &mut term, &mut channel, &endpoint).await;

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
    channel: &mut Channel<Msg>,
    endpoint: &Endpoint,
) -> Result<()> {
    let mut events = EventStream::new();
    let mut redraw = tokio::time::interval(Duration::from_millis(33));
    redraw.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_gen = term.generation().wrapping_sub(1);
    let mut connected = true;
    let mut quit = false;

    loop {
        tokio::select! {
            _ = redraw.tick() => {
                let gen = term.generation();
                if gen != last_gen || !connected {
                    last_gen = gen;
                    draw_frame(terminal, term, endpoint, connected)?;
                }
                if !connected {
                    // Let the final frame render, then exit.
                    break;
                }
            }
            ev = events.next() => {
                match ev {
                    Some(Ok(Event::Key(k))) if k.kind != KeyEventKind::Release => {
                        if k.code == crossterm::event::KeyCode::Char(']')
                            && k.modifiers.contains(crossterm::event::KeyModifiers::CONTROL)
                        {
                            quit = true;
                        } else if let Some(action) = scroll_action(&k) {
                            apply_scroll(term, action);
                        } else if let Some(bytes) = encode_key(
                            &k,
                            term.application_cursor_keys(),
                            term.application_keypad(),
                        ) {
                            channel.data(&bytes[..]).await.ok();
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
                        channel.data(&out[..]).await.ok();
                    }
                    Some(Ok(Event::Mouse(m))) => handle_mouse(term, channel, m).await,
                    Some(Ok(Event::Resize(w, h))) => {
                        let rows = h.saturating_sub(1).max(1);
                        term.resize(w as u32, rows as u32);
                        channel.window_change(w as u32, rows as u32, 0, 0).await.ok();
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => {}
                }
            }
            msg = channel.wait() => {
                match msg {
                    Some(ChannelMsg::Data { data }) => {
                        term.feed(&data);
                        send_responses(term, channel).await;
                    }
                    Some(ChannelMsg::ExtendedData { data, .. }) => {
                        term.feed(&data);
                        send_responses(term, channel).await;
                    }
                    Some(ChannelMsg::ExitStatus { .. }) | Some(ChannelMsg::Close) | None => {
                        connected = false;
                    }
                    _ => {}
                }
            }
        }

        if quit || !connected {
            if !connected && quit {
                // Already exited above; nothing extra.
            }
            break;
        }
    }

    if !connected {
        // One last draw so the "closed" state is visible before teardown.
        let _ = draw_frame(terminal, term, endpoint, false);
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

async fn handle_mouse(
    term: &mut Terminal,
    channel: &mut Channel<Msg>,
    m: crossterm::event::MouseEvent,
) {
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
        channel.data(&bytes[..]).await.ok();
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

async fn send_responses(term: &mut Terminal, channel: &mut Channel<Msg>) {
    let resp = term.take_responses();
    if !resp.is_empty() {
        channel.data(&resp[..]).await.ok();
    }
}

fn draw_frame(
    terminal: &mut RatuiTerminal<CrosstermBackend<std::io::Stdout>>,
    term: &Terminal,
    endpoint: &Endpoint,
    connected: bool,
) -> Result<()> {
    let label = term.title().map(str::to_string).unwrap_or_else(|| endpoint.label());
    let offset = term.viewport_offset();
    let right = if !connected {
        "closed — press any key to exit".to_string()
    } else if offset > 0 {
        format!("{} lines up · Ctrl-] quit", offset)
    } else {
        "Ctrl-] quit".to_string()
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
