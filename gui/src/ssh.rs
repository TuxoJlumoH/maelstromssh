//! Bridge between the async session (background tokio task for SSH, serial,
//! Telnet or raw TCP) and the single-threaded GUI. The task owns the
//! connection and exchanges raw bytes and commands with the UI over unbounded
//! channels; the UI owns the core [`Terminal`] and feeds it the bytes it
//! receives.
//!
//! [`Terminal`]: maelstromssh_core::term::Terminal

use std::sync::{mpsc as std_mpsc, Arc};

use maelstromssh_core::config::Protocol;
use maelstromssh_core::prompt::{KiPrompt, Prompter};
use maelstromssh_core::serial;
use maelstromssh_core::ssh::{ChannelMsg, KnownHosts, Session};
use maelstromssh_core::target::Target;
use maelstromssh_core::tcp::TcpLine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

/// A command from the UI thread to the session task.
pub enum Cmd {
    /// Bytes to write to the remote side.
    Data(Vec<u8>),
    /// PTY resize (`window_change` or Telnet NAWS).
    WindowChange { cols: u32, rows: u32 },
    /// Send a serial or Telnet break signal.
    Break,
}

/// An event from the SSH task to the UI thread.
pub enum Evt {
    /// The connect task needs an answer from the user.
    Ask(Question),
    /// The shell channel is open; terminal rendering can begin.
    Ready,
    /// Output from the shell (stdout/stderr merged).
    Data(Vec<u8>),
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
                Ok(session) => run_connected(session, cmd_rx, &evt_tx, &notify, &term_type).await,
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

/// Drives an already-connected session's shell channel.
async fn run_connected(
    session: Session,
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
    let _ = evt_tx.send(Evt::Ready);
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
                    None => break, // UI dropped the sender: shut down
                }
            }
        }
    }

    let _ = session.disconnect().await;
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
                Some(Cmd::WindowChange { .. }) => {}
                Some(Cmd::Break) => {
                    let brk = breaker.clone();
                    let _ = tokio::task::spawn_blocking(move || brk.send()).await;
                }
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
                };
                if let Some(bytes) = out {
                    if writer.write_all(&bytes).await.is_err() || writer.flush().await.is_err() {
                        let _ = evt_tx.send(Evt::Closed("writing socket failed".into()));
                        notify.request_repaint();
                        break;
                    }
                }
            }
        }
    }
}
