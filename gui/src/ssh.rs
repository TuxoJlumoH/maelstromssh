//! Bridge between the async SSH session (background tokio task) and the
//! single-threaded GUI. The task owns the `Session`/`Channel` and exchanges
//! raw bytes and commands with the UI over unbounded channels; the UI owns
//! the core [`Terminal`] and feeds it the bytes it receives.
//!
//! [`Terminal`]: maelstromssh_core::term::Terminal

use std::sync::{mpsc as std_mpsc, Arc};

use maelstromssh_core::prompt::{KiPrompt, Prompter};
use maelstromssh_core::ssh::{ChannelMsg, KnownHosts, Session};
use maelstromssh_core::target::Target;
use tokio::sync::mpsc;

/// A command from the UI thread to the SSH task.
pub enum Cmd {
    /// Bytes to write to the shell's stdin.
    Data(Vec<u8>),
    /// PTY resize (`window_change`).
    WindowChange { cols: u32, rows: u32 },
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
/// a shell, then drives it until it closes or the UI drops its sender.
pub async fn connect_and_run(
    target: Target,
    term_type: String,
    cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    evt_tx: mpsc::UnboundedSender<Evt>,
    notify: egui::Context,
) {
    let prompter = Arc::new(GuiPrompter {
        evt_tx: evt_tx.clone(),
        notify: notify.clone(),
    });
    let result = Session::connect(
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
            let _ = evt_tx.send(Evt::Closed(e.to_string()));
            notify.request_repaint();
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
                    None => break, // UI dropped the sender: shut down
                }
            }
        }
    }

    let _ = session.disconnect().await;
}
