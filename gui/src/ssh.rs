//! Bridge between the async SSH session (background tokio task) and the
//! single-threaded GUI. The task owns the `Session`/`Channel` and exchanges
//! raw bytes and commands with the UI over unbounded channels; the UI owns
//! the core [`Terminal`] and feeds it the bytes it receives.

use std::path::PathBuf;
use std::sync::Arc;

use vortexssh_core::config::AuthMethod;
use vortexssh_core::ssh::{AuthCredentials, ChannelMsg, HostKeyVerifier, Session};

/// A command from the UI thread to the SSH task.
pub enum Cmd {
    /// Bytes to write to the shell's stdin.
    Data(Vec<u8>),
    /// PTY resize (`window_change`).
    WindowChange { cols: u32, rows: u32 },
}

/// An event from the SSH task to the UI thread.
pub enum Evt {
    /// The shell channel is open; terminal rendering can begin.
    Ready,
    /// Output from the shell (stdout/stderr merged).
    Data(Vec<u8>),
    /// The channel closed or errored.
    Closed(String),
}

/// The four channel ends connecting the UI and the SSH task.
pub struct Channels {
    pub cmd_tx: tokio::sync::mpsc::UnboundedSender<Cmd>,
    pub cmd_rx: tokio::sync::mpsc::UnboundedReceiver<Cmd>,
    pub evt_tx: tokio::sync::mpsc::UnboundedSender<Evt>,
    pub evt_rx: tokio::sync::mpsc::UnboundedReceiver<Evt>,
}

impl Channels {
    pub fn new() -> Self {
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
        let (evt_tx, evt_rx) = tokio::sync::mpsc::unbounded_channel();
        Self {
            cmd_tx,
            cmd_rx,
            evt_tx,
            evt_rx,
        }
    }
}

/// Connection parameters + secrets needed to open a session.
#[derive(Clone)]
pub struct ConnectSpec {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: AuthMethod,
    pub term_type: String,
}

/// Connects and authenticates, opens a shell, then drives it until it closes
/// or the command channel is dropped. `password`/`passphrase` are the secrets
/// the UI already collected. `notify` wakes the UI when output arrives.
pub async fn connect_and_run(
    spec: ConnectSpec,
    password: Option<String>,
    passphrase: Option<String>,
    verifier: Arc<dyn HostKeyVerifier>,
    cmd_rx: tokio::sync::mpsc::UnboundedReceiver<Cmd>,
    evt_tx: tokio::sync::mpsc::UnboundedSender<Evt>,
    notify: egui::Context,
) {
    let credentials = match &spec.auth {
        AuthMethod::Password | AuthMethod::KeyboardInteractive => {
            AuthCredentials::Password(password.unwrap_or_default())
        }
        AuthMethod::PublicKey { key_path, .. } => AuthCredentials::PublicKey {
            key_path: PathBuf::from(key_path),
            passphrase,
        },
        AuthMethod::Agent => AuthCredentials::Agent,
    };

    let session = match Session::connect(
        (spec.host.as_str(), spec.port),
        &spec.host,
        spec.port,
        &spec.user,
        credentials,
        verifier,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            let _ = evt_tx.send(Evt::Closed(format!("connecting: {e}")));
            notify.request_repaint();
            return;
        }
    };

    run_connected(session, cmd_rx, evt_tx, notify, &spec.term_type).await;
}

/// Drives an already-connected session's shell channel.
async fn run_connected(
    mut session: Session,
    mut cmd_rx: tokio::sync::mpsc::UnboundedReceiver<Cmd>,
    evt_tx: tokio::sync::mpsc::UnboundedSender<Evt>,
    notify: egui::Context,
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
