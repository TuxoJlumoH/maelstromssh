use std::io::ErrorKind;
use std::sync::Arc;
use std::time::Duration;

use russh::client::{self, Handle, Msg};
use russh::Channel;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::config::AuthMethod;
use crate::error::{Error, Result};
use crate::prompt::Prompter;

use super::auth::{Authenticator, KeyFile};
use super::client::{ClientHandler, HostKeyVerifier, ServerEvent};

/// A connected, authenticated SSH session. Wraps a `russh::client::Handle`
/// so callers (CLI/TUI/GUI) never touch `russh` types directly.
pub struct Session {
    handle: Arc<Handle<ClientHandler>>,
    /// Server-initiated channel events (remote forwarding). Taken by the
    /// tunnel module when remote forwards are requested.
    events: Option<mpsc::UnboundedReceiver<ServerEvent>>,
}

/// A shareable channel-opening handle, handed to long-lived background tasks
/// (port forwarding) so they can open channels without borrowing the session.
#[derive(Clone)]
pub struct ClientHandle(Arc<Handle<ClientHandler>>);

impl ClientHandle {
    /// Opens a direct-tcpip channel to `host:port` (local/SOCKS forwarding).
    pub async fn open_direct_tcpip(
        &self,
        host: &str,
        port: u16,
        origin_addr: &str,
        origin_port: u16,
    ) -> Result<Channel<Msg>> {
        self.0
            .channel_open_direct_tcpip(host, port as u32, origin_addr, origin_port as u32)
            .await
            .map_err(Error::Ssh)
    }

    /// Asks the server to listen on `addr:port` for remote forwarding.
    /// Returns the actual bound port (meaningful when `port == 0`).
    pub async fn tcpip_forward(&self, addr: &str, port: u16) -> Result<u16> {
        self.0
            .tcpip_forward(addr, port as u32)
            .await
            .map(|p| p as u16)
            .map_err(Error::Ssh)
    }

    /// Cancels a previously requested remote forward.
    pub async fn cancel_tcpip_forward(&self, addr: &str, port: u16) -> Result<()> {
        self.0
            .cancel_tcpip_forward(addr, port as u32)
            .await
            .map_err(Error::Ssh)
    }
}

impl Session {
    /// Connects to `host:port` and authenticates as `user`. Secrets and
    /// keyboard-interactive challenges are requested from `prompter` only
    /// when the server actually needs them.
    pub async fn connect(
        host: &str,
        port: u16,
        user: &str,
        auth: &AuthMethod,
        prompter: Arc<dyn Prompter>,
        verifier: Arc<dyn HostKeyVerifier>,
    ) -> Result<Self> {
        let config = Arc::new(client::Config::default());
        let (tx, rx) = mpsc::unbounded_channel();
        let rejection = Arc::new(std::sync::Mutex::new(None));
        let handler = ClientHandler {
            host: host.to_string(),
            port,
            verifier,
            events: tx,
            rejection: rejection.clone(),
        };

        // Read key files first so a bad path fails before any network I/O.
        let keys = KeyFile::for_method(auth)?;
        let socket = connect_tcp(host, port).await?;
        let mut handle = match client::connect_stream(config, socket, handler).await {
            Ok(h) => h,
            Err(e) => {
                let reason = rejection.lock().unwrap_or_else(|p| p.into_inner()).take();
                return Err(match (reason, e) {
                    (Some(reason), _) => reason,
                    (None, russh::Error::UnknownKey) => Error::HostKeyRejected {
                        host: host_label(host, port),
                    },
                    (None, e) => Error::Ssh(e),
                });
            }
        };

        let outcome = Authenticator::new(&mut handle, user, host, &prompter)
            .run(auth, keys)
            .await?;
        if let Err(details) = outcome {
            return Err(Error::AuthFailed {
                user: user.to_string(),
                host: host_label(host, port),
                details,
            });
        }

        Ok(Self {
            handle: Arc::new(handle),
            events: Some(rx),
        })
    }

    /// Opens an interactive shell channel with a PTY, matching the given
    /// terminal type and size. Returns the raw channel; driving stdin/stdout
    /// I/O and resize events is the caller's responsibility (CLI/TUI layer).
    pub async fn open_shell(&self, term_type: &str, cols: u32, rows: u32) -> Result<Channel<Msg>> {
        let channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(Error::Ssh)?;
        channel
            .request_pty(false, term_type, cols, rows, 0, 0, &[])
            .await
            .map_err(Error::Ssh)?;
        channel.request_shell(false).await.map_err(Error::Ssh)?;
        Ok(channel)
    }

    /// Opens a channel and execs a single command (no PTY) — used for
    /// one-shot, non-interactive operations.
    pub async fn open_exec(&self, command: &str) -> Result<Channel<Msg>> {
        let channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(Error::Ssh)?;
        channel.exec(true, command).await.map_err(Error::Ssh)?;
        Ok(channel)
    }

    /// Opens a channel and requests the given SSH subsystem (e.g. "sftp").
    pub async fn open_subsystem(&self, name: &str) -> Result<Channel<Msg>> {
        let channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(Error::Ssh)?;
        channel
            .request_subsystem(true, name)
            .await
            .map_err(Error::Ssh)?;
        Ok(channel)
    }

    pub async fn disconnect(&self) -> Result<()> {
        self.handle
            .disconnect(russh::Disconnect::ByApplication, "", "English")
            .await
            .map_err(Error::Ssh)?;
        Ok(())
    }

    /// Clones the channel-opening handle, for long-lived background tasks
    /// (port forwarding) that outlive the borrow of the session.
    pub fn handle(&self) -> ClientHandle {
        ClientHandle(self.handle.clone())
    }

    /// Takes the server-event stream (remote forwarding). Returns `None` if
    /// it has already been taken.
    pub fn take_events(&mut self) -> Option<mpsc::UnboundedReceiver<ServerEvent>> {
        self.events.take()
    }
}

/// How long to wait for the TCP connection before giving up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// Opens the TCP connection, turning the usual failures into messages that
/// say what went wrong.
async fn connect_tcp(host: &str, port: u16) -> Result<TcpStream> {
    let addr = host_label(host, port);
    let fail = |reason: String| Error::Connect {
        addr: addr.clone(),
        reason,
    };
    let socket = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port))).await
    {
        Err(_) => {
            return Err(fail(format!(
                "no response after {}s",
                CONNECT_TIMEOUT.as_secs()
            )))
        }
        Ok(Err(e)) => {
            let reason = match e.kind() {
                ErrorKind::ConnectionRefused => {
                    "connection refused (is sshd running on that port?)".to_string()
                }
                ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable => {
                    "host is unreachable".to_string()
                }
                ErrorKind::TimedOut => "connection timed out".to_string(),
                _ if e.to_string().contains("lookup address") => {
                    format!("unknown host '{host}'")
                }
                _ => e.to_string(),
            };
            return Err(fail(reason));
        }
        Ok(Ok(s)) => s,
    };
    socket.set_nodelay(true).ok();
    Ok(socket)
}

/// `host`, or `[host]:port` for non-standard ports (as OpenSSH writes it).
pub(crate) fn host_label(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}
