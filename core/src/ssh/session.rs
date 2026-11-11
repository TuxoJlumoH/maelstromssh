use std::sync::Arc;
use std::time::Duration;

use russh::client::{self, Handle, Msg};
use russh::Channel;
use tokio::sync::mpsc;

use crate::config::AuthMethod;
use crate::error::{Error, Result};
use crate::prompt::Prompter;
use crate::target::JumpHost;

use super::auth::{Authenticator, KeyFile};
use super::client::{ClientHandler, HostKeyVerifier, ServerEvent};

/// A connected, authenticated SSH session. Wraps a `russh::client::Handle`
/// so callers (CLI/TUI/GUI) never touch `russh` types directly.
pub struct Session {
    handle: Arc<Handle<ClientHandler>>,
    /// Jump-host sessions kept alive while this target session is open,
    /// ordered from outermost bastion to innermost hop.
    jump_handles: Vec<Arc<Handle<ClientHandler>>>,
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
        Self::connect_via(&[], host, port, user, auth, prompter, verifier).await
    }

    /// Connects to `host:port` through zero or more SSH jump hosts (`ProxyJump`
    /// / `-J`), tunneling each hop over a `direct-tcpip` channel on the
    /// previous hop.
    pub async fn connect_via(
        jumps: &[JumpHost],
        host: &str,
        port: u16,
        user: &str,
        auth: &AuthMethod,
        prompter: Arc<dyn Prompter>,
        verifier: Arc<dyn HostKeyVerifier>,
    ) -> Result<Self> {
        // Read key files first so a bad path fails before any network I/O.
        let mut jump_keys = Vec::with_capacity(jumps.len());
        for hop in jumps {
            jump_keys.push(KeyFile::for_method(&hop.auth)?);
        }
        let target_keys = KeyFile::for_method(auth)?;

        let mut jump_handles: Vec<Arc<Handle<ClientHandler>>> = Vec::with_capacity(jumps.len());
        for (hop, keys) in jumps.iter().zip(jump_keys) {
            let (handle, _rx) = match jump_handles.last() {
                None => {
                    let socket = crate::net::connect(&hop.host, hop.port, "sshd").await?;
                    Self::handshake_and_auth(
                        socket,
                        &hop.host,
                        hop.port,
                        &hop.user,
                        &hop.auth,
                        keys,
                        &prompter,
                        verifier.clone(),
                    )
                    .await?
                }
                Some(prev) => {
                    let channel = prev
                        .channel_open_direct_tcpip(&hop.host, hop.port as u32, "127.0.0.1", 0)
                        .await
                        .map_err(|e| Error::Connect {
                            addr: format!("{}:{}", hop.host, hop.port),
                            reason: format!("via jump host: {e}"),
                        })?;
                    Self::handshake_and_auth(
                        channel.into_stream(),
                        &hop.host,
                        hop.port,
                        &hop.user,
                        &hop.auth,
                        keys,
                        &prompter,
                        verifier.clone(),
                    )
                    .await?
                }
            };
            jump_handles.push(handle);
        }

        let (handle, rx) = match jump_handles.last() {
            None => {
                let socket = crate::net::connect(host, port, "sshd").await?;
                Self::handshake_and_auth(
                    socket,
                    host,
                    port,
                    user,
                    auth,
                    target_keys,
                    &prompter,
                    verifier,
                )
                .await?
            }
            Some(prev) => {
                let channel = prev
                    .channel_open_direct_tcpip(host, port as u32, "127.0.0.1", 0)
                    .await
                    .map_err(|e| Error::Connect {
                        addr: format!("{host}:{port}"),
                        reason: format!("via jump host: {e}"),
                    })?;
                Self::handshake_and_auth(
                    channel.into_stream(),
                    host,
                    port,
                    user,
                    auth,
                    target_keys,
                    &prompter,
                    verifier,
                )
                .await?
            }
        };

        Ok(Self {
            handle,
            jump_handles,
            events: Some(rx),
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn handshake_and_auth<S>(
        stream: S,
        host: &str,
        port: u16,
        user: &str,
        auth: &AuthMethod,
        keys: Vec<KeyFile>,
        prompter: &Arc<dyn Prompter>,
        verifier: Arc<dyn HostKeyVerifier>,
    ) -> Result<(
        Arc<Handle<ClientHandler>>,
        mpsc::UnboundedReceiver<ServerEvent>,
    )>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let config = Arc::new(client::Config {
            keepalive_interval: Some(KEEPALIVE_INTERVAL),
            keepalive_max: KEEPALIVE_MAX,
            ..Default::default()
        });
        let (tx, rx) = mpsc::unbounded_channel();
        let rejection = Arc::new(std::sync::Mutex::new(None));
        let handler = ClientHandler {
            host: host.to_string(),
            port,
            verifier,
            events: tx,
            rejection: rejection.clone(),
        };

        let mut handle = match client::connect_stream(config, stream, handler).await {
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

        let outcome = Authenticator::new(&mut handle, user, host, prompter)
            .run(auth, keys)
            .await?;
        if let Err(details) = outcome {
            return Err(Error::AuthFailed {
                user: user.to_string(),
                host: host_label(host, port),
                details,
            });
        }

        Ok((Arc::new(handle), rx))
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
        let res = self
            .handle
            .disconnect(russh::Disconnect::ByApplication, "", "English")
            .await
            .map_err(Error::Ssh);
        for jh in self.jump_handles.iter().rev() {
            let _ = jh
                .disconnect(russh::Disconnect::ByApplication, "", "English")
                .await;
        }
        res
    }

    /// Whether the connection has gone away (closed by either side).
    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
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

/// A keepalive goes out after this long without hearing from the server...
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
/// ...and the connection counts as lost after this many go unanswered, so a
/// dead network link is noticed in about 2 minutes instead of never.
const KEEPALIVE_MAX: usize = 3;

/// `host`, or `[host]:port` for non-standard ports (as OpenSSH writes it).
pub(crate) fn host_label(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}
