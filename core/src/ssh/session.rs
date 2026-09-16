use std::path::PathBuf;
use std::sync::Arc;

use russh::client::{self, Handle, Msg};
use russh::keys::PrivateKeyWithHashAlg;
use russh::Channel;
use tokio::net::ToSocketAddrs;
use tokio::sync::mpsc;

use crate::error::{Error, Result};
use crate::keys;

use super::client::{ClientHandler, HostKeyVerifier, ServerEvent};

/// How to authenticate an SSH session. Mirrors `config::AuthMethod` but
/// carries resolved secrets (e.g. an in-memory decrypted key) rather than
/// just a profile reference.
pub enum AuthCredentials {
    Password(String),
    PublicKey {
        key_path: PathBuf,
        passphrase: Option<String>,
    },
    /// Delegate to a running ssh-agent (via `$SSH_AUTH_SOCK`). Each identity
    /// the agent exposes is tried in order.
    Agent,
}

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
    /// Connects and authenticates in one step. `host_label` and `port` are
    /// used for host key verification (known_hosts lookups) and should
    /// match what the user configured, even if `addr` resolves elsewhere.
    pub async fn connect<A: ToSocketAddrs>(
        addr: A,
        host_label: &str,
        port: u16,
        user: &str,
        auth: AuthCredentials,
        verifier: Arc<dyn HostKeyVerifier>,
    ) -> Result<Self> {
        let config = Arc::new(client::Config::default());
        let (tx, rx) = mpsc::unbounded_channel();
        let handler = ClientHandler {
            host: host_label.to_string(),
            port,
            verifier,
            events: tx,
        };

        let mut handle = client::connect(config, addr, handler)
            .await
            .map_err(Error::Ssh)?;

        let authenticated = match auth {
            AuthCredentials::Password(password) => handle
                .authenticate_password(user, password)
                .await
                .map_err(Error::Ssh)?
                .success(),
            AuthCredentials::PublicKey {
                key_path,
                passphrase,
            } => {
                let key = keys::load_openssh(&key_path, passphrase.as_deref())?;
                let hash_alg = handle
                    .best_supported_rsa_hash()
                    .await
                    .map_err(Error::Ssh)?
                    .flatten();
                handle
                    .authenticate_publickey(
                        user,
                        PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg),
                    )
                    .await
                    .map_err(Error::Ssh)?
                    .success()
            }
            AuthCredentials::Agent => authenticate_agent(&mut handle, user).await?,
        };

        if !authenticated {
            return Err(Error::AuthFailed {
                user: user.to_string(),
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
    pub async fn open_shell(
        &mut self,
        term_type: &str,
        cols: u32,
        rows: u32,
    ) -> Result<Channel<Msg>> {
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
    pub async fn open_exec(&mut self, command: &str) -> Result<Channel<Msg>> {
        let channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(Error::Ssh)?;
        channel.exec(true, command).await.map_err(Error::Ssh)?;
        Ok(channel)
    }

    /// Opens a channel and requests the given SSH subsystem (e.g. "sftp").
    pub async fn open_subsystem(&mut self, name: &str) -> Result<Channel<Msg>> {
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

    pub async fn disconnect(&mut self) -> Result<()> {
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

/// Authenticate by trying each identity exposed by the local ssh-agent.
#[cfg(any(unix, windows))]
async fn authenticate_agent(handle: &mut Handle<ClientHandler>, user: &str) -> Result<bool> {
    let rsa_hash = handle
        .best_supported_rsa_hash()
        .await
        .map_err(Error::Ssh)?
        .flatten();

    let mut agent = keys::agent::connect_env().await?;
    let identities = keys::agent::list_identities(&mut agent).await?;

    if identities.is_empty() {
        tracing::debug!("ssh-agent reported no identities");
        return Ok(false);
    }

    for identity in &identities {
        let public_key = match identity.public_key() {
            std::borrow::Cow::Borrowed(key) => key.clone(),
            std::borrow::Cow::Owned(key) => key,
        };
        // RSA requires a hash alg to signal rsa-sha2-256/512; other key
        // types ignore this parameter.
        let hash_alg = if public_key.algorithm().is_rsa() {
            rsa_hash
        } else {
            None
        };
        tracing::debug!("trying agent identity: {}", identity.comment());
        let result = handle
            .authenticate_publickey_with(user, public_key, hash_alg, &mut agent)
            .await
            .map_err(Error::AgentAuth)?;
        if result.success() {
            return Ok(true);
        }
    }

    Ok(false)
}

#[cfg(not(any(unix, windows)))]
async fn authenticate_agent(_handle: &mut Handle<ClientHandler>, _user: &str) -> Result<bool> {
    Err(Error::Other(
        "ssh-agent is not supported on this platform".into(),
    ))
}
