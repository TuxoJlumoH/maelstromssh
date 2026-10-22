use std::path::Path;
use std::sync::Arc;

use russh::client::{self, Handle, KeyboardInteractiveAuthResponse, Msg};
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg};
use russh::Channel;
use tokio::sync::mpsc;

use crate::config::AuthMethod;
use crate::error::{Error, Result};
use crate::keys;
use crate::prompt::{KiPrompt, Prompter};

use super::client::{ClientHandler, HostKeyVerifier, ServerEvent};

/// How many times to re-ask for a mistyped password or passphrase.
const SECRET_ATTEMPTS: usize = 3;

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

        let mut handle = match client::connect(config, (host, port), handler).await {
            Ok(h) => h,
            Err(e) => {
                let reason = rejection.lock().unwrap_or_else(|p| p.into_inner()).take();
                return Err(match (reason, e) {
                    (Some(reason), _) => reason,
                    (None, russh::Error::UnknownKey) => Error::HostKeyRejected {
                        host: host.to_string(),
                    },
                    (None, e) => Error::Ssh(e),
                });
            }
        };

        let authenticated = match auth {
            AuthMethod::Password => {
                authenticate_password(&mut handle, user, host, &prompter).await?
            }
            AuthMethod::PublicKey { key_path } => {
                let key = load_key(Path::new(key_path), &prompter).await?;
                authenticate_key(&mut handle, user, key).await?
            }
            AuthMethod::Agent => authenticate_agent(&mut handle, user).await?,
            AuthMethod::KeyboardInteractive => {
                authenticate_keyboard_interactive(&mut handle, user, &prompter).await?
            }
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

/// Runs a (possibly blocking) prompt without stalling the async executor.
async fn ask<T, F>(prompter: &Arc<dyn Prompter>, f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&dyn Prompter) -> Option<T> + Send + 'static,
{
    let prompter = prompter.clone();
    tokio::task::spawn_blocking(move || f(prompter.as_ref()))
        .await
        .map_err(|e| Error::Other(format!("prompt task failed: {e}")))?
        .ok_or(Error::Cancelled)
}

async fn authenticate_password(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    host: &str,
    prompter: &Arc<dyn Prompter>,
) -> Result<bool> {
    let label = format!("{user}@{host}'s password: ");
    for _ in 0..SECRET_ATTEMPTS {
        let label = label.clone();
        let password = ask(prompter, move |p| p.secret(&label)).await?;
        if handle
            .authenticate_password(user, password)
            .await
            .map_err(Error::Ssh)?
            .success()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Loads a private key, asking for its passphrase only if it is encrypted.
async fn load_key(path: &Path, prompter: &Arc<dyn Prompter>) -> Result<PrivateKey> {
    match keys::load_openssh(path, None) {
        Err(Error::RusshKey(russh::keys::Error::KeyIsEncrypted)) => {}
        other => {
            return other.map_err(|e| Error::Config(format!("loading key {}: {e}", path.display())))
        }
    }
    let label = format!("Passphrase for {}: ", path.display());
    for _ in 0..SECRET_ATTEMPTS {
        let label = label.clone();
        let passphrase = ask(prompter, move |p| p.secret(&label)).await?;
        if let Ok(key) = keys::load_openssh(path, Some(&passphrase)) {
            return Ok(key);
        }
    }
    Err(Error::Config(format!(
        "wrong passphrase for {}",
        path.display()
    )))
}

async fn authenticate_key(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    key: PrivateKey,
) -> Result<bool> {
    let hash_alg = handle
        .best_supported_rsa_hash()
        .await
        .map_err(Error::Ssh)?
        .flatten();
    Ok(handle
        .authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg))
        .await
        .map_err(Error::Ssh)?
        .success())
}

/// Runs a keyboard-interactive exchange: the server may send any number of
/// challenge rounds (e.g. password, then an OTP code) before deciding.
async fn authenticate_keyboard_interactive(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    prompter: &Arc<dyn Prompter>,
) -> Result<bool> {
    let mut response = handle
        .authenticate_keyboard_interactive_start(user, None)
        .await
        .map_err(Error::Ssh)?;
    loop {
        match response {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest {
                name,
                instructions,
                prompts,
            } => {
                let answers = if prompts.is_empty() {
                    Vec::new()
                } else {
                    let prompts: Vec<KiPrompt> = prompts
                        .into_iter()
                        .map(|p| KiPrompt {
                            text: p.prompt,
                            echo: p.echo,
                        })
                        .collect();
                    ask(prompter, move |p| {
                        p.keyboard_interactive(&name, &instructions, &prompts)
                    })
                    .await?
                };
                response = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await
                    .map_err(Error::Ssh)?;
            }
        }
    }
}

/// Authenticate by trying each identity exposed by the local ssh-agent.
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
        let public_key = identity.public_key().into_owned();
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
