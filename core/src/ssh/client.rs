use russh::client::Msg;
use russh::keys::known_hosts::learn_known_hosts;
use russh::keys::{check_known_hosts, HashAlg, PublicKeyOrCertificate};
use russh::Channel;
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::error::{Error, Result};
use crate::prompt::Prompter;

use super::session::host_label;

/// Pluggable host key verification, checked once per connection before any
/// authentication happens.
pub trait HostKeyVerifier: Send + Sync {
    /// Returns `Ok(true)` to proceed with the connection, `Ok(false)` to
    /// abort. Returning `Err` (e.g. on a changed/mismatched key) always
    /// aborts and should be surfaced to the user as a security warning.
    fn verify(&self, host: &str, port: u16, key: &PublicKeyOrCertificate) -> Result<bool>;
}

/// Insecure: accepts any host key unconditionally. Only intended for
/// integration tests against a throwaway local sshd — never wire this up as
/// a default in the CLI/TUI/GUI.
pub struct AcceptAll;

impl HostKeyVerifier for AcceptAll {
    fn verify(&self, _host: &str, _port: u16, _key: &PublicKeyOrCertificate) -> Result<bool> {
        Ok(true)
    }
}

/// Trust-on-first-use verifier backed by the standard OpenSSH `known_hosts`
/// file. Unknown keys are confirmed through the prompter and then saved; a
/// *changed* key (potential MITM) is always rejected without asking.
pub struct KnownHosts {
    pub prompter: Arc<dyn Prompter>,
}

impl HostKeyVerifier for KnownHosts {
    fn verify(&self, host: &str, port: u16, key: &PublicKeyOrCertificate) -> Result<bool> {
        let PublicKeyOrCertificate::PublicKey { key: pubkey, .. } = key else {
            return Err(Error::HostKeyVerification {
                host: host_label(host, port),
                reason: "the server presented a host certificate, which is not supported".into(),
            });
        };

        match check_known_hosts(host, port, pubkey) {
            Ok(true) => Ok(true),
            Ok(false) => {
                let fingerprint = pubkey.fingerprint(HashAlg::Sha256).to_string();
                if self.prompter.confirm_host_key(host, port, &fingerprint) {
                    learn_known_hosts(host, port, pubkey)
                        .map_err(|e| Error::Other(format!("saving known_hosts entry: {e}")))?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Err(russh::keys::Error::KeyChanged { line }) => Err(Error::HostKeyVerification {
                host: host_label(host, port),
                reason: format!(
                    "the host key has CHANGED since it was saved in known_hosts (line {line}).\n\
                     Someone could be intercepting the connection, or the server was reinstalled.\n\
                     If you trust the new key, remove the old one with: ssh-keygen -R '{}'",
                    host_label(host, port)
                ),
            }),
            Err(e) => Err(Error::HostKeyVerification {
                host: host_label(host, port),
                reason: e.to_string(),
            }),
        }
    }
}

/// Messages pushed from server-initiated channels (e.g. remote forwarding)
/// up to session consumers. Extended in the tunnel module.
pub enum ServerEvent {
    ForwardedTcpIp {
        channel: Channel<Msg>,
        originator_addr: String,
        originator_port: u32,
        /// The server-side port the connection came *to* (identifies which
        /// remote forward was hit).
        forwarded_port: u32,
    },
}

pub struct ClientHandler {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) verifier: Arc<dyn HostKeyVerifier>,
    pub(crate) events: mpsc::UnboundedSender<ServerEvent>,
    /// Why the host key was rejected, so `connect` can report it instead of
    /// russh's generic error.
    pub(crate) rejection: Arc<std::sync::Mutex<Option<Error>>>,
}

impl russh::client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        // Verification may block on a user prompt, so keep it off the
        // async executor.
        let outcome = tokio::task::block_in_place(|| {
            self.verifier
                .verify(&self.host, self.port, server_public_key)
        });
        match outcome {
            Ok(ok) => Ok(ok),
            Err(e) => {
                tracing::debug!("host key check failed: {e}");
                *self.rejection.lock().unwrap_or_else(|p| p.into_inner()) = Some(e);
                Ok(false)
            }
        }
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        _connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        reply: russh::client::ChannelOpenHandle,
        _session: &mut russh::client::Session,
    ) -> std::result::Result<(), Self::Error> {
        reply.accept().await;
        let _ = self.events.send(ServerEvent::ForwardedTcpIp {
            channel,
            originator_addr: originator_address.to_string(),
            originator_port,
            forwarded_port: connected_port,
        });
        Ok(())
    }
}
