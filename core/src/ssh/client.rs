use russh::client::Msg;
use russh::keys::known_hosts::learn_known_hosts;
use russh::keys::{check_known_hosts, HashAlg, PublicKeyOrCertificate};
use russh::Channel;
use tokio::sync::mpsc;

use crate::error::{Error, Result};

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

/// Interactive confirmation callback: `(host, port, sha256_fingerprint) -> accept?`.
pub type HostKeyPrompt = Box<dyn Fn(&str, u16, &str) -> bool + Send + Sync>;

/// Trust-on-first-use verifier backed by the standard OpenSSH `known_hosts`
/// file. Unknown keys are handed to `prompt` (host, port, SHA256
/// fingerprint) for interactive confirmation; accepted keys are persisted.
/// A *changed* key (potential MITM) is always rejected without prompting.
pub struct KnownHosts {
    pub prompt: HostKeyPrompt,
}

impl HostKeyVerifier for KnownHosts {
    fn verify(&self, host: &str, port: u16, key: &PublicKeyOrCertificate) -> Result<bool> {
        let PublicKeyOrCertificate::PublicKey { key: pubkey, .. } = key else {
            // OpenSSH certificate-based host auth isn't handled yet.
            return Ok(false);
        };

        match check_known_hosts(host, port, pubkey) {
            Ok(true) => Ok(true),
            Ok(false) => {
                let fingerprint = pubkey.fingerprint(HashAlg::Sha256).to_string();
                if (self.prompt)(host, port, &fingerprint) {
                    learn_known_hosts(host, port, pubkey)
                        .map_err(|e| Error::Other(format!("saving known_hosts entry: {e}")))?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Err(e) => Err(Error::HostKeyVerification {
                host: host.to_string(),
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
    pub(crate) verifier: std::sync::Arc<dyn HostKeyVerifier>,
    pub(crate) events: mpsc::UnboundedSender<ServerEvent>,
}

impl russh::client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        match self
            .verifier
            .verify(&self.host, self.port, server_public_key)
        {
            Ok(ok) => Ok(ok),
            Err(e) => {
                tracing::error!("host key verification failed: {e}");
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
