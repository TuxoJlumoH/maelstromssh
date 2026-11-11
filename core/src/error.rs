use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Ssh(#[from] russh::Error),

    #[error(transparent)]
    Sftp(#[from] russh_sftp::client::error::Error),

    #[error(transparent)]
    Key(#[from] russh::keys::ssh_key::Error),

    #[error(transparent)]
    RusshKey(#[from] russh::keys::Error),

    #[error(transparent)]
    AgentAuth(#[from] russh::AgentAuthError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Config(String),

    #[error("cannot connect to {addr}: {reason}")]
    Connect { addr: String, reason: String },

    #[error("host key verification failed for {host}: {reason}")]
    HostKeyVerification { host: String, reason: String },

    #[error("host key for {host} was not accepted")]
    HostKeyRejected { host: String },

    #[error("authentication failed for {user}@{host}{details}")]
    AuthFailed {
        user: String,
        host: String,
        /// What was tried and what the server accepts, e.g.
        /// " (tried password); the server accepts: publickey".
        details: String,
    },

    #[error("cancelled")]
    Cancelled,

    #[error("{0}")]
    Other(String),
}

/// Lets core errors flow out of a `russh::Signer` used during auth.
impl From<russh::SendError> for Error {
    fn from(_: russh::SendError) -> Self {
        Error::Other("the connection closed during authentication".into())
    }
}

impl Error {
    /// Returns a short, actionable troubleshooting hint for common connection
    /// and authentication failures, or `None` when the error message is
    /// already self-explanatory.
    pub fn hint(&self) -> Option<String> {
        match self {
            Error::AuthFailed {
                user,
                host,
                details,
            } => {
                if details.contains("the server accepts: publickey")
                    && !details.contains("password")
                {
                    Some(format!(
                        "This server only accepts SSH keys for '{user}'. Make sure your public key \
                         (~/.ssh/id_ed25519.pub) is in ~{user}/.ssh/authorized_keys on {host}, or \
                         select a specific private key file (-i)."
                    ))
                } else if details.contains("no ssh-agent keys or ~/.ssh/id_* keys to try") {
                    Some(
                        "Generate a keypair with `maelstromssh keygen` or choose password \
                         authentication."
                            .into(),
                    )
                } else {
                    Some(format!(
                        "Check that username '{user}' is right for {host}, or verify your \
                         password / SSH key."
                    ))
                }
            }
            Error::HostKeyVerification { host, reason } if reason.contains("CHANGED") => {
                Some(format!(
                    "If {host} was reinstalled and you trust the new fingerprint, forget the old \
                     key in Known hosts (web UI) or run: maelstromssh known-hosts remove '{host}'"
                ))
            }
            Error::Connect { addr, reason } if reason.contains("no response after") => {
                Some(format!(
                    "Check the IP/hostname and port for {addr}, or whether a firewall or VPN is \
                     blocking the connection."
                ))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_failed_publickey_only_gives_key_hint() {
        let err = Error::AuthFailed {
            user: "deploy".into(),
            host: "web-01".into(),
            details: " (tried ~/.ssh/id_ed25519); the server accepts: publickey".into(),
        };
        let hint = err.hint().unwrap();
        assert!(hint.contains("authorized_keys"), "{hint}");
        assert!(hint.contains("deploy"), "{hint}");
    }
}
