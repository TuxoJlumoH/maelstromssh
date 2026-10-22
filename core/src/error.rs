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
