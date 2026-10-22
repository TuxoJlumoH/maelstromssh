use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("SSH error: {0}")]
    Ssh(#[from] russh::Error),

    #[error("SFTP error: {0}")]
    Sftp(#[from] russh_sftp::client::error::Error),

    #[error("key error: {0}")]
    Key(#[from] russh::keys::ssh_key::Error),

    #[error("key error: {0}")]
    RusshKey(#[from] russh::keys::Error),

    #[error("ssh-agent error: {0}")]
    AgentAuth(#[from] russh::AgentAuthError),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("config error: {0}")]
    Config(String),

    #[error("host key verification failed for {host}: {reason}")]
    HostKeyVerification { host: String, reason: String },

    #[error("host key for {host} was not accepted")]
    HostKeyRejected { host: String },

    #[error("authentication failed for user {user}")]
    AuthFailed { user: String },

    #[error("cancelled")]
    Cancelled,

    #[error("{0}")]
    Other(String),
}
