//! ssh-agent client support: connecting to a running agent and listing its
//! identities. The actual signing happens during authentication in
//! `ssh::Session::connect` (russh's `AgentClient` implements `auth::Signer`).
//!
//! Unix uses `$SSH_AUTH_SOCK`; Windows uses the OpenSSH named pipe
//! (`\\.\pipe\openssh-ssh-agent`).

use crate::error::Result;

#[cfg(any(unix, windows))]
use russh::keys::agent::client::AgentClient;
#[cfg(any(unix, windows))]
use russh::keys::agent::AgentIdentity;

#[cfg(unix)]
pub type Connection = AgentClient<tokio::net::UnixStream>;

#[cfg(windows)]
pub type Connection =
    AgentClient<tokio::net::windows::named_pipe::NamedPipeClient>;

/// Connect to the local agent (`$SSH_AUTH_SOCK` on Unix, the OpenSSH named
/// pipe on Windows).
#[cfg(unix)]
pub async fn connect_env() -> Result<Connection> {
    Ok(AgentClient::connect_env().await?)
}

/// Connect to the OpenSSH for Windows agent.
#[cfg(windows)]
pub async fn connect_env() -> Result<Connection> {
    Ok(Connection::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent").await?)
}

/// List the identities currently loaded in the agent.
#[cfg(any(unix, windows))]
pub async fn list_identities(agent: &mut Connection) -> Result<Vec<AgentIdentity>> {
    Ok(agent.request_identities().await?)
}

/// No agent support on this platform (neither Unix sockets nor Windows).
#[cfg(not(any(unix, windows)))]
pub async fn connect_env() -> Result<()> {
    Err(crate::error::Error::Other(
        "ssh-agent is not supported on this platform".into(),
    ))
}
