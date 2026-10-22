//! ssh-agent client support: connecting to the agent at `$SSH_AUTH_SOCK` and
//! listing its identities. Signing happens during authentication in
//! `ssh::Session::connect` (russh's `AgentClient` implements `auth::Signer`).

use russh::keys::agent::client::AgentClient;
use russh::keys::agent::AgentIdentity;

use crate::error::Result;

pub type Connection = AgentClient<tokio::net::UnixStream>;

pub async fn connect_env() -> Result<Connection> {
    Ok(AgentClient::connect_env().await?)
}

pub async fn list_identities(agent: &mut Connection) -> Result<Vec<AgentIdentity>> {
    Ok(agent.request_identities().await?)
}
