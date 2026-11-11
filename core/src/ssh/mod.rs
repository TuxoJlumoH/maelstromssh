//! SSH transport: connecting, authenticating, and driving interactive shell
//! channels. Wraps `russh` behind a small API so callers (CLI/TUI/GUI) never
//! touch `russh` types directly.

mod auth;
mod client;
pub mod known_hosts;
mod session;

pub use client::{AcceptAll, ClientHandler, HostKeyVerifier, KnownHosts, ServerEvent};
pub use known_hosts::{
    default_known_hosts_path, list_known_hosts, remove_known_host, remove_known_host_line,
    KnownHostEntry,
};
pub use session::{ClientHandle, Session};

pub use russh::client::Msg;
/// Re-exported so callers can drive channel I/O (read `ChannelMsg`, send
/// `data`/`window_change`, etc.) without depending on `russh` directly.
pub use russh::{Channel, ChannelMsg};
