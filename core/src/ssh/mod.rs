//! SSH transport: connecting, authenticating, and driving interactive shell
//! channels. Wraps `russh` behind a small API so callers (CLI/TUI/GUI) never
//! touch `russh` types directly.

mod client;
mod session;

pub use client::{AcceptAll, ClientHandler, HostKeyVerifier, KnownHosts, ServerEvent};
pub use session::{ClientHandle, Session};

pub use russh::client::Msg;
/// Re-exported so callers can drive channel I/O (read `ChannelMsg`, send
/// `data`/`window_change`, etc.) without depending on `russh` directly.
pub use russh::{Channel, ChannelMsg};
