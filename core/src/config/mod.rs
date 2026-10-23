//! Session/profile management: persisted connection settings that CLI, TUI,
//! and future GUI front-ends all read/write through this module.

mod forward_spec;
mod profile;
mod ssh_config;
mod store;

pub use forward_spec::parse_forward;
pub use profile::{AuthMethod, ForwardKind, ForwardRule, Profile, TerminalSettings};
pub use ssh_config::{HostConfig, SshConfig};
pub use store::ProfileStore;
