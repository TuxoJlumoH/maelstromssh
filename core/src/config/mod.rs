//! Session/profile management: persisted connection settings that CLI, TUI,
//! and future GUI front-ends all read/write through this module.

mod forward_spec;
mod profile;
mod snippets;
mod ssh_config;
mod store;

pub use forward_spec::{forward_spec, parse_forward};
pub use profile::{
    AuthMethod, FlowControl, ForwardKind, ForwardRule, Parity, Profile, Protocol, SerialSettings,
    TerminalSettings,
};
pub use snippets::{Snippet, SnippetStore};
pub use ssh_config::{HostConfig, SshConfig};
pub use store::{ProfileStore, check_name as check_profile_name};
