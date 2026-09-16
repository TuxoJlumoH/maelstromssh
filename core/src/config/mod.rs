//! Session/profile management: persisted connection settings that CLI, TUI,
//! and future GUI front-ends all read/write through this module.

mod profile;
mod store;

pub use profile::{AuthMethod, ForwardKind, ForwardRule, Profile, TerminalSettings};
pub use store::ProfileStore;
