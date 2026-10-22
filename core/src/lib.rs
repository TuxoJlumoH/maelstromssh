//! vortexssh-core: protocol-agnostic engine for SSH sessions, SFTP, tunneling,
//! and key management. Contains no UI/rendering code — CLI, TUI, and any
//! future GUI front-ends all drive this engine.

pub mod config;
pub mod error;
pub mod keys;
pub mod paths;
pub mod prompt;
pub mod sftp;
pub mod ssh;
pub mod target;
pub mod term;
pub mod tunnel;

pub use error::{Error, Result};
