use serde::{Deserialize, Serialize};

/// A saved connection profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    /// Unique profile name, e.g. "prod-web-1".
    pub name: String,
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub user: String,
    #[serde(default)]
    pub auth: AuthMethod,
    #[serde(default)]
    pub forwards: Vec<ForwardRule>,
    #[serde(default)]
    pub terminal: TerminalSettings,
}

fn default_port() -> u16 {
    22
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum AuthMethod {
    /// Whatever works, as OpenSSH does it: ssh-agent keys, then key files
    /// (`identities`, or the default `~/.ssh/id_*` keys when empty), then
    /// keyboard-interactive or a password prompt.
    Auto {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        identities: Vec<String>,
    },
    /// Prompt for a password interactively; never stored in the profile.
    Password,
    /// Public key auth with an OpenSSH-format private key.
    PublicKey { key_path: String },
    /// Delegate entirely to a running ssh-agent.
    Agent,
    /// keyboard-interactive (e.g. 2FA prompts).
    KeyboardInteractive,
}

impl Default for AuthMethod {
    fn default() -> Self {
        AuthMethod::Auto {
            identities: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardRule {
    pub kind: ForwardKind,
    pub bind_host: String,
    pub bind_port: u16,
    /// Destination host/port; unused for Dynamic (SOCKS) forwards.
    #[serde(default)]
    pub dest_host: Option<String>,
    #[serde(default)]
    pub dest_port: Option<u16>,
}

impl std::fmt::Display for ForwardRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bind = if self.bind_host.is_empty() {
            self.bind_port.to_string()
        } else {
            format!("{}:{}", self.bind_host, self.bind_port)
        };
        match self.kind {
            ForwardKind::Local => write!(
                f,
                "local {bind} -> {}:{}",
                self.dest_host.as_deref().unwrap_or("127.0.0.1"),
                self.dest_port.unwrap_or(0)
            ),
            ForwardKind::Remote => write!(
                f,
                "remote {bind} -> {}:{}",
                self.dest_host.as_deref().unwrap_or("127.0.0.1"),
                self.dest_port.unwrap_or(0)
            ),
            ForwardKind::Dynamic => write!(f, "dynamic {bind}"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ForwardKind {
    Local,
    Remote,
    Dynamic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalSettings {
    #[serde(default = "default_term_type")]
    pub term_type: String,
    #[serde(default = "default_scrollback")]
    pub scrollback_lines: u32,
    #[serde(default)]
    pub color_scheme: Option<String>,
}

impl Default for TerminalSettings {
    fn default() -> Self {
        Self {
            term_type: default_term_type(),
            scrollback_lines: default_scrollback(),
            color_scheme: None,
        }
    }
}

fn default_term_type() -> String {
    "xterm-256color".to_string()
}

fn default_scrollback() -> u32 {
    10_000
}
