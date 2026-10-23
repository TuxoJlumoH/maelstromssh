use serde::{Deserialize, Serialize};

/// A saved connection profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    /// Unique profile name, e.g. "prod-web-1".
    pub name: String,
    #[serde(default)]
    pub protocol: Protocol,
    /// The host name, or the device path (e.g. `/dev/ttyUSB0`) for serial.
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub auth: AuthMethod,
    #[serde(default)]
    pub forwards: Vec<ForwardRule>,
    /// Line settings; only used by serial profiles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<SerialSettings>,
    #[serde(default)]
    pub terminal: TerminalSettings,
}

impl Profile {
    /// An SSH profile with default settings and no host yet.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            protocol: Protocol::Ssh,
            host: String::new(),
            port: default_port(),
            user: String::new(),
            auth: AuthMethod::default(),
            forwards: Vec::new(),
            serial: None,
            terminal: TerminalSettings::default(),
        }
    }
}

fn default_port() -> u16 {
    22
}

/// How a profile connects.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    #[default]
    Ssh,
    /// A local serial port (COM port), e.g. `/dev/ttyUSB0`.
    Serial,
    /// Telnet (unencrypted), e.g. to old switches and routers.
    Telnet,
    /// A plain TCP connection: bytes go both ways unchanged.
    Raw,
}

impl Protocol {
    pub fn name(self) -> &'static str {
        match self {
            Protocol::Ssh => "ssh",
            Protocol::Serial => "serial",
            Protocol::Telnet => "telnet",
            Protocol::Raw => "raw",
        }
    }

    /// Telnet and raw: a terminal over a plain TCP connection.
    pub fn is_tcp(self) -> bool {
        matches!(self, Protocol::Telnet | Protocol::Raw)
    }

    /// The usual port, if the protocol has one.
    pub fn default_port(self) -> Option<u16> {
        match self {
            Protocol::Ssh => Some(22),
            Protocol::Telnet => Some(23),
            Protocol::Serial | Protocol::Raw => None,
        }
    }
}

/// Serial line settings. The defaults are PuTTY's, without flow control:
/// 9600 baud, 8 data bits, no parity, 1 stop bit.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SerialSettings {
    #[serde(default = "default_baud")]
    pub baud: u32,
    #[serde(default = "default_data_bits")]
    pub data_bits: u8,
    #[serde(default)]
    pub parity: Parity,
    #[serde(default = "default_stop_bits")]
    pub stop_bits: u8,
    #[serde(default)]
    pub flow_control: FlowControl,
}

impl Default for SerialSettings {
    fn default() -> Self {
        Self {
            baud: default_baud(),
            data_bits: default_data_bits(),
            parity: Parity::None,
            stop_bits: default_stop_bits(),
            flow_control: FlowControl::None,
        }
    }
}

impl SerialSettings {
    /// Rejects settings no serial port supports.
    pub fn check(&self) -> crate::Result<()> {
        let bad = |what: String| Err(crate::Error::Config(what));
        if self.baud == 0 {
            return bad("the baud rate must be above 0".into());
        }
        if !(5..=8).contains(&self.data_bits) {
            return bad(format!("data bits must be 5 to 8, not {}", self.data_bits));
        }
        if !(1..=2).contains(&self.stop_bits) {
            return bad(format!("stop bits must be 1 or 2, not {}", self.stop_bits));
        }
        Ok(())
    }
}

/// `9600 8N1`, plus the flow control when there is one.
impl std::fmt::Display for SerialSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let parity = match self.parity {
            Parity::None => 'N',
            Parity::Odd => 'O',
            Parity::Even => 'E',
        };
        write!(
            f,
            "{} {}{parity}{}",
            self.baud, self.data_bits, self.stop_bits
        )?;
        match self.flow_control {
            FlowControl::None => Ok(()),
            FlowControl::Software => write!(f, " XON/XOFF"),
            FlowControl::Hardware => write!(f, " RTS/CTS"),
        }
    }
}

fn default_baud() -> u32 {
    9600
}

fn default_data_bits() -> u8 {
    8
}

fn default_stop_bits() -> u8 {
    1
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum Parity {
    #[default]
    None,
    Odd,
    Even,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum FlowControl {
    #[default]
    None,
    /// XON/XOFF.
    Software,
    /// RTS/CTS.
    Hardware,
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
