//! Turning what the user typed (`user@host`, `--profile`, `-i`, `--auth`)
//! into a concrete connection [`Target`]. Shared by every front-end; with the
//! `clap` feature, [`TargetArgs`] can be flattened straight into a CLI parser.

use std::path::PathBuf;

use crate::config::{
    AuthMethod, ForwardRule, HostConfig, ProfileStore, Protocol, SerialSettings, SshConfig,
};
use crate::error::{Error, Result};

/// A fully resolved connection target.
#[derive(Debug, Clone)]
pub struct Target {
    pub protocol: Protocol,
    /// The host, or the device path for serial.
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: AuthMethod,
    pub forwards: Vec<ForwardRule>,
    /// Line settings; `Some` for serial.
    pub serial: Option<SerialSettings>,
    /// Things the user should know before connecting (e.g. ssh_config
    /// settings that are ignored).
    pub warnings: Vec<String>,
}

impl Target {
    /// A serial port, e.g. `/dev/ttyUSB0`.
    pub fn serial(device: impl Into<String>, settings: SerialSettings) -> Self {
        Target {
            protocol: Protocol::Serial,
            host: device.into(),
            port: 0,
            user: String::new(),
            auth: AuthMethod::default(),
            forwards: Vec::new(),
            serial: Some(settings),
            warnings: Vec::new(),
        }
    }

    /// A Telnet or raw TCP connection.
    pub fn tcp(protocol: Protocol, host: impl Into<String>, port: u16) -> Self {
        Target {
            protocol,
            host: host.into(),
            port,
            user: String::new(),
            auth: AuthMethod::default(),
            forwards: Vec::new(),
            serial: None,
            warnings: Vec::new(),
        }
    }

    /// `user@host:port`, `/dev/ttyUSB0 9600 8N1`, `telnet host:23` or
    /// `raw host:port`, for prompts and status bars.
    pub fn label(&self) -> String {
        match self.protocol {
            Protocol::Ssh => format!("{}@{}:{}", self.user, self.host, self.port),
            Protocol::Serial => format!("{} {}", self.host, self.serial.unwrap_or_default()),
            Protocol::Telnet | Protocol::Raw => {
                format!("{} {}:{}", self.protocol.name(), self.host, self.port)
            }
        }
    }
}

/// The `--auth` choices accepted on the command line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum AuthChoice {
    /// Agent, then key files, then keyboard-interactive or password.
    Auto,
    Password,
    Key,
    Agent,
    KeyboardInteractive,
}

impl AuthChoice {
    /// Builds the auth method; `key` needs an identity file.
    pub fn into_method(self, identity: Option<PathBuf>) -> Result<AuthMethod> {
        Ok(match self {
            AuthChoice::Auto => AuthMethod::Auto {
                identities: identity
                    .map(|p| p.display().to_string())
                    .into_iter()
                    .collect(),
            },
            AuthChoice::Password => AuthMethod::Password,
            AuthChoice::Key => {
                let path = identity
                    .ok_or_else(|| Error::Config("--auth key requires --identity <PATH>".into()))?;
                AuthMethod::PublicKey {
                    key_path: path.display().to_string(),
                }
            }
            AuthChoice::Agent => AuthMethod::Agent,
            AuthChoice::KeyboardInteractive => AuthMethod::KeyboardInteractive,
        })
    }
}

/// Picks the auth method from optional `--auth` and `-i` flags. Without
/// `--auth` this is automatic, with `-i` (if given) tried first.
pub fn auth_from_flags(auth: Option<AuthChoice>, identity: Option<PathBuf>) -> Result<AuthMethod> {
    auth.unwrap_or(AuthChoice::Auto).into_method(identity)
}

/// Splits `user@host` into `(user, host)`; the user is `None` for a bare host.
pub fn split_target(target: &str) -> (Option<String>, String) {
    match target.rsplit_once('@') {
        Some((user, host)) => (Some(user.to_string()), host.to_string()),
        None => (None, target.to_string()),
    }
}

/// The local login name, the default remote user.
pub fn local_user() -> String {
    std::env::var("USER").unwrap_or_else(|_| "root".to_string())
}

/// Connection flags shared by every front-end.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct TargetArgs {
    /// user@host, or just host (defaults to $USER). Host aliases from
    /// ~/.ssh/config work. Omit if using --profile.
    pub target: Option<String>,
    /// Port (default 22).
    #[cfg_attr(feature = "clap", arg(short = 'p', long))]
    pub port: Option<u16>,
    /// Private key to try first (the agent and password still work as
    /// fallbacks unless --auth says otherwise).
    #[cfg_attr(feature = "clap", arg(short = 'i', long))]
    pub identity: Option<PathBuf>,
    /// Load connection settings from a saved profile.
    #[cfg_attr(feature = "clap", arg(long, conflicts_with = "target"))]
    pub profile: Option<String>,
    /// Authentication method (default: auto).
    #[cfg_attr(feature = "clap", arg(long, value_enum))]
    pub auth: Option<AuthChoice>,
}

impl TargetArgs {
    /// Resolves the flags against the default profile store and
    /// `~/.ssh/config` (plus `/etc/ssh/ssh_config`), for an SSH connection:
    /// other kinds of profile are an error.
    pub fn resolve(self) -> Result<Target> {
        ssh_only(self.resolve_any()?)
    }

    /// Like [`resolve`](Self::resolve), but a profile may be of any
    /// protocol (e.g. serial); check `Target::protocol`.
    pub fn resolve_any(self) -> Result<Target> {
        let store = ProfileStore::default_location()?;
        let ssh_config = if self.profile.is_some() {
            SshConfig::default()
        } else {
            SshConfig::load_default()?
        };
        self.resolve_any_with(&store, &ssh_config)
    }

    /// [`resolve`](Self::resolve) with a given profile store and ssh_config.
    pub fn resolve_with(self, store: &ProfileStore, ssh_config: &SshConfig) -> Result<Target> {
        ssh_only(self.resolve_any_with(store, ssh_config)?)
    }

    /// Command-line flags win over `ssh_config`, which wins over defaults.
    /// Saved profiles are used as they are; `ssh_config` does not apply.
    pub fn resolve_any_with(self, store: &ProfileStore, ssh_config: &SshConfig) -> Result<Target> {
        if let Some(name) = self.profile {
            let p = store.load(&name)?;
            match p.protocol {
                Protocol::Ssh => {}
                Protocol::Serial => {
                    return Ok(Target::serial(p.host, p.serial.unwrap_or_default()))
                }
                Protocol::Telnet | Protocol::Raw => {
                    return Ok(Target::tcp(p.protocol, p.host, self.port.unwrap_or(p.port)))
                }
            }
            let auth = match self.auth {
                Some(choice) => choice.into_method(self.identity)?,
                None => match self.identity {
                    Some(id) => AuthChoice::Auto.into_method(Some(id))?,
                    None => p.auth,
                },
            };
            return Ok(Target {
                protocol: Protocol::Ssh,
                host: p.host,
                port: self.port.unwrap_or(p.port),
                user: p.user,
                auth,
                forwards: p.forwards,
                serial: None,
                warnings: Vec::new(),
            });
        }

        let target = self
            .target
            .ok_or_else(|| Error::Config("provide a <target> or --profile <NAME>".into()))?;
        let (user, host) = split_target(&target);
        if host.is_empty() {
            return Err(Error::Config(format!("no host in '{target}'")));
        }
        let config = ssh_config.lookup(&host, user.as_deref())?;
        let auth = match self.identity {
            Some(id) => auth_from_flags(self.auth, Some(id))?,
            None => auth_with_config(self.auth, &config)?,
        };
        Ok(Target {
            protocol: Protocol::Ssh,
            host: config.hostname.unwrap_or(host),
            port: self.port.or(config.port).unwrap_or(22),
            user: user.or(config.user).unwrap_or_else(local_user),
            auth,
            forwards: Vec::new(),
            serial: None,
            warnings: config
                .unsupported
                .iter()
                .map(|k| format!("ignoring {k} (not supported by maelstromssh)"))
                .collect(),
        })
    }
}

fn ssh_only(target: Target) -> Result<Target> {
    match target.protocol {
        Protocol::Ssh => Ok(target),
        other => Err(Error::Config(format!(
            "this is a {} profile; open it with `maelstromssh connect` or the web UI",
            other.name()
        ))),
    }
}

/// The auth method when no `-i` was given: `IdentityFile`s from
/// ssh_config take its place. Like OpenSSH, ones that do not exist are
/// skipped.
fn auth_with_config(auth: Option<AuthChoice>, config: &HostConfig) -> Result<AuthMethod> {
    let existing: Vec<String> = config
        .identity_files
        .iter()
        .filter(|p| {
            let exists = std::path::Path::new(p).exists();
            if !exists {
                tracing::debug!("ssh_config IdentityFile {p} does not exist, skipping");
            }
            exists
        })
        .cloned()
        .collect();
    match auth.unwrap_or(AuthChoice::Auto) {
        AuthChoice::Auto => Ok(AuthMethod::Auto {
            identities: existing,
        }),
        AuthChoice::Key => {
            AuthChoice::Key.into_method(existing.into_iter().next().map(PathBuf::from))
        }
        choice => choice.into_method(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Profile;

    #[test]
    fn splits_user_and_host() {
        assert_eq!(
            split_target("alice@example.com"),
            (Some("alice".into()), "example.com".into())
        );
        assert_eq!(split_target("example.com"), (None, "example.com".into()));
    }

    #[test]
    fn bare_identity_is_tried_first_in_auto() {
        let t = TargetArgs {
            target: Some("bob@h".into()),
            identity: Some("/k".into()),
            ..Default::default()
        }
        .resolve_with(&ProfileStore::new("/nonexistent"), &SshConfig::default())
        .unwrap();
        assert!(matches!(t.auth, AuthMethod::Auto { ref identities } if identities == &["/k"]));
        assert_eq!(t.port, 22);
    }

    #[test]
    fn default_is_auto_with_default_keys() {
        let t = TargetArgs {
            target: Some("h".into()),
            ..Default::default()
        }
        .resolve_with(&ProfileStore::new("/nonexistent"), &SshConfig::default())
        .unwrap();
        assert!(matches!(t.auth, AuthMethod::Auto { ref identities } if identities.is_empty()));
    }

    #[test]
    fn key_choice_requires_identity() {
        assert!(AuthChoice::Key.into_method(None).is_err());
    }

    #[test]
    fn missing_target_is_an_error() {
        assert!(TargetArgs::default()
            .resolve_with(&ProfileStore::new("/nonexistent"), &SshConfig::default())
            .is_err());
    }

    #[test]
    fn profile_flags_override_saved_settings() {
        let dir = std::env::temp_dir().join(format!("maelstromssh-target-{}", std::process::id()));
        let store = ProfileStore::new(&dir);
        store
            .save(&Profile {
                name: "box".into(),
                host: "10.0.0.5".into(),
                port: 2222,
                user: "admin".into(),
                auth: AuthMethod::Password,
                forwards: vec![],
                ..Profile::new("box")
            })
            .unwrap();

        let t = TargetArgs {
            profile: Some("box".into()),
            ..Default::default()
        }
        .resolve_with(&store, &SshConfig::default())
        .unwrap();
        assert_eq!(
            (t.host.as_str(), t.port, t.user.as_str()),
            ("10.0.0.5", 2222, "admin")
        );
        assert!(matches!(t.auth, AuthMethod::Password));

        let t = TargetArgs {
            profile: Some("box".into()),
            port: Some(22),
            auth: Some(AuthChoice::Agent),
            ..Default::default()
        }
        .resolve_with(&store, &SshConfig::default())
        .unwrap();
        assert_eq!(t.port, 22);
        assert!(matches!(t.auth, AuthMethod::Agent));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn serial_profiles_need_resolve_any() {
        let dir =
            std::env::temp_dir().join(format!("maelstromssh-target-ser-{}", std::process::id()));
        let store = ProfileStore::new(&dir);
        store
            .save(&Profile {
                protocol: Protocol::Serial,
                host: "/dev/ttyUSB0".into(),
                serial: Some(SerialSettings {
                    baud: 115_200,
                    ..Default::default()
                }),
                ..Profile::new("console")
            })
            .unwrap();
        let args = TargetArgs {
            profile: Some("console".into()),
            ..Default::default()
        };
        let e = args
            .clone()
            .resolve_with(&store, &SshConfig::default())
            .unwrap_err();
        assert!(e.to_string().contains("serial profile"), "{e}");
        let t = args
            .resolve_any_with(&store, &SshConfig::default())
            .unwrap();
        assert_eq!(t.protocol, Protocol::Serial);
        assert_eq!(t.label(), "/dev/ttyUSB0 115200 8N1");

        store
            .save(&Profile {
                protocol: Protocol::Telnet,
                host: "switch".into(),
                port: 2323,
                ..Profile::new("sw")
            })
            .unwrap();
        let args = TargetArgs {
            profile: Some("sw".into()),
            ..Default::default()
        };
        let e = args
            .clone()
            .resolve_with(&store, &SshConfig::default())
            .unwrap_err();
        assert!(e.to_string().contains("telnet profile"), "{e}");
        let t = args
            .resolve_any_with(&store, &SshConfig::default())
            .unwrap();
        assert_eq!(t.label(), "telnet switch:2323");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ssh_config_fills_gaps_but_flags_win() {
        let dir =
            std::env::temp_dir().join(format!("maelstromssh-target-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("web_key");
        std::fs::write(&key, "").unwrap();
        let config = SshConfig::parse(
            &format!(
                "Host web\n  HostName 10.0.0.9\n  User deploy\n  Port 2200\n  \
                 IdentityFile {}\n  IdentityFile /missing/key\n",
                key.display()
            ),
            &dir,
        )
        .unwrap();
        let store = ProfileStore::new("/nonexistent");

        let t = TargetArgs {
            target: Some("web".into()),
            ..Default::default()
        }
        .resolve_with(&store, &config)
        .unwrap();
        assert_eq!(
            (t.host.as_str(), t.port, t.user.as_str()),
            ("10.0.0.9", 2200, "deploy")
        );
        let key_str = key.display().to_string();
        assert!(
            matches!(t.auth, AuthMethod::Auto { ref identities } if identities == std::slice::from_ref(&key_str))
        );

        let t = TargetArgs {
            target: Some("root@web".into()),
            port: Some(22),
            identity: Some("/other".into()),
            ..Default::default()
        }
        .resolve_with(&store, &config)
        .unwrap();
        assert_eq!((t.port, t.user.as_str()), (22, "root"));
        assert!(matches!(t.auth, AuthMethod::Auto { ref identities } if identities == &["/other"]));

        let t = TargetArgs {
            target: Some("web".into()),
            auth: Some(AuthChoice::Key),
            ..Default::default()
        }
        .resolve_with(&store, &config)
        .unwrap();
        assert!(matches!(t.auth, AuthMethod::PublicKey { ref key_path } if key_path == &key_str));

        std::fs::remove_dir_all(&dir).ok();
    }
}
