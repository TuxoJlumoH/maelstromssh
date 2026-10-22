//! Turning what the user typed (`user@host`, `--profile`, `-i`, `--auth`)
//! into a concrete connection [`Target`]. Shared by every front-end; with the
//! `clap` feature, [`TargetArgs`] can be flattened straight into a CLI parser.

use std::path::PathBuf;

use crate::config::{AuthMethod, ForwardRule, ProfileStore};
use crate::error::{Error, Result};

/// A fully resolved connection target.
#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: AuthMethod,
    pub forwards: Vec<ForwardRule>,
}

impl Target {
    /// `user@host:port`, for prompts and status bars.
    pub fn label(&self) -> String {
        format!("{}@{}:{}", self.user, self.host, self.port)
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

/// Splits `user@host` into `(user, host)`; a bare host gets `$USER`.
pub fn split_target(target: &str) -> (String, String) {
    match target.rsplit_once('@') {
        Some((user, host)) => (user.to_string(), host.to_string()),
        None => (local_user(), target.to_string()),
    }
}

fn local_user() -> String {
    std::env::var("USER").unwrap_or_else(|_| "root".to_string())
}

/// Connection flags shared by every front-end.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct TargetArgs {
    /// user@host, or just host (defaults to $USER). Omit if using --profile.
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
    /// Resolves the flags against the default profile store.
    pub fn resolve(self) -> Result<Target> {
        let store = ProfileStore::default_location()?;
        self.resolve_with(&store)
    }

    pub fn resolve_with(self, store: &ProfileStore) -> Result<Target> {
        if let Some(name) = self.profile {
            let p = store.load(&name)?;
            let auth = match self.auth {
                Some(choice) => choice.into_method(self.identity)?,
                None => match self.identity {
                    Some(id) => AuthChoice::Auto.into_method(Some(id))?,
                    None => p.auth,
                },
            };
            return Ok(Target {
                host: p.host,
                port: self.port.unwrap_or(p.port),
                user: p.user,
                auth,
                forwards: p.forwards,
            });
        }

        let target = self
            .target
            .ok_or_else(|| Error::Config("provide a <target> or --profile <NAME>".into()))?;
        let (user, host) = split_target(&target);
        if host.is_empty() {
            return Err(Error::Config(format!("no host in '{target}'")));
        }
        Ok(Target {
            host,
            port: self.port.unwrap_or(22),
            user,
            auth: auth_from_flags(self.auth, self.identity)?,
            forwards: Vec::new(),
        })
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
            ("alice".into(), "example.com".into())
        );
        let (_, host) = split_target("example.com");
        assert_eq!(host, "example.com");
    }

    #[test]
    fn bare_identity_is_tried_first_in_auto() {
        let t = TargetArgs {
            target: Some("bob@h".into()),
            identity: Some("/k".into()),
            ..Default::default()
        }
        .resolve_with(&ProfileStore::new("/nonexistent"))
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
        .resolve_with(&ProfileStore::new("/nonexistent"))
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
            .resolve_with(&ProfileStore::new("/nonexistent"))
            .is_err());
    }

    #[test]
    fn profile_flags_override_saved_settings() {
        let dir = std::env::temp_dir().join(format!("vortexssh-target-{}", std::process::id()));
        let store = ProfileStore::new(&dir);
        store
            .save(&Profile {
                name: "box".into(),
                host: "10.0.0.5".into(),
                port: 2222,
                user: "admin".into(),
                auth: AuthMethod::Password,
                forwards: vec![],
                terminal: Default::default(),
            })
            .unwrap();

        let t = TargetArgs {
            profile: Some("box".into()),
            ..Default::default()
        }
        .resolve_with(&store)
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
        .resolve_with(&store)
        .unwrap();
        assert_eq!(t.port, 22);
        assert!(matches!(t.auth, AuthMethod::Agent));

        std::fs::remove_dir_all(&dir).ok();
    }
}
