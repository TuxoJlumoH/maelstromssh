//! vortexssh-tui: a full-screen `ratatui` terminal for `vortexssh` SSH sessions.
//!
//! This is the Phase 2 front-end — it drives the `vortexssh-core` terminal
//! emulator (grid, scrollback, reflow) and an SSH shell channel in a TUI
//! with a one-line status bar.

mod app;
mod input;
mod render;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use vortexssh_core::config::{AuthMethod, ProfileStore};
use vortexssh_core::keys;
use vortexssh_core::ssh::{AuthCredentials, HostKeyVerifier, KnownHosts, Session};
use vortexssh_core::term::Terminal;

#[derive(Parser)]
#[command(name = "vortexssh-tui", version, about = "An interactive SSH terminal")]
struct Cli {
    /// user@host, or just host (defaults to $USER). Omit if using --profile.
    target: Option<String>,
    #[arg(short = 'p', long)]
    port: Option<u16>,
    /// Path to a private key for public-key auth.
    #[arg(short = 'i', long)]
    identity: Option<PathBuf>,
    /// Load connection settings from a saved profile.
    #[arg(long, conflicts_with = "target")]
    profile: Option<String>,
    /// Override the authentication method.
    #[arg(long, value_enum)]
    auth: Option<AuthChoice>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum AuthChoice {
    Password,
    Key,
    Agent,
    KeyboardInteractive,
}

/// Resolved connection parameters, whether sourced from a profile or the
/// command line.
struct ConnectSpec {
    host: String,
    port: u16,
    user: String,
    auth: AuthMethod,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let spec = resolve_spec(cli.target, cli.port, cli.identity, cli.profile, cli.auth)?;

    // Authentication happens on the ordinary terminal, before we take over
    // the screen with raw mode + the alternate buffer.
    let credentials = auth_method_to_credentials(&spec.auth, &spec.user, &spec.host)?;

    let mut session = Session::connect(
        (spec.host.as_str(), spec.port),
        &spec.host,
        spec.port,
        &spec.user,
        credentials,
        known_hosts_verifier(),
    )
    .await
    .context("connecting/authenticating")?;

    // Shell size: the status bar takes one row from the top-level screen.
    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    let shell_rows = rows.saturating_sub(1).max(1);
    let term_type = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());

    let channel = session
        .open_shell(&term_type, cols as u32, shell_rows as u32)
        .await
        .context("opening shell channel")?;

    let term = Terminal::new(cols as u32, shell_rows as u32);

    let endpoint = app::Endpoint {
        user: spec.user.clone(),
        host: spec.host.clone(),
        port: spec.port,
    };

    let result = app::run(channel, term, endpoint).await;

    session.disconnect().await.ok();
    result
}

fn split_target(target: &str) -> (String, String) {
    match target.split_once('@') {
        Some((user, host)) => (user.to_string(), host.to_string()),
        None => {
            let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
            (user, target.to_string())
        }
    }
}

fn to_auth_method(choice: AuthChoice, identity: Option<PathBuf>) -> Result<AuthMethod> {
    Ok(match choice {
        AuthChoice::Password => AuthMethod::Password,
        AuthChoice::Key => {
            let path = identity.context("--auth key requires --identity <PATH>")?;
            AuthMethod::PublicKey {
                key_path: path.display().to_string(),
            }
        }
        AuthChoice::Agent => AuthMethod::Agent,
        AuthChoice::KeyboardInteractive => AuthMethod::KeyboardInteractive,
    })
}

fn resolve_spec(
    target: Option<String>,
    port: Option<u16>,
    identity: Option<PathBuf>,
    profile: Option<String>,
    auth: Option<AuthChoice>,
) -> Result<ConnectSpec> {
    if let Some(name) = profile {
        let store = ProfileStore::default_location()?;
        let mut p = store
            .load(&name)
            .with_context(|| format!("loading profile '{name}'"))?;
        if let Some(port) = port {
            p.port = port;
        }
        if let Some(auth) = auth {
            p.auth = to_auth_method(auth, identity)?;
        }
        Ok(ConnectSpec {
            host: p.host,
            port: p.port,
            user: p.user,
            auth: p.auth,
        })
    } else {
        let target = target.context("provide a <target> or --profile <NAME>")?;
        let (user, host) = split_target(&target);
        let port = port.unwrap_or(22);
        let auth = match (auth, identity) {
            (Some(choice), id) => to_auth_method(choice, id)?,
            (None, Some(id)) => AuthMethod::PublicKey {
                key_path: id.display().to_string(),
            },
            (None, None) => AuthMethod::Password,
        };
        Ok(ConnectSpec {
            host,
            port,
            user,
            auth,
        })
    }
}

fn auth_method_to_credentials(
    method: &AuthMethod,
    user: &str,
    host: &str,
) -> Result<AuthCredentials> {
    match method {
        AuthMethod::Password => {
            let password = rpassword::prompt_password(format!("{user}@{host}'s password: "))
                .context("reading password")?;
            Ok(AuthCredentials::Password(password))
        }
        AuthMethod::PublicKey { key_path, .. } => {
            let path = Path::new(key_path);
            let key = keys::load_openssh(path, None)
                .with_context(|| format!("loading private key {key_path}"))?;
            let passphrase = if key.is_encrypted() {
                Some(
                    rpassword::prompt_password(format!("Passphrase for {key_path}: "))
                        .context("reading passphrase")?,
                )
            } else {
                None
            };
            Ok(AuthCredentials::PublicKey {
                key_path: path.to_path_buf(),
                passphrase,
            })
        }
        AuthMethod::Agent => Ok(AuthCredentials::Agent),
        AuthMethod::KeyboardInteractive => {
            let password = rpassword::prompt_password(format!("{user}@{host}'s password: "))
                .context("reading password")?;
            Ok(AuthCredentials::Password(password))
        }
    }
}

fn known_hosts_verifier() -> Arc<dyn HostKeyVerifier> {
    Arc::new(KnownHosts {
        prompt: Box::new(|host, port, fingerprint| {
            eprintln!(
                "The authenticity of host '{host}:{port}' can't be established.\n\
                 Key fingerprint is {fingerprint}.\n\
                 Are you sure you want to continue connecting (yes/no)?"
            );
            let mut answer = String::new();
            if std::io::stdin().read_line(&mut answer).is_err() {
                return false;
            }
            answer.trim().eq_ignore_ascii_case("yes")
        }),
    })
}
