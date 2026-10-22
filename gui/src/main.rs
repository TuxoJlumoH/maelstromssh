//! vortexssh-gui: a graphical (egui/eframe) front-end for `vortexssh`.
//!
//! Authentication (password/passphrase prompts and host-key confirmation)
//! happens inside the window; the SSH session runs on a background tokio
//! task and talks to this single-threaded GUI over channels (see [`ssh`]).

mod app;
mod keys;
mod paint;
mod ssh;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, ValueEnum};
use egui::{IconData, ViewportBuilder};
use vortexssh_core::config::{AuthMethod, ProfileStore};
use vortexssh_core::ssh::{HostKeyVerifier, KnownHosts};

use crate::app::{GuiApp, HostKeyQuestion};
use crate::ssh::{Channels, ConnectSpec};

#[derive(Parser)]
#[command(name = "vortexssh-gui", version, about = "A graphical SSH terminal")]
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

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let spec = resolve_spec(cli.target, cli.port, cli.identity, cli.profile, cli.auth)?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let handle = rt.handle().clone();

    let (question_tx, question_rx) = std::sync::mpsc::channel();
    let verifier = host_key_verifier(question_tx);
    let channels = Channels::new();

    let icon = Arc::new(IconData {
        rgba: include_bytes!("../../assets/icon-256.rgba").to_vec(),
        width: 256,
        height: 256,
    });

    let options = eframe::NativeOptions {
        viewport: ViewportBuilder::default()
            .with_title("VortexSSH")
            .with_icon(icon)
            .with_inner_size([1000.0, 650.0])
            .with_min_inner_size([320.0, 240.0]),
        ..Default::default()
    };

    let result = eframe::run_native(
        "VortexSSH",
        options,
        Box::new(move |_cc| {
            Ok(Box::new(GuiApp::new(
                spec,
                handle,
                verifier,
                question_rx,
                channels,
            )))
        }),
    );

    // The window closed; give the background connect/shell task a moment to
    // notice the dropped channels and disconnect cleanly.
    rt.shutdown_timeout(Duration::from_secs(1));
    result.map_err(|e| anyhow!("GUI error: {e}"))
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
    let term_type = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());
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
            term_type,
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
            term_type,
        })
    }
}

/// A host-key verifier that, on an unknown key, hands the fingerprint to the
/// UI and blocks until the user accepts or rejects it. Accepted keys are
/// persisted to `known_hosts` by [`KnownHosts`] as usual.
fn host_key_verifier(tx: std::sync::mpsc::Sender<HostKeyQuestion>) -> Arc<dyn HostKeyVerifier> {
    Arc::new(KnownHosts {
        prompt: Box::new(move |host, port, fingerprint| {
            let (reply_tx, reply_rx) = std::sync::mpsc::channel();
            if tx.send(HostKeyQuestion {
                host: host.to_string(),
                port,
                fingerprint: fingerprint.to_string(),
                reply: reply_tx,
            })
            .is_err()
            {
                return false;
            }
            reply_rx.recv().unwrap_or(false)
        }),
    })
}
