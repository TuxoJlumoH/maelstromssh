//! vortexssh-tui: a full-screen `ratatui` terminal for `vortexssh` SSH sessions.
//!
//! Drives the `vortexssh-core` terminal emulator (grid, scrollback, reflow)
//! and an SSH shell channel in a TUI with a one-line status bar.

mod app;
mod input;
mod render;

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use vortexssh_core::prompt::TtyPrompter;
use vortexssh_core::ssh::{KnownHosts, Session};
use vortexssh_core::target::TargetArgs;
use vortexssh_core::term::Terminal;

#[derive(Parser)]
#[command(name = "vortexssh-tui", version, about = "An interactive SSH terminal")]
struct Cli {
    #[command(flatten)]
    target: TargetArgs,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let target = Cli::parse().target.resolve()?;

    // Authentication happens on the ordinary terminal, before we take over
    // the screen with raw mode + the alternate buffer.
    let prompter = Arc::new(TtyPrompter);
    let mut session = Session::connect(
        &target.host,
        target.port,
        &target.user,
        &target.auth,
        prompter.clone(),
        Arc::new(KnownHosts { prompter }),
    )
    .await
    .with_context(|| format!("connecting to {}", target.label()))?;

    // Shell size: the status bar takes one row from the top-level screen.
    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    let shell_rows = rows.saturating_sub(1).max(1);
    let term_type = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());

    let channel = session
        .open_shell(&term_type, cols as u32, shell_rows as u32)
        .await
        .context("opening shell channel")?;

    let term = Terminal::new(cols as u32, shell_rows as u32);

    let result = app::run(channel, term, target.label()).await;

    session.disconnect().await.ok();
    result
}
