//! vortexssh-gui: a graphical (egui/eframe) front-end for `vortexssh`.
//!
//! Authentication (password/passphrase/2FA prompts and host-key
//! confirmation) happens inside the window; the SSH session runs on a
//! background tokio task and talks to this single-threaded GUI over channels
//! (see [`ssh`]).

mod app;
mod keys;
mod paint;
mod ssh;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use clap::Parser;
use egui::{IconData, ViewportBuilder};
use vortexssh_core::target::TargetArgs;

use crate::app::GuiApp;

#[derive(Parser)]
#[command(name = "vortexssh-gui", version, about = "A graphical SSH terminal")]
struct Cli {
    #[command(flatten)]
    target: TargetArgs,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let target = Cli::parse().target.resolve()?;
    for warning in &target.warnings {
        eprintln!("warning: {warning}");
    }
    let term_type = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let handle = rt.handle().clone();

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
        Box::new(move |_cc| Ok(Box::new(GuiApp::new(target, term_type, handle)))),
    );

    // The window closed; give the background connect/shell task a moment to
    // notice the dropped channels and disconnect cleanly.
    rt.shutdown_timeout(Duration::from_secs(1));
    result.map_err(|e| anyhow!("GUI error: {e}"))
}
