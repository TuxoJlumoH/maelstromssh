//! maelstromssh-gui: a graphical (egui/eframe) front-end for `maelstromssh`.
//!
//! Authentication (password/passphrase/2FA prompts and host-key
//! confirmation) happens inside the window; the SSH session runs on a
//! background tokio task and talks to this single-threaded GUI over channels
//! (see [`ssh`]).

mod app;
mod keys;
mod paint;
mod ssh;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use clap::Parser;
use egui::{IconData, ViewportBuilder};
use maelstromssh_core::config::{FlowControl, Parity, Protocol, SerialSettings};
use maelstromssh_core::target::TargetArgs;

use crate::app::{GuiApp, LaunchArgs};

#[derive(Parser)]
#[command(
    name = "maelstromssh-gui",
    version,
    about = "A graphical SSH, serial, Telnet and raw TCP terminal"
)]
struct Cli {
    #[command(flatten)]
    target: TargetArgs,
    /// Open <target> as a serial (COM) port (e.g. /dev/ttyUSB0); set the line
    /// with -b, --parity, etc.
    #[arg(long, conflicts_with_all = ["port", "auth", "identity", "jump", "profile", "telnet", "raw"])]
    serial: bool,
    /// Connect over Telnet (port 23 unless -p is given).
    #[arg(long, conflicts_with_all = ["auth", "identity", "jump", "profile", "raw"])]
    telnet: bool,
    /// Open a raw TCP connection (needs -p).
    #[arg(long, requires = "port", conflicts_with_all = ["auth", "identity", "jump", "profile"])]
    raw: bool,
    #[command(flatten)]
    line: LineArgs,
    /// Save everything the session prints to FILE (appended). A folder gets a
    /// dated file; &H, &P, &Y, &M, &D, &T in the name become the host, port,
    /// date and time.
    #[arg(long, value_name = "FILE")]
    log: Option<PathBuf>,
}

/// Serial line settings. The defaults are 9600 8N1 without flow control.
#[derive(clap::Args, Clone, Copy)]
struct LineArgs {
    /// Baud rate.
    #[arg(short, long, default_value_t = 9600)]
    baud: u32,
    /// Data bits (5-8).
    #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u8).range(5..=8))]
    data_bits: u8,
    #[arg(long, value_enum, default_value = "none")]
    parity: Parity,
    /// Stop bits (1 or 2).
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(1..=2))]
    stop_bits: u8,
    /// Flow control: none, software (XON/XOFF) or hardware (RTS/CTS).
    #[arg(long, value_enum, default_value = "none")]
    flow: FlowControl,
}

impl From<LineArgs> for SerialSettings {
    fn from(a: LineArgs) -> Self {
        SerialSettings {
            baud: a.baud,
            data_bits: a.data_bits,
            parity: a.parity,
            stop_bits: a.stop_bits,
            flow_control: a.flow,
        }
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Without a target or profile the window opens on a connect form, as
    // it does when the arguments don't resolve (errors are shown there).
    let cli = Cli::parse();
    let protocol = if cli.serial {
        Protocol::Serial
    } else if cli.telnet {
        Protocol::Telnet
    } else if cli.raw {
        Protocol::Raw
    } else {
        Protocol::Ssh
    };
    let launch = LaunchArgs {
        target: cli.target,
        protocol,
        serial: cli.line.into(),
        log: cli.log,
    };
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
            .with_title("MaelstromSSH")
            // Matches StartupWMClass in packaging/maelstromssh.desktop.
            .with_app_id("maelstromssh-gui")
            .with_icon(icon)
            .with_inner_size([1000.0, 650.0])
            .with_min_inner_size([320.0, 240.0]),
        ..Default::default()
    };

    let result = eframe::run_native(
        "MaelstromSSH",
        options,
        Box::new(move |_cc| Ok(Box::new(GuiApp::new(launch, term_type, handle)))),
    );

    // The window closed; give the background connect/shell task a moment to
    // notice the dropped channels and disconnect cleanly.
    rt.shutdown_timeout(Duration::from_secs(1));
    result.map_err(|e| anyhow!("GUI error: {e}"))
}
