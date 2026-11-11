//! maelstromssh-tui: a full-screen `ratatui` terminal for `maelstromssh`
//! SSH, serial, Telnet and raw TCP sessions.
//!
//! Drives the `maelstromssh-core` terminal emulator (grid, scrollback, reflow)
//! and an SSH shell channel, serial port or TCP socket in a TUI with a
//! one-line status bar.

mod app;
mod input;
mod render;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::Parser;
use maelstromssh_core::config::{FlowControl, Parity, Protocol, SerialSettings};
use maelstromssh_core::prompt::TtyPrompter;
use maelstromssh_core::serial;
use maelstromssh_core::session_log::SessionLog;
use maelstromssh_core::ssh::{KnownHosts, Session};
use maelstromssh_core::target::{Target, TargetArgs};
use maelstromssh_core::tcp::TcpLine;
use maelstromssh_core::term::Terminal;

#[derive(Parser)]
#[command(
    name = "maelstromssh-tui",
    version,
    about = "An interactive SSH, serial, Telnet and raw TCP terminal"
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

impl Cli {
    fn resolve_target(&self) -> Result<Target> {
        if self.serial {
            let Some(ref dev) = self.target.target else {
                bail!("provide a serial device path (e.g. /dev/ttyUSB0)");
            };
            return Ok(Target::serial(dev, self.line.into()));
        }
        if self.telnet || self.raw {
            let Some(ref host) = self.target.target else {
                bail!("provide a host");
            };
            let protocol = if self.telnet {
                Protocol::Telnet
            } else {
                Protocol::Raw
            };
            let port = self
                .target
                .port
                .or_else(|| protocol.default_port())
                .unwrap_or(0);
            return Ok(Target::tcp(protocol, host, port));
        }
        Ok(self.target.clone().resolve_any()?)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let target = cli.resolve_target()?;
    for warning in &target.warnings {
        eprintln!("warning: {warning}");
    }

    let log = match cli.log {
        Some(path) => {
            let l = SessionLog::create(&path, &target.label(), &target.host, target.port)?;
            eprintln!("Logging to {}", l.path().display());
            Some(l)
        }
        None => None,
    };

    // Shell size: the status bar takes one row from the top-level screen.
    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    let shell_rows = rows.saturating_sub(1).max(1);
    let term_type = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());
    let term = Terminal::new(cols as u32, shell_rows as u32);

    match target.protocol {
        Protocol::Ssh => {
            // Authentication happens on the ordinary terminal, before we take over
            // the screen with raw mode + the alternate buffer.
            let prompter = Arc::new(TtyPrompter);
            let session = match Session::connect_via(
                &target.jump,
                &target.host,
                target.port,
                &target.user,
                &target.auth,
                prompter.clone(),
                Arc::new(KnownHosts { prompter }),
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    if let Some(hint) = e.hint() {
                        bail!("{e}\nhint: {hint}");
                    }
                    return Err(e.into());
                }
            };

            let channel = session
                .open_shell(&term_type, cols as u32, shell_rows as u32)
                .await
                .context("opening shell channel")?;

            let result = app::run(app::Backend::Ssh(channel), term, target.label(), log).await;
            session.disconnect().await.ok();
            result
        }
        Protocol::Serial => {
            let settings = target.serial.unwrap_or_default();
            let line = serial::Line::open(&target.host, &settings)?;
            app::run(app::Backend::Serial(line), term, target.label(), log).await
        }
        Protocol::Telnet | Protocol::Raw => {
            let line = TcpLine::connect(
                target.protocol,
                &target.host,
                target.port,
                &term_type,
                (cols, shell_rows),
            )
            .await?;
            app::run(app::Backend::Tcp(line), term, target.label(), log).await
        }
    }
}
