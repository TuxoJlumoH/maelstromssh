//! maelstromssh-web: SSH in the browser. Serves a terminal, a file browser and
//! port-forward management on 127.0.0.1, driven by the same core engine as
//! the CLI, TUI and GUI.
//!
//! Only this machine can connect, and every request needs the random token
//! from the printed link (see `auth`).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use axum::routing::{delete, get, post, put};
use axum::{middleware, Router};
use clap::Parser;
use tokio::net::TcpListener;
use tokio::signal::unix::{signal, SignalKind};
use tracing_subscriber::EnvFilter;

mod api;
mod assets;
mod auth;
mod conn;
#[cfg(test)]
mod tests;

/// How long the browser has to read the redirect file before it is deleted.
const REDIRECT_FILE_LIFETIME: Duration = Duration::from_secs(30);

/// Tried first when `--port` is not given; a free port is used if it is taken.
const DEFAULT_PORT: u16 = 8022;

#[derive(Parser)]
#[command(
    name = "maelstromssh-web",
    version,
    about = "SSH in the browser: terminal, file browser and port forwards"
)]
struct Args {
    /// Port on 127.0.0.1 (default: 8022, or any free port if that is taken).
    #[arg(short, long)]
    port: Option<u16>,
    /// Only print the link; do not open a browser.
    #[arg(long)]
    no_browser: bool,
}

/// State shared by every request.
pub struct App {
    pub token: String,
    pub port: u16,
    /// Live connections, so file transfers (plain HTTP) can find the SSH
    /// session that a terminal tab opened.
    pub conns: Mutex<HashMap<u64, Arc<conn::Conn>>>,
    pub next_id: AtomicU64,
    /// One-time download tickets (see `api::download_ticket`).
    pub tickets: Mutex<HashMap<String, api::Ticket>>,
}

impl App {
    pub fn conn(&self, id: u64) -> Option<Arc<conn::Conn>> {
        self.conns
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&id)
            .cloned()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();

    let listener = match args.port {
        Some(port) => TcpListener::bind((Ipv4Addr::LOCALHOST, port))
            .await
            .with_context(|| format!("listening on 127.0.0.1:{port}"))?,
        None => match TcpListener::bind((Ipv4Addr::LOCALHOST, DEFAULT_PORT)).await {
            Ok(l) => l,
            Err(_) => TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?,
        },
    };
    let port = listener.local_addr()?.port();
    let app = Arc::new(App {
        token: auth::new_token()?,
        port,
        conns: Mutex::default(),
        next_id: AtomicU64::new(1),
        tickets: Mutex::default(),
    });

    // The token goes in the fragment, which the browser never sends anywhere.
    let url = format!("http://127.0.0.1:{port}/#token={}", app.token);
    println!("MaelstromSSH web UI: {url}");
    println!("Only this machine can connect. Keep the link private; Ctrl-C stops the server.");
    let opener = if args.no_browser {
        None
    } else {
        open_browser(&url, port)
    };
    if let Some(path) = opener.clone() {
        // The browser reads the file right away; don't leave the token on
        // disk for the whole session.
        tokio::spawn(async move {
            tokio::time::sleep(REDIRECT_FILE_LIFETIME).await;
            let _ = std::fs::remove_file(path);
        });
    }

    let mut terminate = signal(SignalKind::terminate()).context("SIGTERM handler")?;
    let mut hangup = signal(SignalKind::hangup()).context("SIGHUP handler")?;
    let result = tokio::select! {
        r = axum::serve(listener, router(app)) => r.context("web server"),
        _ = tokio::signal::ctrl_c() => Ok(()),
        _ = terminate.recv() => Ok(()),
        _ = hangup.recv() => Ok(()),
    };
    if let Some(path) = opener {
        let _ = std::fs::remove_file(path);
    }
    result
}

fn router(app: Arc<App>) -> Router {
    let api = Router::new()
        .route("/ws", get(conn::ws))
        .route("/api/hosts", get(api::hosts))
        .route("/api/serial-ports", get(api::serial_ports))
        .route("/api/profiles", post(api::save_profile))
        .route("/api/profiles/{name}", delete(api::delete_profile))
        .route("/api/conn/{id}/download", post(api::download_ticket))
        .route(
            "/api/conn/{id}/upload",
            put(api::upload).layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .layer(middleware::from_fn_with_state(
            app.clone(),
            auth::require_token,
        ));

    Router::new()
        .route("/", get(assets::index))
        .route("/download/{ticket}", get(api::download))
        .route("/assets/{file}", get(assets::serve))
        .merge(api)
        .layer(middleware::from_fn_with_state(
            app.clone(),
            auth::check_host,
        ))
        .layer(middleware::from_fn(auth::security_headers))
        .with_state(app)
}

/// Opens the browser through a private redirect file rather than the URL
/// itself, so the token never shows up in another process's command line
/// (which every local user can read). Returns the file to delete on exit.
fn open_browser(url: &str, port: u16) -> Option<PathBuf> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let path = dir.join(format!("maelstromssh-web-{port}.html"));
    let _ = std::fs::remove_file(&path);
    let page = format!(
        "<!doctype html><meta http-equiv=\"refresh\" content=\"0;url={url}\">\
         <title>MaelstromSSH</title><a href=\"{url}\">Open MaelstromSSH</a>\n"
    );
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut f| f.write_all(page.as_bytes()));
    if let Err(e) = written {
        eprintln!("Could not open a browser ({e}); open the link above.");
        return None;
    }
    let spawned = std::process::Command::new("xdg-open")
        .arg(&path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    if spawned.is_err() {
        eprintln!("xdg-open is not available; open the link above.");
    }
    Some(path)
}
