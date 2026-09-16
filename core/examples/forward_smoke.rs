//! Manual smoke test for port forwarding against a local sshd:
//!
//! ```sh
//! cargo run -p vortexssh-core --example forward_smoke -- 127.0.0.1 2222 <user> <key_path>
//! ```
//!
//! Starts one local (18080), one remote (19000), and one dynamic/SOCKS (1080)
//! forward to `127.0.0.1:18081`, prints their bindings, and holds the session
//! open until killed. Not run in CI (no local sshd available there).

use std::sync::Arc;

use vortexssh_core::config::{ForwardKind, ForwardRule};
use vortexssh_core::ssh::{AcceptAll, AuthCredentials, Session};
use vortexssh_core::tunnel;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let host = args.next().unwrap_or_else(|| "127.0.0.1".into());
    let port: u16 = args.next().unwrap_or_else(|| "2222".into()).parse()?;
    let user = args.next().unwrap_or_else(|| "pavel".into());
    let key_path = args
        .next()
        .expect("usage: forward_smoke <host> <port> <user> <key_path>");

    let mut session = Session::connect(
        (host.as_str(), port),
        &host,
        port,
        &user,
        AuthCredentials::PublicKey {
            key_path: key_path.into(),
            passphrase: None,
        },
        Arc::new(AcceptAll), // fine for a throwaway local test sshd only
    )
    .await?;

    let dest = "127.0.0.1".to_string();
    let rules = vec![
        ForwardRule {
            kind: ForwardKind::Local,
            bind_host: "127.0.0.1".into(),
            bind_port: 18080,
            dest_host: Some(dest.clone()),
            dest_port: Some(18081),
        },
        ForwardRule {
            kind: ForwardKind::Remote,
            bind_host: "127.0.0.1".into(),
            bind_port: 19000,
            dest_host: Some(dest.clone()),
            dest_port: Some(18081),
        },
        ForwardRule {
            kind: ForwardKind::Dynamic,
            bind_host: "127.0.0.1".into(),
            bind_port: 1080,
            dest_host: None,
            dest_port: None,
        },
    ];

    let infos = tunnel::start_all(&mut session, &rules).await?;
    for info in &infos {
        println!("{info}");
    }

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}
