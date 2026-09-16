//! Manual smoke test for the SFTP subsystem against a local sshd:
//!
//! ```sh
//! cargo run -p vortexssh-core --example sftp_smoke -- 127.0.0.1 2222 <user> <key_path>
//! ```
//!
//! Not run in CI (no local sshd available there) — see Phase 0 notes for a
//! throwaway sshd setup used to validate this manually.

use std::sync::Arc;

use vortexssh_core::sftp;
use vortexssh_core::ssh::{AcceptAll, AuthCredentials, Session};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let host = args.next().unwrap_or_else(|| "127.0.0.1".into());
    let port: u16 = args.next().unwrap_or_else(|| "2222".into()).parse()?;
    let user = args.next().unwrap_or_else(|| "pavel".into());
    let key_path = args
        .next()
        .expect("usage: sftp_smoke <host> <port> <user> <key_path>");

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

    let sftp = sftp::open(&mut session).await?;
    let cwd = sftp.canonicalize(".").await?;
    println!("cwd: {cwd}");

    for entry in sftp.read_dir(".").await? {
        println!("entry: {:?}", entry.file_name());
    }

    session.disconnect().await?;
    Ok(())
}
