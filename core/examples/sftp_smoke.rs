//! Manual smoke test for the SFTP subsystem against a local sshd:
//!
//! ```sh
//! cargo run -p maelstromssh-core --example sftp_smoke -- 127.0.0.1 2222 <user> <key_path>
//! ```
//!
//! Not run in CI (no local sshd available there).

use std::sync::Arc;

use maelstromssh_core::config::AuthMethod;
use maelstromssh_core::prompt::NoPrompt;
use maelstromssh_core::sftp;
use maelstromssh_core::ssh::{AcceptAll, Session};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let host = args.next().unwrap_or_else(|| "127.0.0.1".into());
    let port: u16 = args.next().unwrap_or_else(|| "2222".into()).parse()?;
    let user = args
        .next()
        .unwrap_or_else(maelstromssh_core::target::local_user);
    let key_path = args
        .next()
        .expect("usage: sftp_smoke <host> <port> <user> <key_path>");

    let session = Session::connect(
        &host,
        port,
        &user,
        &AuthMethod::PublicKey { key_path },
        Arc::new(NoPrompt),
        Arc::new(AcceptAll), // fine for a throwaway local test sshd only
    )
    .await?;

    let sftp = sftp::open(&session).await?;
    let cwd = sftp.canonicalize(".").await?;
    println!("cwd: {cwd}");

    for entry in sftp.read_dir(".").await? {
        println!("entry: {:?}", entry.file_name());
    }

    session.disconnect().await?;
    Ok(())
}
