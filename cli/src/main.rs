use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use crossterm::terminal;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vortexssh_core::config::{AuthMethod, ForwardKind, ForwardRule, Profile, ProfileStore};
use vortexssh_core::prompt::TtyPrompter;
use vortexssh_core::ssh::{ChannelMsg, KnownHosts, Session};
use vortexssh_core::target::{auth_from_flags, split_target, AuthChoice, Target, TargetArgs};
use vortexssh_core::term::Terminal;
use vortexssh_core::tunnel;

mod forward;
mod sftp;
use forward::parse as parse_forward;
use sftp::SftpOp;

#[derive(Parser)]
#[command(name = "vortexssh", version, about = "An SSH/SFTP client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Connect to a host and open an interactive shell.
    Connect {
        #[command(flatten)]
        target: TargetArgs,
        /// Local forward: [bind:]port:host:hostport (repeatable).
        #[arg(short = 'L', long = "local-forward", value_name = "SPEC")]
        local: Vec<String>,
        /// Remote forward: [bind:]port:host:hostport (repeatable).
        #[arg(short = 'R', long = "remote-forward", value_name = "SPEC")]
        remote: Vec<String>,
        /// Dynamic (SOCKS5) forward: [bind:]port (repeatable).
        #[arg(short = 'D', long = "dynamic-forward", value_name = "SPEC")]
        dynamic: Vec<String>,
    },
    /// Manage saved connection profiles.
    Profile {
        #[command(subcommand)]
        cmd: ProfileCmd,
    },
    /// Transfer files over SFTP (interactive shell, or a one-shot command).
    Sftp {
        #[command(flatten)]
        target: TargetArgs,
        /// One-shot operation; omit for an interactive SFTP shell.
        #[command(subcommand)]
        operation: Option<SftpOp>,
    },
    /// Generate a new SSH keypair.
    Keygen {
        /// Output path for the private key (public key written to <path>.pub).
        /// Defaults to id_ed25519 / id_rsa depending on --type.
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(short, long, default_value = "")]
        comment: String,
        /// Key type.
        #[arg(short = 't', long, value_enum, default_value = "ed25519")]
        key_type: KeyType,
        /// RSA modulus size in bits (ignored for ed25519).
        #[arg(short = 'b', long, default_value_t = 3072)]
        bits: usize,
    },
}

#[derive(Subcommand)]
enum ProfileCmd {
    /// Save a new connection profile (overwrites an existing one of the same name).
    Add {
        name: String,
        /// host or user@host
        target: String,
        #[arg(short, long)]
        user: Option<String>,
        #[arg(short = 'p', long)]
        port: Option<u16>,
        #[arg(long, value_enum)]
        auth: Option<AuthChoice>,
        #[arg(short = 'i', long)]
        identity: Option<PathBuf>,
        /// Local forward: [bind:]port:host:hostport (repeatable).
        #[arg(short = 'L', long = "local-forward", value_name = "SPEC")]
        local: Vec<String>,
        /// Remote forward: [bind:]port:host:hostport (repeatable).
        #[arg(short = 'R', long = "remote-forward", value_name = "SPEC")]
        remote: Vec<String>,
        /// Dynamic (SOCKS5) forward: [bind:]port (repeatable).
        #[arg(short = 'D', long = "dynamic-forward", value_name = "SPEC")]
        dynamic: Vec<String>,
    },
    /// List saved profiles.
    List,
    /// Print a saved profile's settings.
    Show { name: String },
    /// Delete a saved profile.
    Rm { name: String },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum KeyType {
    Ed25519,
    Rsa,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Connect {
            target,
            local,
            remote,
            dynamic,
        } => {
            let mut target = target.resolve()?;
            target
                .forwards
                .extend(parse_forwards(local, remote, dynamic)?);
            connect(target).await
        }
        Command::Profile { cmd } => match cmd {
            ProfileCmd::Add {
                name,
                target,
                user,
                port,
                auth,
                identity,
                local,
                remote,
                dynamic,
            } => {
                let forwards = parse_forwards(local, remote, dynamic)?;
                profile_add(name, target, user, port, auth, identity, forwards)
            }
            ProfileCmd::List => profile_list(),
            ProfileCmd::Show { name } => profile_show(name),
            ProfileCmd::Rm { name } => profile_rm(name),
        },
        Command::Sftp { target, operation } => {
            let mut session = connect_session(&target.resolve()?).await?;
            let result = match operation {
                Some(op) => sftp::run(&mut session, op).await,
                None => sftp::shell(&mut session).await,
            };
            session.disconnect().await.ok();
            result
        }
        Command::Keygen {
            output,
            comment,
            key_type,
            bits,
        } => keygen(output, &comment, key_type, bits),
    }
}

/// Converts `-L`/`-R`/`-D` flags into forward rules.
fn parse_forwards(
    local: Vec<String>,
    remote: Vec<String>,
    dynamic: Vec<String>,
) -> Result<Vec<ForwardRule>> {
    let mut rules = Vec::with_capacity(local.len() + remote.len() + dynamic.len());
    for spec in local {
        rules.push(parse_forward(&spec, ForwardKind::Local)?);
    }
    for spec in remote {
        rules.push(parse_forward(&spec, ForwardKind::Remote)?);
    }
    for spec in dynamic {
        rules.push(parse_forward(&spec, ForwardKind::Dynamic)?);
    }
    Ok(rules)
}

/// Connects and authenticates, prompting on the terminal for secrets and
/// unknown host keys as needed.
async fn connect_session(target: &Target) -> Result<Session> {
    let prompter = Arc::new(TtyPrompter);
    Session::connect(
        &target.host,
        target.port,
        &target.user,
        &target.auth,
        prompter.clone(),
        Arc::new(KnownHosts { prompter }),
    )
    .await
    .map_err(Into::into)
}

async fn connect(target: Target) -> Result<()> {
    let mut session = connect_session(&target).await?;

    let (cols, rows) = terminal::size().unwrap_or((80, 24));
    let term_type = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());
    let mut term = Terminal::new(cols as u32, rows as u32);

    let mut channel = session
        .open_shell(&term_type, cols as u32, rows as u32)
        .await
        .context("opening shell channel")?;

    let infos = tunnel::start_all(&mut session, &target.forwards).await?;
    for info in &infos {
        eprintln!("{info}");
    }

    terminal::enable_raw_mode().context("enabling raw terminal mode")?;
    let result = pump_shell_io(&mut channel, &mut term).await;
    terminal::disable_raw_mode().ok();

    session.disconnect().await.ok();
    result
}

async fn pump_shell_io(
    channel: &mut vortexssh_core::ssh::Channel<vortexssh_core::ssh::Msg>,
    term: &mut Terminal,
) -> Result<()> {
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut buf = [0u8; 4096];
    let mut stdin_closed = false;
    let mut resize = resize::stream();

    loop {
        tokio::select! {
            r = stdin.read(&mut buf), if !stdin_closed => {
                match r {
                    Ok(0) => {
                        stdin_closed = true;
                        channel.eof().await.ok();
                    }
                    Ok(n) => {
                        channel.data(&buf[..n]).await.ok();
                    }
                    Err(e) => bail!("reading local stdin: {e}"),
                }
            }
            msg = channel.wait() => {
                match msg {
                    Some(ChannelMsg::Data { data }) => {
                        term.feed(&data);
                        stdout.write_all(&data).await?;
                        stdout.flush().await?;
                    }
                    Some(ChannelMsg::ExtendedData { data, .. }) => {
                        stdout.write_all(&data).await?;
                        stdout.flush().await?;
                    }
                    Some(ChannelMsg::ExitStatus { .. }) | Some(ChannelMsg::Close) | None => {
                        break;
                    }
                    _ => {}
                }
            }
            _ = resize::wait(&mut resize) => {
                let (cols, rows) = terminal::size().unwrap_or((80, 24));
                term.resize(cols as u32, rows as u32);
                channel.window_change(cols as u32, rows as u32, 0, 0).await.ok();
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
mod resize {
    use tokio::signal::unix::{signal, SignalKind};

    pub type Stream = tokio::signal::unix::Signal;

    /// Install a SIGWINCH handler. Returns `None` if installation fails, in
    /// which case `wait` will never resolve and resize is simply disabled.
    pub fn stream() -> Option<Stream> {
        signal(SignalKind::window_change()).ok()
    }

    pub async fn wait(stream: &mut Option<Stream>) {
        match stream.as_mut() {
            Some(sig) => {
                sig.recv().await;
            }
            None => std::future::pending::<()>().await,
        }
    }
}

#[cfg(not(unix))]
mod resize {
    pub fn stream() -> Option<()> {
        None
    }

    pub async fn wait(_stream: &mut Option<()>) {
        std::future::pending::<()>().await;
    }
}

fn profile_add(
    name: String,
    target: String,
    user: Option<String>,
    port: Option<u16>,
    auth: Option<AuthChoice>,
    identity: Option<PathBuf>,
    forwards: Vec<ForwardRule>,
) -> Result<()> {
    let store = ProfileStore::default_location()?;
    let (default_user, host) = split_target(&target);
    let user = user.unwrap_or(default_user);
    let port = port.unwrap_or(22);
    let auth = auth_from_flags(auth, identity)?;

    let profile = Profile {
        name: name.clone(),
        host,
        port,
        user,
        auth,
        forwards,
        terminal: Default::default(),
    };
    store.save(&profile)?;
    println!("Saved profile '{name}'");
    Ok(())
}

fn profile_list() -> Result<()> {
    let store = ProfileStore::default_location()?;
    let names = store.list()?;
    if names.is_empty() {
        println!("No profiles saved.");
    } else {
        for name in names {
            println!("{name}");
        }
    }
    Ok(())
}

fn profile_show(name: String) -> Result<()> {
    let store = ProfileStore::default_location()?;
    let p = store
        .load(&name)
        .with_context(|| format!("loading profile '{name}'"))?;
    let auth = match &p.auth {
        AuthMethod::Password => "password".to_string(),
        AuthMethod::PublicKey { key_path, .. } => format!("public-key ({key_path})"),
        AuthMethod::Agent => "agent".to_string(),
        AuthMethod::KeyboardInteractive => "keyboard-interactive".to_string(),
    };
    println!("name:    {name}");
    println!("host:    {}:{}", p.host, p.port);
    println!("user:    {}", p.user);
    println!("auth:    {auth}");
    println!("term:    {}", p.terminal.term_type);
    if p.forwards.is_empty() {
        println!("forwards: (none)");
    } else {
        for rule in &p.forwards {
            println!("forwards: {rule}");
        }
    }
    Ok(())
}

fn profile_rm(name: String) -> Result<()> {
    let store = ProfileStore::default_location()?;
    store
        .delete(&name)
        .with_context(|| format!("deleting profile '{name}'"))?;
    println!("Deleted profile '{name}'");
    Ok(())
}

fn keygen(output: Option<PathBuf>, comment: &str, key_type: KeyType, bits: usize) -> Result<()> {
    use vortexssh_core::keys::{generate, save_openssh, HashAlg, KeyKind};

    let output = output.unwrap_or_else(|| match key_type {
        KeyType::Ed25519 => PathBuf::from("id_ed25519"),
        KeyType::Rsa => PathBuf::from("id_rsa"),
    });
    if output.exists() {
        bail!("{} already exists, refusing to overwrite", output.display());
    }

    let kind = match key_type {
        KeyType::Ed25519 => KeyKind::Ed25519,
        KeyType::Rsa => KeyKind::Rsa { bits },
    };
    let key = generate(kind, comment)?;
    save_openssh(&key, &output)?;

    let pub_path = output.with_extension("pub");
    let public = key.public_key();
    let mut pub_file = std::fs::File::create(&pub_path)?;
    writeln!(
        pub_file,
        "{}",
        public.to_openssh().context("encoding public key")?
    )?;

    println!("Private key written to {}", output.display());
    println!("Public key written to {}", pub_path.display());
    println!("Fingerprint: {}", public.fingerprint(HashAlg::Sha256));
    Ok(())
}
