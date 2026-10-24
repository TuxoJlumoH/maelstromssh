//! One browser tab = one WebSocket = one SSH connection, serial port, or
//! Telnet or raw TCP connection.
//!
//! The socket carries terminal bytes as binary frames and everything else
//! as JSON text frames:
//!
//! - browser → server: `connect`, `answer` (to a login prompt), `resize`,
//!   `break` (serial and Telnet), `sftp` and `forward_add` / `forward_stop`
//!   requests (each with an `id` that the `reply` echoes);
//! - server → browser: `ask` (a login prompt) and `ask_cancel` (it timed
//!   out), `warning`, `ready`, `reply`, `forwards` (the current list) and
//!   `closed`.
//!
//! Downloads and uploads are plain HTTP requests (see `api`) that find the
//! connection by the id sent in `ready`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc as std_mpsc, Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use maelstromssh_core::config::{
    forward_spec, parse_forward, ForwardKind, ForwardRule, Protocol, SerialSettings,
};
use maelstromssh_core::prompt::{KiPrompt, Prompter};
use maelstromssh_core::serial::Line;
use maelstromssh_core::session_log::SessionLog;
use maelstromssh_core::sftp::{self, SftpSession};
use maelstromssh_core::ssh::{ChannelMsg, KnownHosts, Session};
use maelstromssh_core::target::{Target, TargetArgs};
use maelstromssh_core::tcp::TcpLine;
use maelstromssh_core::tunnel::{ActiveForward, ForwardInfo, Forwarder};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, OnceCell};
use tokio_util::sync::CancellationToken;

use crate::App;

const TERM_TYPE: &str = "xterm-256color";

/// A connected session and what runs on it besides the shell.
pub struct Conn {
    pub session: Session,
    sftp: OnceCell<SftpSession>,
    forwarder: Forwarder,
    /// `None` once the connection is closing, so a forward that finishes
    /// starting after that is stopped instead of kept.
    forwards: tokio::sync::Mutex<Option<Vec<RunningForward>>>,
    next_forward: AtomicU64,
}

struct RunningForward {
    id: u64,
    kind: ForwardKind,
    spec: String,
    active: ActiveForward,
}

impl Conn {
    /// The SFTP subsystem, opened on first use.
    pub async fn sftp(&self) -> maelstromssh_core::Result<&SftpSession> {
        self.sftp
            .get_or_try_init(|| sftp::open(&self.session))
            .await
    }

    async fn add_forward(&self, rule: &ForwardRule) -> maelstromssh_core::Result<()> {
        let active = self.forwarder.start(rule).await?;
        let mut forwards = self.forwards.lock().await;
        let Some(list) = forwards.as_mut() else {
            drop(forwards);
            let _ = active.stop().await;
            return Err(maelstromssh_core::Error::Other(
                "the connection is closed".into(),
            ));
        };
        list.push(RunningForward {
            id: self.next_forward.fetch_add(1, Ordering::Relaxed),
            kind: rule.kind,
            spec: forward_spec(rule),
            active,
        });
        Ok(())
    }

    async fn stop_forward(&self, id: u64) -> maelstromssh_core::Result<()> {
        let running = {
            let mut forwards = self.forwards.lock().await;
            let list = forwards.as_mut();
            list.and_then(|l| l.iter().position(|f| f.id == id).map(|i| l.remove(i)))
        };
        match running {
            Some(f) => f.active.stop().await,
            None => Ok(()),
        }
    }

    async fn stop_all_forwards(&self) {
        let list = self.forwards.lock().await.take().unwrap_or_default();
        for f in list {
            let _ = f.active.stop().await;
        }
    }

    async fn forward_list(&self) -> Value {
        let forwards = self.forwards.lock().await;
        Value::Array(
            forwards
                .iter()
                .flatten()
                .map(|f| {
                    let (listen, dest) = match &f.active.info {
                        ForwardInfo::Local { local, dest } => (local.to_string(), dest.clone()),
                        ForwardInfo::Remote { port, dest } => {
                            (format!("server port {port}"), dest.clone())
                        }
                        ForwardInfo::Dynamic { local } => (local.to_string(), "SOCKS5".into()),
                    };
                    json!({ "id": f.id, "kind": f.kind, "spec": f.spec,
                            "listen": listen, "dest": dest })
                })
                .collect(),
        )
    }
}

/// JSON messages for the browser. Terminal output goes through a separate
/// bounded queue (`TermTx`) so a slow browser slows the shell down instead
/// of filling memory.
type OutTx = mpsc::UnboundedSender<Value>;

/// Terminal output frames waiting for the browser.
type TermTx = mpsc::Sender<Vec<u8>>;

/// Where a session's terminal output goes: the browser, and the log if
/// there is one.
struct TermOut {
    tx: TermTx,
    log: Option<SessionLog>,
    /// For reporting a failed log write.
    out: OutTx,
}

impl TermOut {
    /// Queues output for the browser; check [`capacity`](Self::capacity)
    /// first. Fails once the tab has gone.
    fn send(&mut self, data: Vec<u8>) -> Result<(), ()> {
        if let Some(log) = &mut self.log {
            log.write(&data);
            if let Some(e) = log.take_error() {
                send(&self.out, json!({ "type": "warning", "message": e }));
            }
        }
        self.tx.try_send(data).map_err(|_| ())
    }

    fn capacity(&self) -> usize {
        self.tx.capacity()
    }

    async fn reserve(&self) -> Result<(), ()> {
        self.tx.reserve().await.map(drop).map_err(|_| ())
    }

    /// The log file, as shown to the user.
    fn log_path(&self) -> Option<String> {
        let log = self.log.as_ref()?;
        Some(maelstromssh_core::paths::collapse_home(log.path()))
    }
}

/// How many terminal frames may wait for the browser before the shell stops
/// reading from the server. Frames are at most one SSH packet (~32 KiB).
const TERM_QUEUE: usize = 64;

/// How long closing a connection may take before it is abandoned.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a login prompt waits for an answer before giving up.
const PROMPT_TIMEOUT: Duration = Duration::from_secs(300);

fn send(out: &OutTx, value: Value) {
    let _ = out.send(value);
}

/// Input for the shell or serial port.
enum Input {
    Data(Vec<u8>),
    Resize {
        cols: u32,
        rows: u32,
    },
    /// A serial or Telnet break; the reply goes to request `id`.
    Break(u64),
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum In {
    Connect {
        #[serde(default)]
        target: Option<String>,
        #[serde(default)]
        port: Option<u16>,
        #[serde(default)]
        identity: Option<String>,
        #[serde(default)]
        profile: Option<String>,
        /// Open a serial port instead of an SSH connection.
        #[serde(default)]
        serial: Option<SerialForm>,
        /// Open a Telnet or raw TCP connection instead.
        #[serde(default)]
        tcp: Option<TcpForm>,
        /// Save the session output in the log folder.
        #[serde(default)]
        log: bool,
        cols: u32,
        rows: u32,
    },
    Answer {
        id: u64,
        #[serde(default)]
        value: Value,
    },
    Resize {
        cols: u32,
        rows: u32,
    },
    Break {
        id: u64,
    },
    Sftp {
        id: u64,
        #[serde(flatten)]
        op: SftpOp,
    },
    ForwardAdd {
        id: u64,
        kind: ForwardKind,
        spec: String,
    },
    ForwardStop {
        id: u64,
        forward: u64,
    },
}

#[derive(Deserialize)]
struct SerialForm {
    device: String,
    #[serde(flatten)]
    settings: SerialSettings,
}

#[derive(Deserialize)]
struct TcpForm {
    protocol: Protocol,
    host: String,
    #[serde(default)]
    port: Option<u16>,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum SftpOp {
    List { path: String },
    Mkdir { path: String },
    Remove { path: String, dir: bool },
    Rename { from: String, to: String },
}

/// Login prompts, answered in the browser. Prompts may block (they run on
/// blocking threads or briefly on a runtime worker), like the GUI's.
struct WebPrompter {
    out: OutTx,
    pending: Pending,
    next: AtomicU64,
}

/// Open prompts by id; `None` once the tab has closed, so no new prompt can
/// start waiting for an answer that will never come.
type Pending = Arc<Mutex<Option<HashMap<u64, std_mpsc::Sender<Value>>>>>;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl WebPrompter {
    /// Sends the question and waits for the answer; `None` if the tab closed.
    fn ask(&self, mut question: Value) -> Option<Value> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = std_mpsc::channel();
        lock(&self.pending).as_mut()?.insert(id, tx);
        question["type"] = "ask".into();
        question["id"] = id.into();
        // Prompts block a thread, so they give up after a while rather than
        // holding it for as long as the dialog stays open.
        let answer = if self.out.send(question).is_ok() {
            let answer = rx.recv_timeout(PROMPT_TIMEOUT).ok();
            if answer.is_none() {
                send(&self.out, json!({ "type": "ask_cancel", "id": id }));
            }
            answer
        } else {
            None
        };
        if let Some(map) = lock(&self.pending).as_mut() {
            map.remove(&id);
        }
        answer
    }
}

impl Prompter for WebPrompter {
    fn secret(&self, prompt: &str) -> Option<String> {
        let answer = self.ask(json!({ "kind": "secret", "prompt": prompt }))?;
        answer.as_str().map(str::to_owned)
    }

    fn confirm_host_key(&self, host: &str, port: u16, fingerprint: &str) -> bool {
        let question = json!({ "kind": "host_key", "host": host, "port": port,
                               "fingerprint": fingerprint });
        self.ask(question).and_then(|a| a.as_bool()) == Some(true)
    }

    fn keyboard_interactive(
        &self,
        name: &str,
        instructions: &str,
        prompts: &[KiPrompt],
    ) -> Option<Vec<String>> {
        let prompts: Vec<Value> = prompts
            .iter()
            .map(|p| json!({ "text": p.text, "echo": p.echo }))
            .collect();
        let answer = self.ask(json!({ "kind": "keyboard_interactive", "name": name,
                                      "instructions": instructions, "prompts": prompts }))?;
        let answers: Vec<String> = answer
            .as_array()?
            .iter()
            .map(|v| v.as_str().map(str::to_owned))
            .collect::<Option<_>>()?;
        (answers.len() == prompts.len()).then_some(answers)
    }
}

pub async fn ws(State(app): State<Arc<App>>, upgrade: WebSocketUpgrade) -> Response {
    upgrade
        .max_message_size(1 << 20)
        .protocols([crate::auth::WS_PROTOCOL])
        .on_upgrade(move |socket| run(app, socket))
}

async fn run(app: Arc<App>, socket: WebSocket) {
    let (mut sink, mut stream) = socket.split();
    let (out, mut out_rx) = mpsc::unbounded_channel::<Value>();
    let (term_tx, mut term_rx) = mpsc::channel::<Vec<u8>>(TERM_QUEUE);
    let writer = tokio::spawn(async move {
        loop {
            // JSON first, so prompts and replies are not stuck behind output.
            let msg = tokio::select! {
                biased;
                Some(v) = out_rx.recv() => Message::Text(v.to_string().into()),
                Some(b) = term_rx.recv() => Message::Binary(b.into()),
                else => break,
            };
            if sink.send(msg).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });
    let mut term_tx = Some(term_tx);

    let pending: Pending = Arc::new(Mutex::new(Some(HashMap::new())));
    let conn: Arc<OnceLock<Arc<Conn>>> = Arc::default();
    let (input_tx, input_rx) = mpsc::unbounded_channel::<Input>();
    let mut input_rx = Some(input_rx);
    let mut session_task = None;
    let cancel = CancellationToken::new();

    while let Some(msg) = stream.next().await {
        let msg = match msg {
            Ok(msg) => msg,
            Err(e) => {
                tracing::warn!("browser connection failed: {e}");
                break;
            }
        };
        let text = match msg {
            Message::Binary(bytes) => {
                let _ = input_tx.send(Input::Data(bytes.to_vec()));
                continue;
            }
            Message::Text(text) => text,
            Message::Close(_) => break,
            _ => continue,
        };
        let request = match serde_json::from_str::<In>(&text) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("bad message from the browser: {e}");
                // Answer it, so the page does not wait forever.
                let message: Value = serde_json::from_str(&text).unwrap_or_default();
                if let Some(id) = message.get("id").and_then(Value::as_u64) {
                    reply(&out, id, Err(format!("bad request: {e}")));
                } else if message.get("type").and_then(Value::as_str) == Some("connect") {
                    send(
                        &out,
                        json!({ "type": "closed", "reason": format!("bad request: {e}") }),
                    );
                }
                continue;
            }
        };
        match request {
            In::Connect {
                target,
                port,
                identity,
                profile,
                serial,
                tcp,
                log,
                cols,
                rows,
            } => {
                let (Some(input), Some(term)) = (input_rx.take(), term_tx.take()) else {
                    continue; // already connecting
                };
                let args = match (serial, tcp) {
                    (Some(form), _) => {
                        Request::Direct(Target::serial(form.device.trim(), form.settings))
                    }
                    (None, Some(form)) => {
                        let port = form.port.or(form.protocol.default_port()).unwrap_or(0);
                        Request::Direct(Target::tcp(form.protocol, form.host.trim(), port))
                    }
                    (None, None) => Request::Args(TargetArgs {
                        target: target.filter(|t| !t.trim().is_empty()),
                        port,
                        identity: identity.filter(|i| !i.trim().is_empty()).map(Into::into),
                        profile: profile.filter(|p| !p.is_empty()),
                        auth: None,
                    }),
                };
                let prompter = Arc::new(WebPrompter {
                    out: out.clone(),
                    pending: pending.clone(),
                    next: AtomicU64::new(1),
                });
                let tab = Tab {
                    term,
                    log,
                    input,
                    cancel: cancel.clone(),
                };
                session_task = Some(tokio::spawn(run_session(
                    app.clone(),
                    args,
                    (cols, rows),
                    prompter,
                    tab,
                    conn.clone(),
                )));
            }
            In::Answer { id, value } => {
                let tx = lock(&pending).as_mut().and_then(|m| m.remove(&id));
                if let Some(tx) = tx {
                    let _ = tx.send(value);
                }
            }
            In::Resize { cols, rows } => {
                let _ = input_tx.send(Input::Resize { cols, rows });
            }
            In::Break { id } => {
                if input_tx.send(Input::Break(id)).is_err() {
                    reply(&out, id, Err("not connected".into()));
                }
            }
            In::Sftp { id, op } => {
                let Some(conn) = conn.get().cloned() else {
                    reply(&out, id, Err("not connected".into()));
                    continue;
                };
                let out = out.clone();
                tokio::spawn(async move {
                    let result = sftp_op(&conn, op).await.map_err(|e| e.to_string());
                    reply(&out, id, result);
                });
            }
            In::ForwardAdd { id, kind, spec } => {
                let Some(conn) = conn.get().cloned() else {
                    reply(&out, id, Err("not connected".into()));
                    continue;
                };
                let out = out.clone();
                tokio::spawn(async move {
                    let result = match parse_forward(spec.trim(), kind) {
                        Ok(rule) => conn.add_forward(&rule).await.map_err(|e| e.to_string()),
                        Err(e) => Err(e.to_string()),
                    };
                    reply(&out, id, result.map(|()| Value::Null));
                    send(
                        &out,
                        json!({ "type": "forwards", "list": conn.forward_list().await }),
                    );
                });
            }
            In::ForwardStop { id, forward } => {
                let Some(conn) = conn.get().cloned() else {
                    reply(&out, id, Err("not connected".into()));
                    continue;
                };
                let out = out.clone();
                tokio::spawn(async move {
                    let result = conn.stop_forward(forward).await.map_err(|e| e.to_string());
                    reply(&out, id, result.map(|()| Value::Null));
                    send(
                        &out,
                        json!({ "type": "forwards", "list": conn.forward_list().await }),
                    );
                });
            }
        }
    }

    // The tab is gone: cancel any open prompt and end the session, which
    // then stops the forwards and disconnects.
    lock(&pending).take();
    drop(input_tx);
    cancel.cancel();
    if let Some(task) = session_task {
        if tokio::time::timeout(SHUTDOWN_TIMEOUT * 2, task)
            .await
            .is_err()
        {
            tracing::warn!("a session did not shut down in time");
        }
    }
    writer.abort();
}

fn reply(out: &OutTx, id: u64, result: Result<Value, String>) {
    let msg = match result {
        Ok(data) => json!({ "type": "reply", "id": id, "ok": true, "data": data }),
        Err(error) => json!({ "type": "reply", "id": id, "ok": false, "error": error }),
    };
    send(out, msg);
}

async fn sftp_op(conn: &Conn, op: SftpOp) -> maelstromssh_core::Result<Value> {
    let sftp = conn.sftp().await?;
    Ok(match op {
        SftpOp::List { path } => {
            let path = if path.is_empty() { "." } else { &path };
            let path = sftp::canonicalize(sftp, path).await?;
            let entries: Vec<Value> = sftp::list(sftp, &path)
                .await?
                .into_iter()
                .filter(|e| e.name != "." && e.name != "..")
                .map(|e| {
                    json!({ "name": e.name, "dir": e.is_dir, "link": e.is_symlink,
                            "size": e.size, "mtime": e.modified, "perm": e.permissions })
                })
                .collect();
            json!({ "path": path, "entries": entries })
        }
        SftpOp::Mkdir { path } => {
            sftp::create_dir(sftp, &path).await?;
            Value::Null
        }
        SftpOp::Remove { path, dir } => {
            if dir {
                sftp::remove_dir(sftp, &path).await?;
            } else {
                sftp::remove_file(sftp, &path).await?;
            }
            Value::Null
        }
        SftpOp::Rename { from, to } => {
            sftp::rename(sftp, &from, &to).await?;
            Value::Null
        }
    })
}

/// The browser tab's side of a session: where terminal output goes, where
/// keyboard input comes from, and the signal that the tab has closed.
struct Tab {
    term: TermTx,
    /// Whether to log the session output.
    log: bool,
    input: mpsc::UnboundedReceiver<Input>,
    cancel: CancellationToken,
}

/// What the tab asked to connect to.
enum Request {
    /// A host or profile, resolved like the CLI does.
    Args(TargetArgs),
    /// A serial port or Telnet/raw host given in the dialog.
    Direct(Target),
}

/// Connects, runs the shell until it exits or the tab closes, then cleans up.
async fn run_session(
    app: Arc<App>,
    request: Request,
    (cols, rows): (u32, u32),
    prompter: Arc<WebPrompter>,
    tab: Tab,
    slot: Arc<OnceLock<Arc<Conn>>>,
) {
    let Tab {
        term,
        log,
        mut input,
        cancel,
    } = tab;
    let out = prompter.out.clone();
    let closed = |reason: String| send(&out, json!({ "type": "closed", "reason": reason }));

    let target = match request {
        Request::Direct(target) => target,
        Request::Args(args) => {
            match tokio::task::spawn_blocking(move || args.resolve_any()).await {
                Ok(Ok(target)) => target,
                Ok(Err(e)) => return closed(e.to_string()),
                Err(e) => return closed(e.to_string()),
            }
        }
    };
    let log = if log {
        let (label, host, port) = (target.label(), target.host.clone(), target.port);
        match tokio::task::spawn_blocking(move || SessionLog::create_default(&label, &host, port))
            .await
        {
            Ok(Ok(log)) => Some(log),
            Ok(Err(e)) => return closed(e.to_string()),
            Err(e) => return closed(e.to_string()),
        }
    } else {
        None
    };
    let mut term = TermOut {
        tx: term,
        log,
        out: out.clone(),
    };
    match target.protocol {
        Protocol::Ssh => {}
        Protocol::Serial => return closed(run_serial(&target, &out, term, input, cancel).await),
        Protocol::Telnet | Protocol::Raw => {
            let size = (clamp_u16(cols), clamp_u16(rows));
            return closed(run_tcp(&target, size, &out, term, input, cancel).await);
        }
    }
    for warning in &target.warnings {
        send(&out, json!({ "type": "warning", "message": warning }));
    }
    // A server that stalls the handshake would otherwise keep this task
    // (and the tab's resources) forever, even after the tab is closed.
    let connected = tokio::select! {
        r = Session::connect(
            &target.host,
            target.port,
            &target.user,
            &target.auth,
            prompter.clone(),
            Arc::new(KnownHosts {
                prompter: prompter.clone(),
            }),
        ) => r,
        _ = cancel.cancelled() => return,
    };
    let mut session = match connected {
        Ok(s) => s,
        Err(e) => return closed(e.to_string()),
    };
    let shell = tokio::select! {
        r = session.open_shell(TERM_TYPE, cols, rows) => r,
        _ = cancel.cancelled() => Err(maelstromssh_core::Error::Other("closed".into())),
    };
    let channel = match shell {
        Ok(c) => c,
        Err(e) => {
            let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, session.disconnect()).await;
            return closed(format!("opening a shell: {e}"));
        }
    };
    let forwarder = Forwarder::new(&mut session);
    let conn = Arc::new(Conn {
        session,
        sftp: OnceCell::new(),
        forwarder,
        forwards: tokio::sync::Mutex::new(Some(Vec::new())),
        next_forward: AtomicU64::new(1),
    });
    let id = app.next_id.fetch_add(1, Ordering::Relaxed);
    lock(&app.conns).insert(id, conn.clone());
    let _ = slot.set(conn.clone());

    for rule in &target.forwards {
        if let Err(e) = conn.add_forward(rule).await {
            let message = format!("forward {rule}: {e}");
            send(&out, json!({ "type": "warning", "message": message }));
        }
    }
    send(
        &out,
        json!({ "type": "ready", "conn": id, "label": target.label(),
                "forwards": conn.forward_list().await, "log": term.log_path() }),
    );

    // Keyboard input gets its own task: writing can wait on the server (a
    // full SSH window, or russh's queue while this side is not reading
    // output), and it must never stop the loop below from reading, or the
    // two would wait on each other forever.
    let (mut reader, writer) = channel.split();
    let typing_out = out.clone();
    let mut typing = tokio::spawn(async move {
        let out = typing_out;
        while let Some(cmd) = input.recv().await {
            match cmd {
                Input::Data(bytes) => {
                    if writer.data(&bytes[..]).await.is_err() {
                        return false;
                    }
                }
                Input::Resize { cols, rows } => {
                    let _ = writer.window_change(cols, rows, 0, 0).await;
                }
                Input::Break(id) => reply(&out, id, Err("SSH has no break signal here".into())),
            }
        }
        true // the tab closed
    });

    let mut exit_status = None;
    let reason = loop {
        tokio::select! {
            _ = cancel.cancelled() => break "closed".to_string(),
            done = &mut typing => break match done {
                Ok(true) => "closed".to_string(),
                _ => "The connection was lost.".to_string(),
            },
            // Only read more output while the browser keeps up.
            msg = reader.wait(), if term.capacity() > 0 => match msg {
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                    if term.send(data.to_vec()).is_err() {
                        break "closed".to_string();
                    }
                }
                Some(ChannelMsg::ExitStatus { exit_status: code }) => exit_status = Some(code),
                Some(ChannelMsg::Close) | None => break match exit_status {
                    None if conn.session.is_closed() => "The connection was lost.".to_string(),
                    Some(0) | None => "The remote shell exited.".to_string(),
                    Some(code) => format!("The remote shell exited with status {code}."),
                },
                _ => {}
            },
            space = term.reserve(), if term.capacity() == 0 => {
                if space.is_err() {
                    break "closed".to_string();
                }
            }
        }
    };
    typing.abort();
    // Dropping the reader unblocks russh if it waits to hand us output.
    drop(reader);

    lock(&app.conns).remove(&id);
    let cleanup = async {
        conn.stop_all_forwards().await;
        let _ = conn.session.disconnect().await;
    };
    if tokio::time::timeout(SHUTDOWN_TIMEOUT, cleanup)
        .await
        .is_err()
    {
        tracing::warn!("disconnecting timed out");
    }
    closed(reason);
}

/// Runs a serial port until the tab closes or the port fails; returns why
/// it ended.
async fn run_serial(
    target: &Target,
    out: &OutTx,
    mut term: TermOut,
    mut input: mpsc::UnboundedReceiver<Input>,
    cancel: CancellationToken,
) -> String {
    let settings = target.serial.unwrap_or_default();
    let device = target.host.clone();
    let line = match tokio::task::spawn_blocking(move || Line::open(&device, &settings)).await {
        Ok(Ok(line)) => line,
        Ok(Err(e)) => return e.to_string(),
        Err(e) => return e.to_string(),
    };
    let Line {
        mut reader,
        mut writer,
        breaker,
    } = line;
    send(
        out,
        json!({ "type": "ready", "conn": null, "protocol": "serial", "label": target.label(),
                "forwards": [], "log": term.log_path() }),
    );

    // Writing can wait on the device (flow control); it must not stop
    // output from being read.
    let typing_out = out.clone();
    let mut typing = tokio::spawn(async move {
        while let Some(cmd) = input.recv().await {
            match cmd {
                Input::Data(bytes) => {
                    if writer.write_all(&bytes).await.is_err() || writer.flush().await.is_err() {
                        return false;
                    }
                }
                Input::Resize { .. } => {}
                Input::Break(id) => {
                    let breaker = breaker.clone();
                    let result = match tokio::task::spawn_blocking(move || breaker.send()).await {
                        Ok(r) => r.map(|()| Value::Null).map_err(|e| e.to_string()),
                        Err(e) => Err(e.to_string()),
                    };
                    reply(&typing_out, id, result);
                }
            }
        }
        true // the tab closed
    });

    let mut buf = vec![0u8; 16 * 1024];
    let reason = loop {
        tokio::select! {
            _ = cancel.cancelled() => break "closed".to_string(),
            done = &mut typing => break match done {
                Ok(true) => "closed".to_string(),
                _ => "Writing to the serial port failed.".to_string(),
            },
            // Only read more output while the browser keeps up.
            r = reader.read(&mut buf), if term.capacity() > 0 => match r {
                Ok(0) => break "The serial port closed.".to_string(),
                Ok(n) => {
                    if term.send(buf[..n].to_vec()).is_err() {
                        break "closed".to_string();
                    }
                }
                Err(e) => break format!("Reading the serial port failed: {e}"),
            },
            space = term.reserve(), if term.capacity() == 0 => {
                if space.is_err() {
                    break "closed".to_string();
                }
            }
        }
    };
    typing.abort();
    reason
}

fn clamp_u16(v: u32) -> u16 {
    v.min(u16::MAX as u32) as u16
}

/// Runs a Telnet or raw TCP connection until the tab closes or the server
/// hangs up; returns why it ended.
async fn run_tcp(
    target: &Target,
    size: (u16, u16),
    out: &OutTx,
    mut term: TermOut,
    mut input: mpsc::UnboundedReceiver<Input>,
    cancel: CancellationToken,
) -> String {
    let protocol = target.protocol;
    let connecting = TcpLine::connect(protocol, &target.host, target.port, "xterm-256color", size);
    let line = tokio::select! {
        r = connecting => match r {
            Ok(line) => line,
            Err(e) => return e.to_string(),
        },
        _ = cancel.cancelled() => return "closed".to_string(),
    };
    let TcpLine {
        mut reader,
        mut writer,
        mut filter,
    } = line;
    send(
        out,
        json!({ "type": "ready", "conn": null, "protocol": protocol.name(),
                "label": target.label(), "forwards": [], "log": term.log_path() }),
    );

    // The server may be slow to read; writes queue here instead of
    // stopping output. Typing and Telnet replies are small.
    let (wire, mut wire_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut writing = tokio::spawn(async move {
        while let Some(bytes) = wire_rx.recv().await {
            writer.write_all(&bytes).await?;
        }
        std::io::Result::Ok(())
    });

    let mut buf = vec![0u8; 16 * 1024];
    let reason = loop {
        tokio::select! {
            _ = cancel.cancelled() => break "closed".to_string(),
            done = &mut writing => break match done {
                Ok(Err(e)) => format!("Sending to the server failed: {e}"),
                _ => "closed".to_string(),
            },
            cmd = input.recv() => {
                let Some(cmd) = cmd else { break "closed".to_string() };
                let bytes = match cmd {
                    Input::Data(bytes) => Some(filter.encode(&bytes)),
                    Input::Resize { cols, rows } => filter.resize(clamp_u16(cols), clamp_u16(rows)),
                    Input::Break(id) => {
                        let brk = filter.brk();
                        let result = match brk {
                            Some(_) => Ok(Value::Null),
                            None => Err("raw connections have no break signal".to_string()),
                        };
                        reply(out, id, result);
                        brk
                    }
                };
                if let Some(bytes) = bytes {
                    let _ = wire.send(bytes);
                }
            }
            // Only read more output while the browser keeps up.
            r = reader.read(&mut buf), if term.capacity() > 0 => match r {
                Ok(0) => break "The server closed the connection.".to_string(),
                Ok(n) => {
                    let (mut data, mut answer) = (Vec::with_capacity(n), Vec::new());
                    filter.receive(&buf[..n], &mut data, &mut answer);
                    if !answer.is_empty() {
                        let _ = wire.send(answer);
                    }
                    if !data.is_empty() && term.send(data).is_err() {
                        break "closed".to_string();
                    }
                }
                Err(e) => break format!("Reading from the server failed: {e}"),
            },
            space = term.reserve(), if term.capacity() == 0 => {
                if space.is_err() {
                    break "closed".to_string();
                }
            }
        }
    };
    writing.abort();
    reason
}
