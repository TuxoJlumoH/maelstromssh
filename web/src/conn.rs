//! One browser tab = one WebSocket = one SSH connection or serial port.
//!
//! The socket carries terminal bytes as binary frames and everything else
//! as JSON text frames:
//!
//! - browser → server: `connect`, `answer` (to a login prompt), `resize`,
//!   `break` (serial only), `sftp` and `forward_add` / `forward_stop`
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
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, OnceCell};
use tokio_util::sync::CancellationToken;
use vortexssh_core::config::{
    forward_spec, parse_forward, ForwardKind, ForwardRule, Protocol, SerialSettings,
};
use vortexssh_core::prompt::{KiPrompt, Prompter};
use vortexssh_core::serial::Line;
use vortexssh_core::sftp::{self, SftpSession};
use vortexssh_core::ssh::{ChannelMsg, KnownHosts, Session};
use vortexssh_core::target::{Target, TargetArgs};
use vortexssh_core::tunnel::{ActiveForward, ForwardInfo, Forwarder};

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
    pub async fn sftp(&self) -> vortexssh_core::Result<&SftpSession> {
        self.sftp
            .get_or_try_init(|| sftp::open(&self.session))
            .await
    }

    async fn add_forward(&self, rule: &ForwardRule) -> vortexssh_core::Result<()> {
        let active = self.forwarder.start(rule).await?;
        let mut forwards = self.forwards.lock().await;
        let Some(list) = forwards.as_mut() else {
            drop(forwards);
            let _ = active.stop().await;
            return Err(vortexssh_core::Error::Other(
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

    async fn stop_forward(&self, id: u64) -> vortexssh_core::Result<()> {
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
    /// A serial break; the reply goes to request `id`.
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
                cols,
                rows,
            } => {
                let (Some(input), Some(term)) = (input_rx.take(), term_tx.take()) else {
                    continue; // already connecting
                };
                let args = match serial {
                    Some(form) => {
                        Request::Serial(Target::serial(form.device.trim(), form.settings))
                    }
                    None => Request::Args(TargetArgs {
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

async fn sftp_op(conn: &Conn, op: SftpOp) -> vortexssh_core::Result<Value> {
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
    input: mpsc::UnboundedReceiver<Input>,
    cancel: CancellationToken,
}

/// What the tab asked to connect to.
enum Request {
    /// A host or profile, resolved like the CLI does.
    Args(TargetArgs),
    /// A serial port given in the dialog.
    Serial(Target),
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
        mut input,
        cancel,
    } = tab;
    let out = prompter.out.clone();
    let closed = |reason: String| send(&out, json!({ "type": "closed", "reason": reason }));

    let target = match request {
        Request::Serial(target) => target,
        Request::Args(args) => {
            match tokio::task::spawn_blocking(move || args.resolve_any()).await {
                Ok(Ok(target)) => target,
                Ok(Err(e)) => return closed(e.to_string()),
                Err(e) => return closed(e.to_string()),
            }
        }
    };
    if target.protocol == Protocol::Serial {
        let reason = run_serial(&target, &out, term, input, cancel).await;
        return closed(reason);
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
        _ = cancel.cancelled() => Err(vortexssh_core::Error::Other("closed".into())),
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
                "forwards": conn.forward_list().await }),
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
                Input::Break(id) => reply(&out, id, Err("breaks are for serial ports".into())),
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
                    if term.try_send(data.to_vec()).is_err() {
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
    term: TermTx,
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
                "forwards": [] }),
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
                    if term.try_send(buf[..n].to_vec()).is_err() {
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
