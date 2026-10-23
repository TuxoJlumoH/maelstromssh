//! Local / remote / dynamic (SOCKS5) port forwarding.
//!
//! Local and dynamic forwards bind a local listener and open `direct-tcpip`
//! channels for each connection; remote forwards ask the server to listen and
//! bridge the channels the server pushes back via [`ServerEvent`]s. Bridging
//! streams two endpoints (a TCP stream and an SSH channel) in both directions.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::task::AbortHandle;

use crate::config::{ForwardKind, ForwardRule};
use crate::error::{Error, Result};
use crate::ssh::{Channel, ChannelMsg, ClientHandle, Msg, ServerEvent, Session};

const BUF_SIZE: usize = 64 * 1024;

/// A summary of one started forward, reported back to the front-end.
pub enum ForwardInfo {
    Local { local: SocketAddr, dest: String },
    Remote { port: u16, dest: String },
    Dynamic { local: SocketAddr },
}

impl fmt::Display for ForwardInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ForwardInfo::Local { local, dest } => {
                write!(f, "Local forward: {local} -> {dest}")
            }
            ForwardInfo::Remote { port, dest } => {
                write!(f, "Remote forward: :{port} -> {dest}")
            }
            ForwardInfo::Dynamic { local } => {
                write!(f, "SOCKS5 proxy: {local}")
            }
        }
    }
}

/// Starts every forward in `rules` against the session, returning a summary
/// line per forward. Detached background tasks carry a cloned [`ClientHandle`]
/// and keep running for the life of the session.
pub async fn start_all(session: &mut Session, rules: &[ForwardRule]) -> Result<Vec<ForwardInfo>> {
    let forwarder = Forwarder::new(session);
    let mut infos = Vec::new();
    for rule in rules {
        infos.push(forwarder.start(rule).await?.info);
    }
    Ok(infos)
}

/// Remote-forward destinations, keyed by the port the server listens on.
type RemoteMap = Arc<Mutex<HashMap<u16, (String, u16)>>>;

/// Starts and stops individual forwards on one session, for front-ends that
/// manage forwards while connected.
pub struct Forwarder {
    handle: ClientHandle,
    /// `None` when the session's server events were already taken, so
    /// remote forwards cannot be dispatched.
    remote: Option<RemoteMap>,
}

/// A running forward. Dropping it leaves the forward running; call
/// [`ActiveForward::stop`] to end it.
pub struct ActiveForward {
    pub info: ForwardInfo,
    stop: Stop,
}

enum Stop {
    Listener(AbortHandle),
    Remote {
        handle: ClientHandle,
        bind_host: String,
        port: u16,
        map: RemoteMap,
    },
}

impl Forwarder {
    /// Takes the session's server-event stream to dispatch remote forwards.
    pub fn new(session: &mut Session) -> Self {
        let remote = session.take_events().map(|rx| {
            let map = RemoteMap::default();
            tokio::spawn(remote_dispatcher(rx, map.clone()));
            map
        });
        Self {
            handle: session.handle(),
            remote,
        }
    }

    pub async fn start(&self, rule: &ForwardRule) -> Result<ActiveForward> {
        let dest_host = rule.dest_host.clone().unwrap_or_else(|| "127.0.0.1".into());
        let dest_port = rule.dest_port.unwrap_or(0);
        let dest = format!("{dest_host}:{dest_port}");
        Ok(match rule.kind {
            ForwardKind::Local => {
                let listener = bind(&rule.bind_host, rule.bind_port).await?;
                let local = listener.local_addr()?;
                let task = tokio::spawn(serve_local(
                    listener,
                    self.handle.clone(),
                    dest_host,
                    dest_port,
                ));
                ActiveForward {
                    info: ForwardInfo::Local { local, dest },
                    stop: Stop::Listener(task.abort_handle()),
                }
            }
            ForwardKind::Dynamic => {
                let listener = bind(&rule.bind_host, rule.bind_port).await?;
                let local = listener.local_addr()?;
                let task = tokio::spawn(serve_dynamic(listener, self.handle.clone()));
                ActiveForward {
                    info: ForwardInfo::Dynamic { local },
                    stop: Stop::Listener(task.abort_handle()),
                }
            }
            ForwardKind::Remote => {
                let map = self.remote.clone().ok_or_else(|| {
                    Error::Other("remote forwarding is not available on this session".into())
                })?;
                let bound = self
                    .handle
                    .tcpip_forward(&rule.bind_host, rule.bind_port)
                    .await?;
                let port = if rule.bind_port == 0 {
                    bound
                } else {
                    rule.bind_port
                };
                map.lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(port, (dest_host, dest_port));
                ActiveForward {
                    info: ForwardInfo::Remote { port, dest },
                    stop: Stop::Remote {
                        handle: self.handle.clone(),
                        bind_host: rule.bind_host.clone(),
                        port,
                        map,
                    },
                }
            }
        })
    }
}

impl ActiveForward {
    /// Stops accepting new connections; connections already open keep
    /// running until they close.
    pub async fn stop(self) -> Result<()> {
        match self.stop {
            Stop::Listener(task) => task.abort(),
            Stop::Remote {
                handle,
                bind_host,
                port,
                map,
            } => {
                map.lock().unwrap_or_else(|p| p.into_inner()).remove(&port);
                handle.cancel_tcpip_forward(&bind_host, port).await?;
            }
        }
        Ok(())
    }
}

/// Binds a local listener and forwards each connection to `dest_host:dest_port`
/// over a `direct-tcpip` channel. Returns the actual bound address.
pub async fn forward_local(
    handle: ClientHandle,
    bind_host: &str,
    bind_port: u16,
    dest_host: String,
    dest_port: u16,
) -> Result<SocketAddr> {
    let listener = bind(bind_host, bind_port).await?;
    let local = listener.local_addr()?;
    tokio::spawn(serve_local(listener, handle, dest_host, dest_port));
    Ok(local)
}

/// Binds a local SOCKS5 proxy; each `CONNECT` request is relayed through a
/// `direct-tcpip` channel. Returns the actual bound address.
pub async fn forward_dynamic(
    handle: ClientHandle,
    bind_host: &str,
    bind_port: u16,
) -> Result<SocketAddr> {
    let listener = bind(bind_host, bind_port).await?;
    let local = listener.local_addr()?;
    tokio::spawn(serve_dynamic(listener, handle));
    Ok(local)
}

async fn serve_local(
    listener: TcpListener,
    handle: ClientHandle,
    dest_host: String,
    dest_port: u16,
) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
        let h = handle.clone();
        let dhost = dest_host.clone();
        tokio::spawn(async move {
            let channel = match h.open_direct_tcpip(&dhost, dest_port, "127.0.0.1", 0).await {
                Ok(c) => c,
                Err(_) => return,
            };
            bridge(stream, channel).await;
        });
    }
}

async fn serve_dynamic(listener: TcpListener, handle: ClientHandle) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
        let h = handle.clone();
        tokio::spawn(async move {
            let _ = handle_socks(stream, h).await;
        });
    }
}

async fn bind(bind_host: &str, bind_port: u16) -> Result<TcpListener> {
    let host = local_bind_host(bind_host);
    TcpListener::bind((host, bind_port))
        .await
        .map_err(|e| Error::Other(format!("listening on {host}:{bind_port}: {e}")))
}

/// A local listener with no bind address listens on loopback only, as
/// OpenSSH does by default (`GatewayPorts no`).
fn local_bind_host(bind_host: &str) -> &str {
    if bind_host.is_empty() {
        "127.0.0.1"
    } else {
        bind_host
    }
}

/// Consumes server-initiated `forwarded-tcpip` channels and bridges each to
/// the local destination it maps to (by the port the server bound).
async fn remote_dispatcher(mut rx: UnboundedReceiver<ServerEvent>, map: RemoteMap) {
    while let Some(evt) = rx.recv().await {
        let ServerEvent::ForwardedTcpIp {
            channel,
            forwarded_port,
            ..
        } = evt;
        let dest = map
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&(forwarded_port as u16))
            .cloned();
        if let Some((host, port)) = dest {
            tokio::spawn(async move {
                let Ok(stream) = TcpStream::connect((host.as_str(), port)).await else {
                    return;
                };
                bridge(stream, channel).await;
            });
        }
    }
}

/// Relays bytes between a local TCP stream and an SSH channel in both
/// directions until either side closes.
async fn bridge(stream: TcpStream, mut channel: Channel<Msg>) {
    let (mut rd, mut wr) = stream.into_split();
    let mut buf = vec![0u8; BUF_SIZE];
    loop {
        tokio::select! {
            r = rd.read(&mut buf) => {
                match r {
                    Ok(0) => { let _ = channel.eof().await; break; }
                    Ok(n) => { if channel.data(&buf[..n]).await.is_err() { break; } }
                    Err(_) => break,
                }
            }
            msg = channel.wait() => {
                match msg {
                    Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                        if wr.write_all(&data).await.is_err() { break; }
                    }
                    Some(ChannelMsg::Close) | None => break,
                    _ => {}
                }
            }
        }
    }
    let _ = wr.shutdown().await;
}

/// Performs the SOCKS5 handshake for one connection and, on `CONNECT`,
/// bridges the stream to a `direct-tcpip` channel.
async fn handle_socks(mut stream: TcpStream, handle: ClientHandle) -> std::io::Result<()> {
    // Greeting: VER, NMETHODS, METHODS…
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Ok(());
    }
    let mut methods = vec![0u8; head[1] as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        stream.write_all(&[0x05, 0xff]).await?; // no acceptable method
        return Ok(());
    }
    stream.write_all(&[0x05, 0x00]).await?; // no authentication

    // Request: VER, CMD, RSV, ATYP, addr…, port(2)
    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        return Ok(());
    }
    let Some((host, port)) = read_socks_addr(&mut stream, req[3]).await? else {
        return Ok(());
    };

    if req[1] != 0x01 {
        // Only CONNECT is supported (no BIND / UDP ASSOCIATE).
        stream
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Ok(());
    }

    match handle.open_direct_tcpip(&host, port, "127.0.0.1", 0).await {
        Ok(channel) => {
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            bridge(stream, channel).await;
        }
        Err(_) => {
            stream
                .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
        }
    }
    Ok(())
}

/// Reads a SOCKS5 address (ATYP already consumed) plus its 2-byte port.
async fn read_socks_addr(
    stream: &mut TcpStream,
    atyp: u8,
) -> std::io::Result<Option<(String, u16)>> {
    let addr_bytes = match atyp {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            1 + len[0] as usize // length byte + name
        }
        _ => return Ok(None),
    };
    let mut buf = vec![0u8; 1 + addr_bytes + 2];
    buf[0] = atyp;
    stream.read_exact(&mut buf[1..1 + addr_bytes]).await?;
    stream.read_exact(&mut buf[1 + addr_bytes..]).await?; // port
    Ok(parse_socks_addr(&buf).map(|(h, p, _)| (h, p)))
}

/// Parses a SOCKS5 address from a buffer whose first byte is the ATYP.
/// Returns `(host, port, bytes_consumed)` or `None` on truncation/unknown
/// ATYP. Pure so it is unit-testable.
pub fn parse_socks_addr(buf: &[u8]) -> Option<(String, u16, usize)> {
    let atyp = *buf.first()?;
    let (host, consumed) = match atyp {
        0x01 => {
            let b = buf.get(1..5)?;
            (format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]), 5)
        }
        0x03 => {
            let len = *buf.get(1)? as usize;
            let name = buf.get(2..2 + len)?;
            (String::from_utf8_lossy(name).into_owned(), 2 + len)
        }
        0x04 => {
            let b = buf.get(1..17)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(b);
            (std::net::Ipv6Addr::from(octets).to_string(), 17)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([*buf.get(consumed)?, *buf.get(consumed + 1)?]);
    Some((host, port, consumed + 2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_address() {
        let buf = [0x01, 127, 0, 0, 1, 0x1f, 0x90]; // 127.0.0.1:8080
        assert_eq!(parse_socks_addr(&buf), Some(("127.0.0.1".into(), 8080, 7)));
    }

    #[test]
    fn parses_domain_address() {
        let mut buf = vec![0x03, 9];
        buf.extend_from_slice(b"localhost");
        buf.extend_from_slice(&[0x00, 0x50]); // :80
        assert_eq!(
            parse_socks_addr(&buf),
            Some(("localhost".into(), 80, 2 + 9 + 2))
        );
    }

    #[test]
    fn parses_ipv6_address() {
        let mut buf = vec![0x04];
        buf.extend_from_slice(&[0; 15]);
        buf.push(1); // ::1
        buf.extend_from_slice(&[0x1b, 0x58]); // :7000
        assert_eq!(parse_socks_addr(&buf), Some(("::1".into(), 7000, 19)));
    }

    #[test]
    fn rejects_truncated_and_unknown() {
        assert_eq!(parse_socks_addr(&[0x01, 1, 2]), None);
        assert_eq!(parse_socks_addr(&[0x09]), None);
        assert_eq!(parse_socks_addr(&[]), None);
    }
}
