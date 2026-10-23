//! Opening TCP connections, shared by SSH, Telnet and raw connections.

use std::io::ErrorKind;
use std::time::Duration;

use tokio::net::TcpStream;

use crate::error::{Error, Result};

/// How long to wait for the TCP connection before giving up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// Opens a TCP connection, turning the usual failures into messages that
/// say what went wrong. `service` names what should be listening, e.g.
/// "sshd", for the "connection refused" hint.
pub async fn connect(host: &str, port: u16, service: &str) -> Result<TcpStream> {
    let addr = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let fail = |reason: String| Error::Connect {
        addr: addr.clone(),
        reason,
    };
    let socket = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port))).await
    {
        Err(_) => {
            return Err(fail(format!(
                "no response after {}s",
                CONNECT_TIMEOUT.as_secs()
            )))
        }
        Ok(Err(e)) => {
            let reason = match e.kind() {
                ErrorKind::ConnectionRefused => {
                    format!("connection refused (is {service} running on that port?)")
                }
                ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable => {
                    "host is unreachable".to_string()
                }
                ErrorKind::TimedOut => "connection timed out".to_string(),
                _ if e.to_string().contains("lookup address") => {
                    format!("unknown host '{host}'")
                }
                _ => e.to_string(),
            };
            return Err(fail(reason));
        }
        Ok(Ok(s)) => s,
    };
    socket.set_nodelay(true).ok();
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn refused_names_the_service() {
        // Bind and drop to get a port nothing listens on.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let e = connect("127.0.0.1", port, "a Telnet server")
            .await
            .unwrap_err();
        assert!(
            e.to_string()
                .contains("refused (is a Telnet server running"),
            "{e}"
        );
    }
}
