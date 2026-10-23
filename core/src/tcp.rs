//! Telnet and raw TCP connections: a terminal over a plain TCP socket.
//!
//! [`TcpLine::connect`] opens the socket (and starts Telnet option
//! negotiation); the front-end then runs everything it reads through
//! [`Filter::receive`] and everything typed through [`Filter::encode`].

use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use crate::config::Protocol;
use crate::error::{Error, Result};
use crate::telnet::Telnet;

/// An open Telnet or raw connection, split so reading and writing can run
/// in separate tasks.
pub struct TcpLine {
    pub reader: OwnedReadHalf,
    pub writer: OwnedWriteHalf,
    pub filter: Filter,
}

impl TcpLine {
    /// Connects to `host:port`. For Telnet, the window size `cols` x `rows`
    /// and `term_type` are offered to the server.
    pub async fn connect(
        protocol: Protocol,
        host: &str,
        port: u16,
        term_type: &str,
        (cols, rows): (u16, u16),
    ) -> Result<Self> {
        let mut filter = match protocol {
            Protocol::Telnet => Filter::Telnet(Box::new(Telnet::new(term_type, cols, rows))),
            Protocol::Raw => Filter::Raw,
            other => {
                return Err(Error::Config(format!(
                    "{} is not a TCP protocol",
                    other.name()
                )))
            }
        };
        if port == 0 {
            return Err(Error::Config("a port is needed (1-65535)".into()));
        }
        let service = match protocol {
            Protocol::Telnet => "a Telnet server",
            _ => "a server",
        };
        let socket = crate::net::connect(host, port, service).await?;
        let (reader, mut writer) = socket.into_split();
        let hello = filter.start();
        if !hello.is_empty() {
            writer.write_all(&hello).await?;
        }
        Ok(Self {
            reader,
            writer,
            filter,
        })
    }
}

/// What happens to the bytes on a TCP connection.
#[derive(Debug)]
pub enum Filter {
    /// Unchanged both ways.
    Raw,
    Telnet(Box<Telnet>),
}

impl Filter {
    fn start(&mut self) -> Vec<u8> {
        match self {
            Filter::Raw => Vec::new(),
            Filter::Telnet(t) => t.start(),
        }
    }

    /// Splits what the server sent into terminal output (`data`) and bytes
    /// to send back (`reply`).
    pub fn receive(&mut self, input: &[u8], data: &mut Vec<u8>, reply: &mut Vec<u8>) {
        match self {
            Filter::Raw => data.extend_from_slice(input),
            Filter::Telnet(t) => t.receive(input, data, reply),
        }
    }

    /// Typed bytes as they go on the wire.
    pub fn encode(&self, input: &[u8]) -> Vec<u8> {
        match self {
            Filter::Raw => input.to_vec(),
            Filter::Telnet(t) => {
                let mut out = Vec::with_capacity(input.len() + 4);
                t.encode(input, &mut out);
                out
            }
        }
    }

    /// The bytes that tell the server about a new window size, if any.
    pub fn resize(&mut self, cols: u16, rows: u16) -> Option<Vec<u8>> {
        match self {
            Filter::Raw => None,
            Filter::Telnet(t) => t.resize(cols, rows),
        }
    }

    /// The bytes of a break signal; raw connections have none.
    pub fn brk(&self) -> Option<Vec<u8>> {
        match self {
            Filter::Raw => None,
            Filter::Telnet(_) => Some(Telnet::brk().to_vec()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn telnet_negotiates_and_raw_does_not() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let line = TcpLine::connect(Protocol::Telnet, "127.0.0.1", port, "xterm", (80, 24))
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let mut hello = [0u8; 12];
        server.read_exact(&mut hello).await.unwrap();
        assert_eq!(hello[..3], [255, 251, 31]); // IAC WILL NAWS
        assert!(line.filter.brk().is_some());
        drop(line);

        let mut line = TcpLine::connect(Protocol::Raw, "127.0.0.1", port, "xterm", (80, 24))
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        line.writer
            .write_all(&line.filter.encode(b"a\r\xff"))
            .await
            .unwrap();
        drop(line);
        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"a\r\xff");
    }

    #[tokio::test]
    async fn port_zero_and_ssh_are_refused() {
        assert!(
            TcpLine::connect(Protocol::Raw, "127.0.0.1", 0, "x", (80, 24))
                .await
                .is_err()
        );
        assert!(
            TcpLine::connect(Protocol::Ssh, "127.0.0.1", 22, "x", (80, 24))
                .await
                .is_err()
        );
    }
}
