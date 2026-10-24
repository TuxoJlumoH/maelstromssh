//! Serial (COM) ports: opening one with given line settings, and listing
//! the ports this machine has.

use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;

use tokio::io::{ReadHalf, WriteHalf};
use tokio_serial::{SerialPortBuilderExt, SerialStream};

use crate::config::{FlowControl, Parity, SerialSettings};
use crate::error::{Error, Result};

/// An open serial port, split so reading and writing can run in separate
/// tasks.
pub struct Line {
    pub reader: ReadHalf<SerialStream>,
    pub writer: WriteHalf<SerialStream>,
    pub breaker: Breaker,
}

impl Line {
    /// Opens `path` (see [`open`]).
    pub fn open(path: &str, settings: &SerialSettings) -> Result<Self> {
        let port = open(path, settings)?;
        let breaker = Breaker {
            // SAFETY: the port's descriptor is open while `port` lives.
            fd: Arc::new(unsafe { BorrowedFd::borrow_raw(port.as_raw_fd()) }.try_clone_to_owned()?),
        };
        let (reader, writer) = tokio::io::split(port);
        Ok(Self {
            reader,
            writer,
            breaker,
        })
    }
}

/// Sends a break signal on the line, e.g. to enter a router's ROM monitor.
/// It holds a duplicate of the port's descriptor, so the device stays open
/// (and locked) until the `Line` and every `Breaker` are dropped.
#[derive(Clone)]
pub struct Breaker {
    fd: Arc<OwnedFd>,
}

impl Breaker {
    /// Holds the line low for 0.25 to 0.5 s. Blocks for that long, so call
    /// it from a blocking thread or `spawn_blocking`.
    pub fn send(&self) -> Result<()> {
        // SAFETY: the descriptor is owned by `self` and open.
        if unsafe { libc::tcsendbreak(self.fd.as_raw_fd(), 0) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error().into())
        }
    }
}

/// A serial port found on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortInfo {
    /// The device, e.g. `/dev/ttyUSB0`.
    pub path: String,
    /// What it is, e.g. "USB: FT232R USB UART (0403:6001)", or "".
    pub description: String,
}

/// The serial ports on this machine, sorted by path. Built-in `ttyS*`
/// entries without a UART behind them are left out.
pub fn list_ports() -> Result<Vec<PortInfo>> {
    let ports = tokio_serial::available_ports().map_err(|e| Error::Other(e.to_string()))?;
    let mut list: Vec<PortInfo> = ports
        .into_iter()
        .filter(|p| has_uart(&p.port_name))
        .map(|p| PortInfo {
            description: describe(&p.port_type),
            path: p.port_name,
        })
        .collect();
    list.sort_by(|a, b| a.path.cmp(&b.path));
    list.dedup_by(|a, b| a.path == b.path);
    Ok(list)
}

/// Linux creates `ttyS0`..`ttyS31` whether or not there is hardware; the
/// sysfs `type` of an empty slot is 0 (`PORT_UNKNOWN`).
fn has_uart(path: &str) -> bool {
    let Some(name) = Path::new(path).file_name().and_then(|n| n.to_str()) else {
        return true;
    };
    match std::fs::read_to_string(format!("/sys/class/tty/{name}/type")) {
        Ok(kind) => kind.trim() != "0",
        Err(_) => true,
    }
}

fn describe(kind: &tokio_serial::SerialPortType) -> String {
    use tokio_serial::SerialPortType;
    match kind {
        SerialPortType::UsbPort(usb) => {
            let name = [usb.manufacturer.as_deref(), usb.product.as_deref()]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" ");
            let ids = format!("{:04x}:{:04x}", usb.vid, usb.pid);
            if name.is_empty() {
                format!("USB ({ids})")
            } else {
                format!("USB: {name} ({ids})")
            }
        }
        SerialPortType::PciPort => "PCI".into(),
        SerialPortType::BluetoothPort => "Bluetooth".into(),
        SerialPortType::Unknown => String::new(),
    }
}

/// Opens `path` for exclusive use with the given line settings.
pub fn open(path: &str, settings: &SerialSettings) -> Result<SerialStream> {
    settings.check()?;
    let data_bits = match settings.data_bits {
        5 => tokio_serial::DataBits::Five,
        6 => tokio_serial::DataBits::Six,
        7 => tokio_serial::DataBits::Seven,
        _ => tokio_serial::DataBits::Eight,
    };
    let stop_bits = match settings.stop_bits {
        2 => tokio_serial::StopBits::Two,
        _ => tokio_serial::StopBits::One,
    };
    let parity = match settings.parity {
        Parity::None => tokio_serial::Parity::None,
        Parity::Odd => tokio_serial::Parity::Odd,
        Parity::Even => tokio_serial::Parity::Even,
    };
    let flow = match settings.flow_control {
        FlowControl::None => tokio_serial::FlowControl::None,
        FlowControl::Software => tokio_serial::FlowControl::Software,
        FlowControl::Hardware => tokio_serial::FlowControl::Hardware,
    };
    tokio_serial::new(path, settings.baud)
        .data_bits(data_bits)
        .stop_bits(stop_bits)
        .parity(parity)
        .flow_control(flow)
        .open_native_async()
        .map_err(|e| open_error(path, e))
}

fn open_error(path: &str, e: tokio_serial::Error) -> Error {
    use tokio_serial::ErrorKind;
    let busy = e.description.contains("lock") || e.description.contains("busy");
    let reason = match e.kind {
        ErrorKind::NoDevice if busy => "it is in use by another program".to_string(),
        ErrorKind::NoDevice => "no such device".to_string(),
        ErrorKind::Io(std::io::ErrorKind::NotFound) => "no such device".to_string(),
        ErrorKind::Io(std::io::ErrorKind::PermissionDenied) => permission_hint(path),
        _ if e.description.contains("Permission denied") => permission_hint(path),
        _ if busy => "it is in use by another program".to_string(),
        _ => e.description,
    };
    Error::Connect {
        addr: path.to_string(),
        reason,
    }
}

/// Serial devices usually belong to a group (`uucp` on Arch, `dialout` on
/// Debian and Fedora); say which one to join.
fn permission_hint(path: &str) -> String {
    use std::os::unix::fs::MetadataExt;
    let group = std::fs::metadata(path)
        .ok()
        .and_then(|m| group_name(m.gid()));
    match group {
        Some(g) if g != "root" => format!(
            "permission denied. Add yourself to the '{g}' group \
             (sudo usermod -aG {g} $USER), then log out and back in"
        ),
        _ => "permission denied".to_string(),
    }
}

fn group_name(gid: u32) -> Option<String> {
    let groups = std::fs::read_to_string("/etc/group").ok()?;
    groups.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        let id = fields.nth(1)?.parse::<u32>().ok()?;
        (id == gid).then(|| name.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn settings_are_checked() {
        let mut s = SerialSettings::default();
        assert!(s.check().is_ok());
        assert_eq!(s.to_string(), "9600 8N1");
        s.data_bits = 9;
        assert!(s.check().is_err());
        s.data_bits = 7;
        s.stop_bits = 3;
        assert!(s.check().is_err());
        s.stop_bits = 2;
        s.parity = Parity::Even;
        s.flow_control = FlowControl::Hardware;
        s.baud = 115_200;
        assert_eq!(s.to_string(), "115200 7E2 RTS/CTS");
    }

    #[test]
    fn missing_device_is_a_clear_error() {
        let e = open("/dev/maelstromssh-no-such-port", &SerialSettings::default()).unwrap_err();
        assert!(e.to_string().contains("no such device"), "{e}");
    }

    #[test]
    fn listing_does_not_fail() {
        let ports = list_ports().unwrap();
        // Empty ttyS slots are filtered out.
        for p in ports {
            assert!(has_uart(&p.path), "{p:?}");
        }
    }

    #[tokio::test]
    async fn line_on_a_pty_carries_bytes_and_breaks() {
        let (mut far, near) = SerialStream::pair().unwrap();
        let path = std::fs::read_link(format!("/proc/self/fd/{}", near.as_raw_fd())).unwrap();
        let mut line = Line::open(path.to_str().unwrap(), &SerialSettings::default()).unwrap();
        line.writer.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        far.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        far.write_all(b"pong").await.unwrap();
        line.reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
        let breaker = line.breaker.clone();
        tokio::task::spawn_blocking(move || breaker.send())
            .await
            .unwrap()
            .unwrap();
        drop(near);
    }

    #[tokio::test]
    async fn pty_pair_carries_bytes() {
        let (mut a, mut b) = SerialStream::pair().unwrap();
        a.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }
}
