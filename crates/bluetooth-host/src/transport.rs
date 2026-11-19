//! Moving HCI packets to and from a controller.
//!
//! | Transport | Spec | Use |
//! |---|---|---|
//! | Linux HCI user channel | `hci0` | any controller the kernel has a driver for (btusb, hci_uart after `hciattach`); the kernel loads its firmware and then hands the whole controller to us |
//! | H4 over a serial port | `serial:/dev/ttyAMA0:115200` | UART controllers, with no kernel driver at all |
//! | H4 over TCP | `tcp:127.0.0.1:9000` | virtual controllers (Bumble), network HCI bridges |
//!
//! The user channel needs the interface down and nothing else using it: on a
//! system with BlueZ, stop `bluetoothd` first. Opening it needs
//! `CAP_NET_ADMIN`.

use std::fmt;
use std::io;
use std::str::FromStr;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

/// HCI packet indicators (H4).
pub mod indicator {
    /// Command, host to controller.
    pub const COMMAND: u8 = 0x01;
    /// ACL data.
    pub const ACL: u8 = 0x02;
    /// Synchronous (SCO) data.
    pub const SCO: u8 = 0x03;
    /// Event, controller to host.
    pub const EVENT: u8 = 0x04;
    /// Isochronous data.
    pub const ISO: u8 = 0x05;
}

/// One HCI packet, without its H4 indicator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    /// A command (header included).
    Command(Vec<u8>),
    /// ACL data (header included).
    Acl(Vec<u8>),
    /// SCO data (header included).
    Sco(Vec<u8>),
    /// An event (header included).
    Event(Vec<u8>),
    /// ISO data (header included).
    Iso(Vec<u8>),
}

impl Packet {
    /// The H4 indicator.
    pub fn indicator(&self) -> u8 {
        match self {
            Packet::Command(_) => indicator::COMMAND,
            Packet::Acl(_) => indicator::ACL,
            Packet::Sco(_) => indicator::SCO,
            Packet::Event(_) => indicator::EVENT,
            Packet::Iso(_) => indicator::ISO,
        }
    }

    /// The bytes after the indicator.
    pub fn bytes(&self) -> &[u8] {
        match self {
            Packet::Command(b)
            | Packet::Acl(b)
            | Packet::Sco(b)
            | Packet::Event(b)
            | Packet::Iso(b) => b,
        }
    }

    /// Splits an H4 frame (indicator first) into a packet, checking that the
    /// length in its header matches.
    pub fn from_h4(frame: &[u8]) -> io::Result<Packet> {
        let (&ind, rest) = frame
            .split_first()
            .ok_or_else(|| invalid("empty HCI packet"))?;
        let header = header_len(ind)?;
        if rest.len() < header || rest.len() != header + payload_len(ind, &rest[..header]) {
            return Err(invalid("HCI packet length does not match its header"));
        }
        Ok(Self::with_indicator(ind, rest.to_vec()))
    }

    fn with_indicator(ind: u8, b: Vec<u8>) -> Packet {
        match ind {
            indicator::COMMAND => Packet::Command(b),
            indicator::ACL => Packet::Acl(b),
            indicator::SCO => Packet::Sco(b),
            indicator::EVENT => Packet::Event(b),
            _ => Packet::Iso(b),
        }
    }
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn header_len(ind: u8) -> io::Result<usize> {
    match ind {
        indicator::COMMAND | indicator::SCO => Ok(3),
        indicator::ACL | indicator::ISO => Ok(4),
        indicator::EVENT => Ok(2),
        other => Err(invalid(&format!(
            "unknown HCI packet indicator {other:#04x}"
        ))),
    }
}

fn payload_len(ind: u8, h: &[u8]) -> usize {
    match ind {
        indicator::COMMAND | indicator::SCO => usize::from(h[2]),
        indicator::ACL => usize::from(u16::from_le_bytes([h[2], h[3]])),
        indicator::ISO => usize::from(u16::from_le_bytes([h[2], h[3]]) & 0x3fff),
        _ => usize::from(h[1]),
    }
}

/// Which controller to open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportSpec {
    /// The Linux HCI user channel of `hciN`.
    UserChannel(u16),
    /// H4 over a serial port.
    Serial {
        /// The device path.
        path: String,
        /// Baud rate.
        baud: u32,
        /// RTS/CTS flow control (most UART controllers need it).
        flow_control: bool,
    },
    /// H4 over TCP, as `host:port`.
    Tcp(String),
}

impl fmt::Display for TransportSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportSpec::UserChannel(n) => write!(f, "hci{n}"),
            TransportSpec::Serial {
                path,
                baud,
                flow_control,
            } => write!(
                f,
                "serial:{path}:{baud}{}",
                if *flow_control { "" } else { ":noflow" }
            ),
            TransportSpec::Tcp(a) => write!(f, "tcp:{a}"),
        }
    }
}

impl FromStr for TransportSpec {
    type Err = String;

    /// `hci0`, `serial:/dev/ttyUSB0:115200` (append `:noflow` to turn RTS/CTS
    /// off), or `tcp:host:port`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(n) = s.strip_prefix("hci") {
            let n = n.trim_start_matches(':');
            return n
                .parse()
                .map(TransportSpec::UserChannel)
                .map_err(|_| format!("bad HCI device {s:?}"));
        }
        if let Some(a) = s.strip_prefix("tcp:") {
            return Ok(TransportSpec::Tcp(a.trim_start_matches("//").to_string()));
        }
        if let Some(rest) = s.strip_prefix("serial:") {
            let mut parts: Vec<&str> = rest.split(':').collect();
            let flow_control = if parts.last() == Some(&"noflow") {
                parts.pop();
                false
            } else {
                true
            };
            let (path, baud) = match parts.as_slice() {
                [path] => (path.to_string(), 115_200),
                [path, baud] => (
                    path.to_string(),
                    baud.parse()
                        .map_err(|_| format!("bad baud rate in {s:?}"))?,
                ),
                _ => return Err(format!("bad serial spec {s:?}")),
            };
            return Ok(TransportSpec::Serial {
                path,
                baud,
                flow_control,
            });
        }
        Err(format!(
            "unknown transport {s:?}: want hciN, serial:PATH:BAUD or tcp:HOST:PORT"
        ))
    }
}

type BoxRead = Box<dyn AsyncRead + Send + Unpin>;
type BoxWrite = Box<dyn AsyncWrite + Send + Unpin>;

/// Reads whole packets.
pub struct PacketReader {
    inner: ReadKind,
}

enum ReadKind {
    /// A byte stream with H4 framing (UART, TCP).
    Stream(BufReader<BoxRead>),
    /// A socket that returns one packet per read (the user channel).
    Datagram(BoxRead, Vec<u8>),
}

/// Writes whole packets.
pub struct PacketWriter {
    inner: BoxWrite,
}

impl PacketReader {
    /// Wraps a byte stream carrying H4 frames.
    pub fn stream(r: impl AsyncRead + Send + Unpin + 'static) -> Self {
        PacketReader {
            inner: ReadKind::Stream(BufReader::with_capacity(4096, Box::new(r))),
        }
    }

    /// Wraps a socket that returns exactly one H4 frame per read.
    pub fn datagram(r: impl AsyncRead + Send + Unpin + 'static) -> Self {
        PacketReader {
            inner: ReadKind::Datagram(Box::new(r), vec![0u8; 1 + 4 + 65_535]),
        }
    }

    /// The next packet. An error means the transport is gone or out of sync.
    pub async fn read(&mut self) -> io::Result<Packet> {
        match &mut self.inner {
            ReadKind::Stream(r) => {
                let ind = r.read_u8().await?;
                let hl = header_len(ind)?;
                let mut buf = vec![0u8; hl];
                r.read_exact(&mut buf).await?;
                let pl = payload_len(ind, &buf);
                buf.resize(hl + pl, 0);
                r.read_exact(&mut buf[hl..]).await?;
                Ok(Packet::with_indicator(ind, buf))
            }
            ReadKind::Datagram(r, buf) => loop {
                let n = r.read(buf).await?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "HCI socket closed",
                    ));
                }
                match Packet::from_h4(&buf[..n]) {
                    Ok(p) => return Ok(p),
                    Err(e) => tracing::warn!("dropping malformed HCI packet: {e}"),
                }
            },
        }
    }
}

impl PacketWriter {
    /// Wraps the write half of a transport.
    pub fn new(w: impl AsyncWrite + Send + Unpin + 'static) -> Self {
        PacketWriter { inner: Box::new(w) }
    }

    /// Writes one packet, indicator first, in a single write.
    pub async fn write(&mut self, indicator: u8, bytes: &[u8]) -> io::Result<()> {
        let mut frame = Vec::with_capacity(1 + bytes.len());
        frame.push(indicator);
        frame.extend_from_slice(bytes);
        self.inner.write_all(&frame).await?;
        self.inner.flush().await
    }
}

/// Opens a transport.
pub async fn open(spec: &TransportSpec) -> io::Result<(PacketReader, PacketWriter)> {
    match spec {
        TransportSpec::Tcp(addr) => {
            let s = tokio::net::TcpStream::connect(addr).await?;
            s.set_nodelay(true)?;
            let (r, w) = s.into_split();
            Ok((PacketReader::stream(r), PacketWriter::new(w)))
        }
        #[cfg(feature = "serial")]
        TransportSpec::Serial {
            path,
            baud,
            flow_control,
        } => {
            use tokio_serial::SerialPortBuilderExt;
            let port = tokio_serial::new(path, *baud)
                .flow_control(if *flow_control {
                    tokio_serial::FlowControl::Hardware
                } else {
                    tokio_serial::FlowControl::None
                })
                .open_native_async()
                .map_err(io::Error::other)?;
            let (r, w) = tokio::io::split(port);
            Ok((PacketReader::stream(r), PacketWriter::new(w)))
        }
        #[cfg(not(feature = "serial"))]
        TransportSpec::Serial { .. } => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "built without the `serial` feature",
        )),
        TransportSpec::UserChannel(dev) => user_channel(*dev).await,
    }
}

#[cfg(target_os = "linux")]
async fn user_channel(dev: u16) -> io::Result<(PacketReader, PacketWriter)> {
    // The kernel refuses the bind (EBUSY) while the interface is up or still
    // being set up after hotplug (firmware loading); wait that out.
    let mut tries = 0;
    let socket = loop {
        match bt_hci_linux::Socket::new(dev) {
            Ok(s) => break s,
            Err(e) if e.raw_os_error() == Some(16) && tries < 20 => {
                tries += 1;
                tracing::info!("hci{dev} is busy (up, or still loading firmware); retrying");
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            Err(e) if e.raw_os_error() == Some(16) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!(
                        "hci{dev} stays busy: is bluetoothd running, or the interface up? ({e})"
                    ),
                ))
            }
            Err(e) => return Err(e),
        }
    };
    let (r, w) = tokio::io::split(socket);
    Ok((PacketReader::datagram(r), PacketWriter::new(w)))
}

#[cfg(not(target_os = "linux"))]
async fn user_channel(_dev: u16) -> io::Result<(PacketReader, PacketWriter)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the HCI user channel exists only on Linux; use serial: or tcp:",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specs() {
        assert_eq!("hci0".parse(), Ok(TransportSpec::UserChannel(0)));
        assert_eq!("hci:1".parse(), Ok(TransportSpec::UserChannel(1)));
        assert_eq!(
            "tcp:127.0.0.1:9000".parse(),
            Ok(TransportSpec::Tcp("127.0.0.1:9000".into()))
        );
        assert_eq!(
            "serial:/dev/ttyAMA0:460800:noflow".parse(),
            Ok(TransportSpec::Serial {
                path: "/dev/ttyAMA0".into(),
                baud: 460_800,
                flow_control: false
            })
        );
        assert!("usb:0".parse::<TransportSpec>().is_err());
    }

    #[tokio::test]
    async fn h4_stream_framing() {
        // An event (Command Complete, Reset), then ACL data, split arbitrarily.
        let bytes = [
            0x04u8, 0x0e, 0x04, 0x01, 0x03, 0x0c, 0x00, 0x02, 0x40, 0x20, 0x02, 0x00, 0xaa, 0xbb,
        ];
        let (a, mut b) = tokio::io::duplex(64);
        tokio::spawn(async move {
            for c in bytes.chunks(3) {
                b.write_all(c).await.unwrap();
            }
        });
        let mut r = PacketReader::stream(a);
        assert_eq!(
            r.read().await.unwrap(),
            Packet::Event(vec![0x0e, 0x04, 0x01, 0x03, 0x0c, 0x00])
        );
        assert_eq!(
            r.read().await.unwrap(),
            Packet::Acl(vec![0x40, 0x20, 0x02, 0x00, 0xaa, 0xbb])
        );
        assert!(r.read().await.is_err());
    }

    #[test]
    fn from_h4_checks_length() {
        assert!(Packet::from_h4(&[0x04, 0x0e, 0x01, 0x00]).is_ok());
        assert!(Packet::from_h4(&[0x04, 0x0e, 0x02, 0x00]).is_err());
        assert!(Packet::from_h4(&[0x09, 0x00]).is_err());
        assert!(Packet::from_h4(&[]).is_err());
    }
}
