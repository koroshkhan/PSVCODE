use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteProtocol {
    ForgePeer,
    Smb,
    Ftp,
    Nfs,
    Ps5ElfLoader,
}

impl RemoteProtocol {
    pub fn default_port(self) -> u16 {
        match self {
            RemoteProtocol::ForgePeer => 8095,
            RemoteProtocol::Smb => 445,
            RemoteProtocol::Ftp => 21,
            RemoteProtocol::Nfs => 2049,
            RemoteProtocol::Ps5ElfLoader => 9021,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointHealth {
    Online { latency_ms: u128 },
    Offline { reason: String },
}

#[derive(Debug, Clone)]
pub struct NetworkEndpoint {
    pub id: String,
    pub name: String,
    pub protocol: RemoteProtocol,
    pub host: String,
    pub port: u16,
    pub share_or_path: String,
    pub pairing_pin: Option<String>,
}

impl NetworkEndpoint {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        protocol: RemoteProtocol,
        host: impl Into<String>,
        port: Option<u16>,
        share_or_path: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            protocol,
            host: host.into(),
            port: port.unwrap_or_else(|| protocol.default_port()),
            share_or_path: share_or_path.into(),
            pairing_pin: None,
        }
    }

    pub fn probe_health(&self, timeout_ms: u64) -> EndpointHealth {
        let addr_str = format!("{}:{}", self.host, self.port);
        let Ok(addr) = addr_str.parse::<SocketAddr>() else {
            return EndpointHealth::Offline {
                reason: "Invalid IP or port format.".into(),
            };
        };

        let start = std::time::Instant::now();
        match TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)) {
            Ok(stream) => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
                EndpointHealth::Online {
                    latency_ms: start.elapsed().as_millis(),
                }
            }
            Err(e) => EndpointHealth::Offline {
                reason: e.to_string(),
            },
        }
    }
}

#[derive(Debug, Default)]
pub struct ConnectManager {
    endpoints: Vec<NetworkEndpoint>,
}

impl ConnectManager {
    pub fn add_or_update(&mut self, endpoint: NetworkEndpoint) {
        if let Some(existing) = self.endpoints.iter_mut().find(|e| e.id == endpoint.id) {
            *existing = endpoint;
        } else {
            self.endpoints.push(endpoint);
        }
    }

    pub fn check_all(&self, timeout_ms: u64) -> Vec<(NetworkEndpoint, EndpointHealth)> {
        self.endpoints
            .iter()
            .cloned()
            .map(|ep| {
                let health = ep.probe_health(timeout_ms);
                (ep, health)
            })
            .collect()
    }
}

pub fn ensure_endpoint_ready(
    manager: &ConnectManager,
    endpoint_id: &str,
    timeout_ms: u64,
) -> io::Result<NetworkEndpoint> {
    let ep = manager
        .endpoints
        .iter()
        .find(|e| e.id == endpoint_id)
        .cloned()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Endpoint not found."))?;

    match ep.probe_health(timeout_ms) {
        EndpointHealth::Online { .. } => Ok(ep),
        EndpointHealth::Offline { reason } => Err(io::Error::new(
            io::ErrorKind::NotConnected,
            format!("Endpoint {} offline: {reason}", ep.name),
        )),
    }
}

pub fn send_elf_payload(elf_path: &Path, ps5_ip: &str, port: u16) -> io::Result<()> {
    if !elf_path.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Payload file (.elf) not found.",
        ));
    }

    let mut file = File::open(elf_path)?;
    let total_len = file.metadata()?.len();
    if total_len < 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ELF file is too small.",
        ));
    }

    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)?;
    if &magic != b"\x7FELF" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid ELF magic header.",
        ));
    }

    file.rewind()?;

    let addr_str = format!("{ps5_ip}:{port}");
    let addr: SocketAddr = addr_str.parse().map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid PS5 IP: {e}"))
    })?;

    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(4))?;
    tcp.set_write_timeout(Some(Duration::from_secs(15)))?;

    let mut writer = BufWriter::with_capacity(1024 * 1024, tcp);
    let mut reader = BufReader::with_capacity(1024 * 1024, file);
    let mut buf = vec![0u8; 256 * 1024];
    let mut sent: u64 = 0;

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n])?;
        sent += n as u64;
    }
    writer.flush()?;

    if sent != total_len {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("Incomplete payload transfer ({sent} / {total_len})."),
        ));
    }

    Ok(())
}
