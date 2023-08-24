//! Network-related code, i.e. actually sending queries and receiving answers.

use crate::QueryMetadata;
use anyhow::{anyhow, bail, Context, Result};
use byteorder::{NetworkEndian, WriteBytesExt};
use std::fmt::Display;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

#[cfg(feature = "tls")]
use std::{convert::TryInto, sync::Arc};

#[cfg(feature = "http")]
use {crate::ConnectionType, data_encoding::BASE64URL_NOPAD};

/// Contains all info needed to connect to a nameserver.
#[derive(Clone, Debug)]
pub struct Nameserver {
    /// Nameserver's hostname. If this is [`None`], `nameserver_ip` must be [`Some`].
    pub hostname: Option<String>,
    /// Nameserver's IP address. If this is [`None`], `nameserver_hostname` must be [`Some`].
    pub ip: Option<IpAddr>,
    /// Nameserver's port.
    pub port: u16,
}

impl Nameserver {
    /// Use the information from `metadata` to create a `Nameserver`.
    pub fn from_metadata(metadata: &QueryMetadata) -> Self {
        let ip = metadata.nameserver.parse().ok();
        let hostname = if ip.is_some() {
            // TODO: this might be suboptimal, e.g. for TLS certificates, the cert hostname might be 1.1.1.1
            // use webpki::DnsNameRef to validate? (note: that crate currently does not support IP addresses)
            None
        } else {
            Some(metadata.nameserver.clone())
        };

        Self {
            ip,
            hostname,
            port: metadata.port,
        }
    }
}

impl Display for Nameserver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ip = self.ip.map(|ip| {
            // if ip is an IPv6 address, check if it is a mapped IPv4 adress. if yes, display the
            // IPv4 address
            match ip {
                IpAddr::V6(ipv6) => match ipv6.to_ipv4() {
                    Some(ipv4) if ipv4.to_ipv6_mapped() == ipv6 => ipv4.to_string(),
                    _ => format!("[{}]", ipv6),
                },
                _ => ip.to_string(),
            }
        });
        match (ip, &self.hostname) {
            (Some(ip), Some(hostname)) => {
                write!(f, "{}:{} ({})", ip, self.port, hostname)
            }
            (Some(ip), None) => {
                write!(f, "{}:{}", ip, self.port)
            }
            (None, Some(hostname)) => {
                write!(f, "{}:{}", hostname, self.port)
            }
            (None, None) => {
                write!(f, "unknown nameserver")
            }
        }
    }
}

impl ToSocketAddrs for Nameserver {
    type Iter = std::vec::IntoIter<SocketAddr>;
    fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        if let Some(ip) = self.ip {
            Ok(vec![(ip, self.port).into()].into_iter())
        } else if let Some(hostname) = &self.hostname {
            (hostname.as_str(), self.port).to_socket_addrs()
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                anyhow!("Nameserver has neither IP nor hostname"),
            ))
        }
    }
}

pub fn send_query_udp(
    nameserver: &mut Nameserver,
    bufsize: u16,
    data: &[u8],
) -> Result<(Vec<u8>, u16, Duration)> {
    let socket = create_and_connect_udp_socket(nameserver)?;
    let mut res = vec![0; bufsize as usize]; // the query sets this as max size

    socket
        .set_write_timeout(Some(Duration::new(2, 0)))
        .context("Could not set UDP socket write timeout.")?;
    socket
        .set_read_timeout(Some(Duration::new(10, 0)))
        .context("Could not set UDP socket read timeout.")?;

    socket
        .connect(nameserver as &Nameserver)
        .context(format!("Could not connect to {} via UDP.", nameserver))?;

    let before = Instant::now();
    socket
        .send(data)
        .context("Could not send data to nameserver.")?;

    let (bytes_recvd, remote_addr) = socket
        .recv_from(&mut res)
        .context("The nameserver did not reply in time.")?;
    let elapsed = before.elapsed();

    nameserver.ip = Some(remote_addr.ip());

    res.resize(bytes_recvd, 0);

    Ok((res, bytes_recvd as u16, elapsed))
}

fn create_and_connect_udp_socket(nameserver: &Nameserver) -> Result<UdpSocket> {
    // on windows, binding a UDP socket to :: and trying to connect to an IPv4 address or a hostname
    // on a machine that has no IPv6 internet connection gives this helpful error message:
    // "The system detected an invalid pointer address in attempting to use a pointer argument in a
    // call. (os error 10014)"
    // therefore we either match the bind address to the IP address version of the nameserver, or if
    // we only have a hostname, we try IPv6 first and try again with IPv4 if that first try fails.
    // this is (to my knowledge) not necessary on linux, but it won't hurt to do this regardless of
    // which OS we're running on.
    if let Some(ip_addr) = nameserver.ip {
        let bind_addr = if ip_addr.is_ipv6() { "::" } else { "0.0.0.0" };
        UdpSocket::bind((bind_addr, 0)).context("Could not create UDP socket.")
    } else {
        let mut err = None;
        for bind_addr in ["::", "0.0.0.0"] {
            let socket = UdpSocket::bind((bind_addr, 0)).context("Could not create UDP socket.")?;
            match socket.connect(nameserver as &Nameserver) {
                Ok(()) => return Ok(socket),
                Err(e) => err = Some(e),
            }
        }

        Err(err.unwrap()).context(format!("Could not connect to {} via UDP.", nameserver))
    }
}

pub fn send_query_tcp(
    nameserver: &mut Nameserver,
    bufsize: u16,
    data: &[u8],
) -> Result<(Vec<u8>, u16, Duration)> {
    let nameserver_socketaddr = nameserver
        .to_socket_addrs()
        .context("Could not get socket address for nameserver.")?
        .next()
        .ok_or_else(|| anyhow!("Could not get socket address for nameserver."))?;
    let mut socket = TcpStream::connect_timeout(&nameserver_socketaddr, Duration::from_secs(10))
        .context(format!(
            "Could not connect to {} via TCP, is the server running?",
            nameserver
        ))?;

    let peer_addr = socket
        .peer_addr()
        .context("Could not get peer address of TCP socket.")?;
    nameserver.ip = Some(peer_addr.ip());

    socket
        .set_write_timeout(Some(Duration::new(2, 0)))
        .context("Could not set TCP stream write timeout.")?;
    socket
        .set_read_timeout(Some(Duration::new(10, 0)))
        .context("Could not set TCP stream read timeout.")?;

    let mut msg = Vec::with_capacity(data.len() + 2);
    msg.write_u16::<NetworkEndian>(data.len() as u16)?;
    msg.extend_from_slice(data);

    let before = Instant::now();
    socket
        .write_all(&msg)
        .context("Could not write data to TCP stream.")?;

    // we can't use socket.read_to_end() because we would have to wait for the read timout to elapse
    // before getting an EOF from the socket. therefore we roll our own implementation which stops reading
    // from the socket as soon as the received number of bytes is equal to the message length given by
    // the first two bytes of the message (plus two, because the message length does not count the two
    // bytes at the start; see RFC 1035, Section 4.2.2)
    let mut offset = 0;
    // the query sets this as max size
    let mut res = vec![0; bufsize as usize];
    while (offset < 2) || (offset - 2 < u16::from_be_bytes([res[0], res[1]]) as usize) {
        offset += socket
            .read(&mut res[offset..])
            .context("Could not read from TCP stream.")?;
    }

    let elapsed = before.elapsed();
    socket.shutdown(std::net::Shutdown::Both)?;

    let bytes_recvd = u16::from_be_bytes([res[0], res[1]]);
    res = res.into_iter().skip(2).collect();
    if bytes_recvd as usize != offset - 2 {
        bail!(
            "Received {} bytes, but TCP message says {} bytes were sent.",
            offset - 2,
            bytes_recvd
        );
    }
    // this will always shrink res
    res.resize(bytes_recvd as usize, 0);

    Ok((res, bytes_recvd, elapsed))
}

#[cfg(feature = "tls")]
pub fn send_query_tls(
    nameserver: &mut Nameserver,
    data: &[u8],
) -> Result<(Vec<u8>, u16, Duration)> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let nameserver_tlsname = nameserver
        .hostname
        .as_ref()
        .expect("The argument parser failed to ensure the DoT nameserver is given as a hostname")
        .as_str()
        .try_into()
        .context("Invalid nameserver hostname.")?;
    let mut session = rustls::ClientConnection::new(Arc::new(config), nameserver_tlsname)
        .context("Could not create TLS connection.")?;

    let nameserver_socketaddr = nameserver
        .to_socket_addrs()
        .context("Could not get socket address for nameserver.")?
        .next()
        .ok_or_else(|| anyhow!("Could not get socket address for nameserver."))?;
    let mut socket = TcpStream::connect_timeout(&nameserver_socketaddr, Duration::from_secs(10))
        .context(format!(
            "Failed to connect to {}, is the server configured to use DNS over TLS?",
            nameserver
        ))?;

    let peer_addr = socket
        .peer_addr()
        .context("Could not get peer address of TCP socket.")?;
    nameserver.ip = Some(peer_addr.ip());

    socket
        .set_write_timeout(Some(Duration::new(2, 0)))
        .context("Could not set TLS/TCP stream write timeout.")?;
    socket
        .set_read_timeout(Some(Duration::new(10, 0)))
        .context("Could not set TLS/TCP stream read timeout.")?;

    let mut plaintext = Vec::new();
    let mut msg = Vec::with_capacity(data.len() + 2);
    msg.write_u16::<NetworkEndian>(data.len() as u16)?;
    msg.extend_from_slice(data);

    let before = Instant::now();
    session
        .writer()
        .write_all(&msg)
        .context("Could not write to TLS socket.")?;

    while (plaintext.len() < 2)
        || plaintext.len() - 2 < u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize
    {
        if session.wants_write() {
            session
                .write_tls(&mut socket)
                .context("Could not write TLS packets to TCP stream.")?;
        }

        if session.wants_read() {
            session
                .read_tls(&mut socket)
                .context("Could not read TLS packets from TCP stream.")?;
            session
                .process_new_packets()
                .context("Could not process new TLS packets.")?;
            // Ignore WouldBlock errors
            match session.reader().read_to_end(&mut plaintext) {
                Ok(_) => (),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
                Err(e) => Err(e).context("Could not read from TLS socket.")?,
            }
        }
    }
    let elapsed = before.elapsed();

    session.send_close_notify();

    // remove first two bytes (see RFC 1035, Section 4.2.2)
    let bytes_recvd = u16::from_be_bytes([plaintext[0], plaintext[1]]);
    plaintext = plaintext.into_iter().skip(2).collect();
    if bytes_recvd != plaintext.len() as u16 {
        bail!(
            "Received {} bytes, but TCP message says {} were sent.",
            bytes_recvd,
            plaintext.len()
        )
    }

    Ok((plaintext, bytes_recvd, elapsed))
}

#[cfg(feature = "http")]
pub fn send_query_http(
    nameserver: &mut Nameserver,
    connection_type: ConnectionType,
    bufsize: u16,
    data: &[u8],
) -> Result<(Vec<u8>, u16, Duration)> {
    let mut res = Vec::with_capacity(bufsize as usize); // the query sets this as max size

    let nameserver_hostname = nameserver
        .hostname
        .as_ref()
        .expect("The argument parser failed to ensure the DoT nameserver is given as a hostname");
    let addr = match connection_type {
        ConnectionType::HttpGet | ConnectionType::HttpPost => {
            format!(
                "http://{}:{}/dns-query",
                nameserver_hostname, nameserver.port
            )
        }
        ConnectionType::HttpsGet | ConnectionType::HttpsPost => {
            format!(
                "https://{}:{}/dns-query",
                nameserver_hostname, nameserver.port
            )
        }
        _ => unreachable!(),
    };
    let b64 = BASE64URL_NOPAD.encode(data);
    let before = Instant::now();

    let response = match connection_type {
        ConnectionType::HttpPost | ConnectionType::HttpsPost => ureq::post(&addr)
            .set("Content-Type", "application/dns-message")
            .send_bytes(data),
        ConnectionType::HttpGet | ConnectionType::HttpsGet => ureq::get(&addr)
            .set("Accept", "application/dns-message")
            .query("dns", &b64)
            .call(),
        _ => unreachable!(),
    }
    .context("HTTP(S) request unsuccessful.")?;

    let elapsed = before.elapsed();
    // for 404 the above ? already returns an Err...
    if response.status() != 200 {
        bail!("HTTP(S) response code not 200.")
    }

    // TODO Response::remote_addr() will be added in ureq 2.6.0
    // nameserver.ip = response.remote_addr().map(|s| s.ip());

    let bytes_recvd = response
        .into_reader()
        .read_to_end(&mut res)
        .context("Could not read the HTTP(S) response.")?;

    res.resize(bytes_recvd, 0);

    Ok((res, bytes_recvd as u16, elapsed))
}
