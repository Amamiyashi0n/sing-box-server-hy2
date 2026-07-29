use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use sha2::{Digest, Sha224};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tracing::info;

use crate::{
    config::{Config, OutboundMode, User},
    server::{TrafficRegistry, UserTraffic, connect_tcp, resolve_outbound_addresses},
};

const AUTH_HASH_LENGTH: usize = 56;
const COMMAND_CONNECT: u8 = 1;
const COMMAND_UDP_ASSOCIATE: u8 = 3;
const ADDRESS_IPV4: u8 = 1;
const ADDRESS_DOMAIN: u8 = 3;
const ADDRESS_IPV6: u8 = 4;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_UDP_PACKET_SIZE: usize = u16::MAX as usize;

pub(crate) type HashedUsers = HashMap<[u8; AUTH_HASH_LENGTH], String>;

pub(crate) fn hashed_users(users: &[User]) -> HashedUsers {
    users
        .iter()
        .map(|user| (password_hash(&user.password), user.name.clone()))
        .collect()
}

pub(crate) fn bind_listener(listen: SocketAddr) -> io::Result<TcpListener> {
    let socket = if listen.is_ipv6() && listen.ip().is_unspecified() {
        let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_only_v6(false)?;
        socket.set_reuse_address(true)?;
        socket.bind(&listen.into())?;
        socket.listen(1024)?;
        socket
    } else {
        let domain = if listen.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_reuse_address(true)?;
        socket.bind(&listen.into())?;
        socket.listen(1024)?;
        socket
    };
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

pub(crate) fn tls_acceptor(config: &Config) -> Result<TlsAcceptor> {
    let certificates = CertificateDer::pem_file_iter(&config.tls.certificate)
        .with_context(|| format!("read TLS certificate {}", config.tls.certificate))?
        .collect::<Result<Vec<_>, _>>()
        .context("parse TLS certificate PEM")?;
    if certificates.is_empty() {
        bail!("TLS certificate file does not contain a certificate");
    }
    let private_key = PrivateKeyDer::from_pem_file(&config.tls.private_key)
        .with_context(|| format!("read TLS private key {}", config.tls.private_key))?;
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .context("configure Trojan TLS certificate")?;
    Ok(TlsAcceptor::from(Arc::new(tls)))
}

pub(crate) async fn serve(
    socket: TcpStream,
    remote: SocketAddr,
    acceptor: TlsAcceptor,
    users: Arc<HashedUsers>,
    outbound_mode: OutboundMode,
    udp_timeout: Duration,
    traffic: Arc<TrafficRegistry>,
) -> Result<()> {
    socket.set_nodelay(true)?;
    let mut stream = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(socket))
        .await
        .context("Trojan TLS handshake timed out")?
        .context("accept Trojan TLS connection")?;
    let request = timeout(HANDSHAKE_TIMEOUT, read_request(&mut stream))
        .await
        .context("Trojan request timed out")??;
    let username = users
        .get(&request.password_hash)
        .cloned()
        .context("invalid Trojan password")?;
    info!(%remote, %username, command = request.command, "Trojan client authenticated");
    let user_traffic = traffic.user(&username);
    let _active = user_traffic.connection();
    match request.command {
        COMMAND_CONNECT => {
            serve_tcp(stream, &request.destination, outbound_mode, user_traffic).await
        }
        COMMAND_UDP_ASSOCIATE => serve_udp(stream, outbound_mode, udp_timeout, user_traffic).await,
        command => bail!("unsupported Trojan command {command}"),
    }
}

struct Request {
    password_hash: [u8; AUTH_HASH_LENGTH],
    command: u8,
    destination: String,
}

async fn read_request<R>(reader: &mut R) -> Result<Request>
where
    R: AsyncRead + Unpin,
{
    let mut password_hash = [0_u8; AUTH_HASH_LENGTH];
    reader.read_exact(&mut password_hash).await?;
    read_crlf(reader).await?;
    let command = reader.read_u8().await?;
    let destination = read_address(reader).await?;
    read_crlf(reader).await?;
    Ok(Request {
        password_hash,
        command,
        destination,
    })
}

async fn serve_tcp(
    mut client: TlsStream<TcpStream>,
    destination: &str,
    outbound_mode: OutboundMode,
    traffic: Arc<UserTraffic>,
) -> Result<()> {
    let mut upstream = connect_tcp(destination, outbound_mode)
        .await
        .with_context(|| format!("connect Trojan destination {destination}"))?;
    let (uploaded, downloaded) = tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .context("relay Trojan TCP connection")?;
    traffic.record_upload(uploaded as usize);
    traffic.record_download(downloaded as usize);
    Ok(())
}

async fn serve_udp(
    mut client: TlsStream<TcpStream>,
    outbound_mode: OutboundMode,
    udp_timeout: Duration,
    traffic: Arc<UserTraffic>,
) -> Result<()> {
    loop {
        let destination = match read_address(&mut client).await {
            Ok(destination) => destination,
            Err(error)
                if error.downcast_ref::<io::Error>().is_some_and(|error| {
                    matches!(
                        error.kind(),
                        io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
                    )
                }) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let length = client.read_u16().await? as usize;
        read_crlf(&mut client).await?;
        let mut payload = vec![0_u8; length];
        client.read_exact(&mut payload).await?;
        let addresses = resolve_outbound_addresses(&destination, outbound_mode).await?;
        let target = addresses[0];
        let socket = UdpSocket::bind(if target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .await
        .context("bind Trojan UDP socket")?;
        socket.send_to(&payload, target).await?;
        traffic.record_upload(payload.len());
        let mut response = vec![0_u8; MAX_UDP_PACKET_SIZE];
        let (received, source) = timeout(udp_timeout, socket.recv_from(&mut response))
            .await
            .context("Trojan UDP response timed out")??;
        write_socket_address(&mut client, source).await?;
        client.write_u16(received as u16).await?;
        client.write_all(b"\r\n").await?;
        client.write_all(&response[..received]).await?;
        client.flush().await?;
        traffic.record_download(received);
    }
}

async fn read_address<R>(reader: &mut R) -> Result<String>
where
    R: AsyncRead + Unpin,
{
    let address = match reader.read_u8().await? {
        ADDRESS_IPV4 => {
            let mut octets = [0_u8; 4];
            reader.read_exact(&mut octets).await?;
            IpAddr::V4(Ipv4Addr::from(octets)).to_string()
        }
        ADDRESS_IPV6 => {
            let mut octets = [0_u8; 16];
            reader.read_exact(&mut octets).await?;
            format!("[{}]", Ipv6Addr::from(octets))
        }
        ADDRESS_DOMAIN => {
            let length = reader.read_u8().await? as usize;
            if length == 0 {
                bail!("empty Trojan destination domain");
            }
            let mut domain = vec![0_u8; length];
            reader.read_exact(&mut domain).await?;
            String::from_utf8(domain).context("Trojan destination domain is not UTF-8")?
        }
        kind => bail!("unsupported Trojan address type {kind}"),
    };
    let port = reader.read_u16().await?;
    Ok(format!("{address}:{port}"))
}

async fn write_socket_address<W>(writer: &mut W, address: SocketAddr) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    match address.ip() {
        IpAddr::V4(ip) => {
            writer.write_u8(ADDRESS_IPV4).await?;
            writer.write_all(&ip.octets()).await?;
        }
        IpAddr::V6(ip) => {
            writer.write_u8(ADDRESS_IPV6).await?;
            writer.write_all(&ip.octets()).await?;
        }
    }
    writer.write_u16(address.port()).await?;
    Ok(())
}

async fn read_crlf<R>(reader: &mut R) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut crlf = [0_u8; 2];
    reader.read_exact(&mut crlf).await?;
    if crlf != *b"\r\n" {
        bail!("invalid Trojan frame delimiter");
    }
    Ok(())
}

fn password_hash(password: &str) -> [u8; AUTH_HASH_LENGTH] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha224::digest(password.as_bytes());
    let mut encoded = [0_u8; AUTH_HASH_LENGTH];
    for (index, byte) in digest.iter().copied().enumerate() {
        encoded[index * 2] = HEX[usize::from(byte >> 4)];
        encoded[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_password_using_sha224_hex() {
        assert_eq!(
            std::str::from_utf8(&password_hash("password")).unwrap(),
            "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
    }

    #[tokio::test]
    async fn parses_connect_request() {
        let hash = password_hash("secret");
        let mut bytes = hash.to_vec();
        bytes.extend_from_slice(b"\r\n\x01\x03\x0bexample.com\x01\xbb\r\n");
        let request = read_request(&mut bytes.as_slice()).await.unwrap();
        assert_eq!(request.password_hash, hash);
        assert_eq!(request.command, COMMAND_CONNECT);
        assert_eq!(request.destination, "example.com:443");
    }
}
