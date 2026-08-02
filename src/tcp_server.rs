use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

use crate::{config::Config, outbound::OutboundConnector, server::TrafficRegistry};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) struct ConnectionOptions {
    pub acceptor: TlsAcceptor,
    pub vless_users: Arc<crate::vless_server::VlessUsers>,
    pub outbound: OutboundConnector,
    pub udp_timeout: Duration,
    pub traffic: Arc<TrafficRegistry>,
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
        .context("configure VLESS TLS certificate")?;
    Ok(TlsAcceptor::from(Arc::new(tls)))
}

pub(crate) async fn serve(
    socket: TcpStream,
    remote: SocketAddr,
    options: ConnectionOptions,
) -> Result<()> {
    let ConnectionOptions {
        acceptor,
        vless_users,
        outbound,
        udp_timeout,
        traffic,
    } = options;
    socket.set_nodelay(true)?;
    let mut stream = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(socket))
        .await
        .context("VLESS TLS handshake timed out")?
        .context("accept VLESS TLS connection")?;
    let mut prefix = [0_u8; 17];
    timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut prefix))
        .await
        .context("VLESS authentication timed out")??;
    if prefix[0] != 0 {
        bail!("unsupported TCP proxy protocol");
    }
    let mut id = [0_u8; 16];
    id.copy_from_slice(&prefix[1..]);
    let username = vless_users
        .get(&id)
        .cloned()
        .context("invalid VLESS user")?;
    crate::vless_server::serve(stream, remote, username, outbound, udp_timeout, traffic).await
}
