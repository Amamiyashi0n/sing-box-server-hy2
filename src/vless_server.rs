use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::server::TlsStream;
use tracing::info;

use crate::{
    config::User,
    outbound::OutboundConnector,
    server::{TrafficRegistry, UserTraffic},
};

const VERSION: u8 = 0;
const COMMAND_TCP: u8 = 1;
const COMMAND_UDP: u8 = 2;
const RELAY_BUFFER_SIZE: usize = 32 * 1024;
const MAX_UDP_PACKET_SIZE: usize = u16::MAX as usize;

pub(crate) type VlessUsers = HashMap<[u8; 16], String>;

pub(crate) fn user_id(username: &str, password: &str) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(username.as_bytes());
    hasher.update([0]);
    hasher.update(password.as_bytes());
    let digest = hasher.finalize();
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    id[6] = (id[6] & 0x0f) | 0x40;
    id[8] = (id[8] & 0x3f) | 0x80;
    id
}

pub(crate) fn user_id_string(username: &str, password: &str) -> String {
    let id = user_id(username, password);
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        id[0],
        id[1],
        id[2],
        id[3],
        id[4],
        id[5],
        id[6],
        id[7],
        id[8],
        id[9],
        id[10],
        id[11],
        id[12],
        id[13],
        id[14],
        id[15]
    )
}

pub(crate) fn users(users: &[User]) -> VlessUsers {
    users
        .iter()
        .map(|user| (user_id(&user.name, &user.password), user.name.clone()))
        .collect()
}

pub(crate) async fn serve(
    mut stream: TlsStream<TcpStream>,
    remote: SocketAddr,
    username: String,
    outbound: OutboundConnector,
    udp_timeout: Duration,
    traffic: Arc<TrafficRegistry>,
) -> Result<()> {
    let addons_length = stream.read_u8().await.context("read VLESS addons length")? as usize;
    if addons_length != 0 {
        let mut addons = vec![0_u8; addons_length];
        stream
            .read_exact(&mut addons)
            .await
            .context("read VLESS addons")?;
        bail!("VLESS flow addons are not supported");
    }
    let command = stream.read_u8().await.context("read VLESS command")?;
    let destination = read_destination(&mut stream).await?;
    let user_traffic = traffic.user(&username);
    let _active = user_traffic.connection();
    info!(%remote, %username, command, %destination, "VLESS client authenticated");
    match command {
        COMMAND_TCP => serve_tcp(stream, destination, outbound, user_traffic).await,
        COMMAND_UDP => serve_udp(stream, destination, outbound, udp_timeout, user_traffic).await,
        _ => bail!("unsupported VLESS command {command:#x}"),
    }
}

async fn read_destination(stream: &mut TlsStream<TcpStream>) -> Result<String> {
    let port = stream
        .read_u16()
        .await
        .context("read VLESS destination port")?;
    let host = match stream.read_u8().await.context("read VLESS address type")? {
        1 => {
            let mut octets = [0_u8; 4];
            stream.read_exact(&mut octets).await?;
            std::net::Ipv4Addr::from(octets).to_string()
        }
        2 => {
            let length = stream.read_u8().await? as usize;
            if length == 0 {
                bail!("empty VLESS destination domain");
            }
            let mut domain = vec![0_u8; length];
            stream.read_exact(&mut domain).await?;
            String::from_utf8(domain).context("VLESS destination domain is not UTF-8")?
        }
        3 => {
            let mut octets = [0_u8; 16];
            stream.read_exact(&mut octets).await?;
            format!("[{}]", std::net::Ipv6Addr::from(octets))
        }
        kind => bail!("unsupported VLESS address type {kind:#x} after port {port}"),
    };
    Ok(format!("{host}:{port}"))
}

async fn serve_tcp(
    mut stream: TlsStream<TcpStream>,
    destination: String,
    outbound: OutboundConnector,
    traffic: Arc<UserTraffic>,
) -> Result<()> {
    let mut upstream = outbound
        .connect_tcp(&destination)
        .await
        .with_context(|| format!("connect VLESS destination {destination}"))?;
    stream.write_all(&[VERSION, 0]).await?;
    let (mut client_reader, mut client_writer) = tokio::io::split(stream);
    let (mut upstream_reader, mut upstream_writer) = upstream.split();
    let upload_traffic = Arc::clone(&traffic);
    let upload = async move {
        let mut buffer = vec![0_u8; RELAY_BUFFER_SIZE];
        loop {
            let count = client_reader.read(&mut buffer).await?;
            if count == 0 {
                upstream_writer.shutdown().await?;
                return Ok::<(), std::io::Error>(());
            }
            upstream_writer.write_all(&buffer[..count]).await?;
            upload_traffic.record_upload(count);
        }
    };
    let download = async move {
        let mut buffer = vec![0_u8; RELAY_BUFFER_SIZE];
        loop {
            let count = upstream_reader.read(&mut buffer).await?;
            if count == 0 {
                client_writer.shutdown().await?;
                return Ok::<(), std::io::Error>(());
            }
            client_writer.write_all(&buffer[..count]).await?;
            traffic.record_download(count);
        }
    };
    tokio::try_join!(upload, download)?;
    Ok(())
}

async fn serve_udp(
    mut stream: TlsStream<TcpStream>,
    destination: String,
    outbound: OutboundConnector,
    udp_timeout: Duration,
    traffic: Arc<UserTraffic>,
) -> Result<()> {
    let socket = Arc::new(outbound.open_udp().await?);
    stream.write_all(&[VERSION, 0]).await?;
    let (mut client_reader, mut client_writer) = tokio::io::split(stream);
    let upload_socket = Arc::clone(&socket);
    let upload_destination = destination.clone();
    let upload_traffic = Arc::clone(&traffic);
    let upload = async move {
        loop {
            let length = client_reader.read_u16().await? as usize;
            if length == 0 || length > MAX_UDP_PACKET_SIZE {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid VLESS UDP packet length",
                ));
            }
            let mut payload = vec![0_u8; length];
            client_reader.read_exact(&mut payload).await?;
            upload_socket.send_to(&payload, &upload_destination).await?;
            upload_traffic.record_upload(length);
        }
        #[allow(unreachable_code)]
        Ok::<(), std::io::Error>(())
    };
    let download = async move {
        let mut payload = Vec::with_capacity(MAX_UDP_PACKET_SIZE);
        loop {
            let (length, _) = socket.recv_from(udp_timeout, &mut payload).await?;
            client_writer.write_u16(length as u16).await?;
            client_writer.write_all(&payload[..length]).await?;
            client_writer.flush().await?;
            traffic.record_download(length);
        }
        #[allow(unreachable_code)]
        Ok::<(), std::io::Error>(())
    };
    tokio::try_join!(upload, download)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_stable_rfc_4122_user_id() {
        assert_eq!(
            user_id_string("poetry", "secret"),
            "d81001c4-7a96-45fe-85e0-c033049bd096"
        );
    }

    #[test]
    fn maps_user_ids_to_names() {
        let users = users(&[User {
            name: "poetry".to_owned(),
            password: "secret".to_owned(),
        }]);
        assert_eq!(
            users.get(&user_id("poetry", "secret")).map(String::as_str),
            Some("poetry")
        );
    }
}
