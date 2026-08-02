use std::{io, net::SocketAddr, time::Duration};

use tokio::net::{TcpSocket, TcpStream, UdpSocket};

use crate::config::{OutboundConfig, OutboundMode};

#[derive(Clone, Copy, Debug)]
pub(crate) struct OutboundConnector {
    mode: OutboundMode,
}

pub(crate) struct OutboundUdpSession {
    ipv4: Option<UdpSocket>,
    ipv6: Option<UdpSocket>,
    mode: OutboundMode,
}

impl OutboundConnector {
    pub(crate) fn new(config: &OutboundConfig) -> Self {
        Self { mode: config.mode }
    }

    pub(crate) async fn connect_tcp(&self, destination: &str) -> io::Result<TcpStream> {
        let addresses = self.resolve(destination).await?;
        let mut last_error = None;
        for address in addresses {
            match self.connect_address(address).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "no usable destination address",
            )
        }))
    }

    pub(crate) async fn connect_address(&self, address: SocketAddr) -> io::Result<TcpStream> {
        let socket = if address.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        socket.connect(address).await
    }

    pub(crate) async fn open_udp(&self) -> io::Result<OutboundUdpSession> {
        let ipv4 = if self.mode == OutboundMode::Ipv6Only {
            None
        } else {
            Some(UdpSocket::bind("0.0.0.0:0").await?)
        };
        let ipv6 = if self.mode == OutboundMode::Ipv4Only {
            None
        } else {
            UdpSocket::bind("[::]:0").await.ok()
        };
        if ipv4.is_none() && ipv6.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "no usable UDP address family",
            ));
        }
        Ok(OutboundUdpSession {
            ipv4,
            ipv6,
            mode: self.mode,
        })
    }

    pub(crate) async fn resolve(&self, destination: &str) -> io::Result<Vec<SocketAddr>> {
        let addresses = tokio::net::lookup_host(destination)
            .await?
            .collect::<Vec<_>>();
        let addresses = order_addresses(addresses, self.mode);
        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("no address matching outbound mode for {destination}"),
            ));
        }
        Ok(addresses)
    }
}

impl OutboundUdpSession {
    pub(crate) async fn send_to(&self, payload: &[u8], destination: &str) -> io::Result<usize> {
        let addresses = tokio::net::lookup_host(destination)
            .await?
            .collect::<Vec<_>>();
        let addresses = order_addresses(addresses, self.mode);
        let mut last_error = None;
        for address in addresses {
            let socket = if address.is_ipv4() {
                &self.ipv4
            } else {
                &self.ipv6
            };
            let Some(socket) = socket else { continue };
            match socket.send_to(payload, address).await {
                Ok(written) => return Ok(written),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("no usable UDP destination for {destination}"),
            )
        }))
    }

    pub(crate) async fn recv_from(
        &self,
        timeout: Duration,
        buffer: &mut Vec<u8>,
    ) -> io::Result<(usize, String)> {
        buffer.resize(u16::MAX as usize, 0);
        let received = tokio::time::timeout(timeout, async {
            match (&self.ipv4, &self.ipv6) {
                (Some(ipv4), Some(ipv6)) => {
                    let mut ipv6_buffer = vec![0_u8; buffer.len()];
                    tokio::select! {
                        value = ipv4.recv_from(buffer) => value,
                        value = ipv6.recv_from(&mut ipv6_buffer) => {
                            let (length, source) = value?;
                            buffer[..length].copy_from_slice(&ipv6_buffer[..length]);
                            Ok((length, source))
                        },
                    }
                }
                (Some(ipv4), None) => ipv4.recv_from(buffer).await,
                (None, Some(ipv6)) => ipv6.recv_from(buffer).await,
                (None, None) => unreachable!("validated UDP session"),
            }
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "UDP session timed out"))??;
        Ok((received.0, received.1.to_string()))
    }
}

fn order_addresses(addresses: Vec<SocketAddr>, mode: OutboundMode) -> Vec<SocketAddr> {
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    for address in addresses {
        let target = if address.is_ipv4() {
            &mut ipv4
        } else {
            &mut ipv6
        };
        if !target.contains(&address) {
            target.push(address);
        }
    }
    match mode {
        OutboundMode::PreferIpv4 => {
            ipv4.extend(ipv6);
            ipv4
        }
        OutboundMode::Ipv4Only => ipv4,
        OutboundMode::Ipv6Only => ipv6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orders_and_filters_address_families() {
        let ipv4 = "192.0.2.1:443".parse().unwrap();
        let ipv6 = "[2001:db8::1]:443".parse().unwrap();
        assert_eq!(
            order_addresses(vec![ipv6, ipv4], OutboundMode::PreferIpv4),
            vec![ipv4, ipv6]
        );
        assert_eq!(
            order_addresses(vec![ipv6, ipv4], OutboundMode::Ipv4Only),
            vec![ipv4]
        );
        assert_eq!(
            order_addresses(vec![ipv4, ipv6], OutboundMode::Ipv6Only),
            vec![ipv6]
        );
    }
}
