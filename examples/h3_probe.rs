use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use bytes::{Buf, BytesMut};
use h3::client;
use http::Request;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::{CertificateDer, pem::PemObject};

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let certificate = CertificateDer::pem_file_iter("integration/cert.pem")?
        .next()
        .context("missing integration certificate")??;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate)?;
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic = QuicClientConfig::try_from(tls)?;
    let mut endpoint = quinn::Endpoint::client("[::]:0".parse()?)?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));
    let address: SocketAddr = "127.0.0.1:14443".parse()?;
    let connection = endpoint.connect(address, "localhost")?.await?;
    let (mut driver, mut client) = client::new(h3_quinn::Connection::new(connection)).await?;
    let driver_task = tokio::spawn(async move {
        futures::future::poll_fn(|context| driver.poll_close(context)).await
    });

    let request = Request::get("https://localhost/probe?source=h3-probe").body(())?;
    let mut stream = client.send_request(request).await?;
    stream.finish().await?;
    let response = stream.recv_response().await?;
    let status = response.status();
    let marker = response
        .headers()
        .get("x-hy2-masquerade")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let mut body = BytesMut::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    println!(
        "status={status} marker={marker} body={}",
        String::from_utf8_lossy(&body)
    );

    let request = Request::post("https://hysteria/auth")
        .header("hysteria-auth", "integration-password")
        .header("hysteria-cc-rx", "12500000")
        .body(())?;
    let mut stream = client.send_request(request).await?;
    stream.finish().await?;
    let response = stream.recv_response().await?;
    println!(
        "auth_status={} udp={} cc_rx={}",
        response.status(),
        response
            .headers()
            .get("hysteria-udp")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default(),
        response
            .headers()
            .get("hysteria-cc-rx")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
    );
    drop(client);
    let _ = driver_task.await;
    endpoint.wait_idle().await;
    Ok(())
}
