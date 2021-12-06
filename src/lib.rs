use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures_util::StreamExt;
use quinn::{Endpoint, Incoming, ServerConfig};
use std::{error::Error, fs, net::SocketAddr, net::ToSocketAddrs, sync::Arc};
use url::Url;

#[async_trait]
pub trait QuicSocket {
    fn new(addr: Option<SocketAddr>) -> Self;
    async fn send(&mut self, payload: Vec<u8>) -> Result<()>;
    async fn recv(&mut self) -> Result<std::vec::Vec<u8>>;
}

pub struct QuicServer {
    pub endpoint: Endpoint,
    pub incoming: Incoming,
}

pub struct QuicClient {
    pub endpoint: Endpoint,
}

#[async_trait]
impl QuicSocket for QuicServer {
    fn new(addr: Option<SocketAddr>) -> QuicServer {
        let server_config = configure_server().unwrap();
        let (endpoint, incoming) = quinn::Endpoint::server(server_config, addr.unwrap()).unwrap();
        QuicServer { endpoint, incoming }
    }
    async fn send(&mut self, payload: Vec<u8>) -> Result<()> {
        while let Some(conn) = self.incoming.next().await {
            let quinn::NewConnection { mut bi_streams, .. } = conn.await?;
            while let Some(stream) = bi_streams.next().await {
                let stream = match stream {
                    Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                        return Ok(());
                    }
                    Err(e) => {
                        return Err(anyhow::Error::new(e));
                    }
                    Ok(s) => s,
                };
                tokio::spawn(handle_send(stream, payload.clone()));
                break;
            }
            break;
        }
        Ok(())
    }
    async fn recv(&mut self) -> Result<std::vec::Vec<u8>> {
        let mut ret = None;
        while let Some(conn) = self.incoming.next().await {
            ret = Some(tokio::spawn(handle_connection(conn)).await);
            break;
        }
        Ok(ret.unwrap().unwrap().unwrap())
    }
}

#[async_trait]
impl QuicSocket for QuicClient {
    fn new(_addr: Option<SocketAddr>) -> Self {
        let ca = "cert.der".to_string();
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(&rustls::Certificate(fs::read(&ca).unwrap()))
            .unwrap();
        let mut client_crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
        let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(client_crypto)));
        QuicClient { endpoint }
    }
    async fn send(&mut self, payload: Vec<u8>) -> Result<()> {
        let remote_url = Url::parse("http://127.0.0.1:4442").unwrap();
        let host = Some("localhost".to_string());
        let remote = (
            remote_url.host_str().unwrap(),
            remote_url.port().unwrap_or(4433),
        )
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow!("couldn't resolve to an address"))
            .unwrap();

        let host = host
            .as_ref()
            .map_or_else(|| remote_url.host_str(), |x| Some(x))
            .ok_or_else(|| anyhow!("no hostname specified"))?;
        let new_conn = self
            .endpoint
            .connect(remote, host)?
            .await
            .map_err(|e| anyhow!("failed to connect: {}", e))?;
        let quinn::NewConnection {
            connection: conn, ..
        } = new_conn;
        let (mut send, _) = conn
            .open_bi()
            .await
            .map_err(|e| anyhow!("failed to open stream: {}", e))?;
        send.write_all(&payload)
            .await
            .map_err(|e| anyhow!("failed to send request: {}", e))?;
        send.finish()
            .await
            .map_err(|e| anyhow!("failed to shutdown stream: {}", e))?;
        conn.close(0u32.into(), b"done");
        self.endpoint.wait_idle().await;
        Ok(())
    }
    async fn recv(&mut self) -> Result<std::vec::Vec<u8>> {
        let remote_url = Url::parse("http://127.0.0.1:4442").unwrap();
        let host = Some("localhost".to_string());
        let remote = (
            remote_url.host_str().unwrap(),
            remote_url.port().unwrap_or(4433),
        )
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow!("couldn't resolve to an address"))
            .unwrap();

        let host = host
            .as_ref()
            .map_or_else(|| remote_url.host_str(), |x| Some(x))
            .ok_or_else(|| anyhow!("no hostname specified"))?;
        let new_conn = self
            .endpoint
            .connect(remote, host)?
            .await
            .map_err(|e| anyhow!("failed to connect: {}", e))?;
        let quinn::NewConnection {
            connection: conn, ..
        } = new_conn;
        let (_, recv) = conn
            .open_bi()
            .await
            .map_err(|e| anyhow!("failed to open stream: {}", e))?;
        let recv_bytes = recv
            .read_to_end(usize::max_value())
            .await
            .map_err(|e| anyhow!("failed to read response: {}", e))?;
        Ok(recv_bytes)
    }
}

#[allow(clippy::field_reassign_with_default)] // https://github.com/rust-lang/rust-clippy/issues/6527
fn configure_server() -> Result<ServerConfig, Box<dyn Error>> {
    let cert_chain = fs::read("./key.pem")?;
    let key = fs::read("./cert.pem")?;
    let priv_key = rustls::PrivateKey(key);
    let cert = vec![rustls::Certificate(cert_chain.clone())];
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert, priv_key)?;
    server_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
    Arc::get_mut(&mut server_config.transport)
        .unwrap()
        .max_concurrent_uni_streams(0_u8.into());
    Ok(server_config)
}

#[allow(unused)]
#[allow(clippy::field_reassign_with_default)] // https://github.com/rust-lang/rust-clippy/issues/6527
fn gen_certificates(path: String) -> Result<(), Box<dyn Error>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = cert.serialize_der().unwrap();
    let priv_key = cert.serialize_private_key_der();
    let priv_key = rustls::PrivateKey(priv_key);
    let cert_chain = vec![rustls::Certificate(cert_der.clone())];
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, priv_key)?;
    server_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    fs::write(path, &cert_der).unwrap();
    Ok(())
}

#[allow(unused)]
pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

async fn handle_connection(conn: quinn::Connecting) -> Result<std::vec::Vec<u8>> {
    Ok(handle_spawn(conn).await.unwrap())
}

async fn handle_spawn(conn: quinn::Connecting) -> Result<std::vec::Vec<u8>> {
    let quinn::NewConnection {
        connection: _,
        mut bi_streams,
        ..
    } = conn.await?;
    let mut req = None;
    while let Some(stream) = bi_streams.next().await {
        let stream = match stream {
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                return Ok(vec![]);
            }
            Err(e) => {
                return Err(anyhow::Error::new(e));
            }
            Ok(s) => s,
        };
        req = Some(tokio::spawn(handle_request(stream)).await?);
        break;
    }
    Ok(req.unwrap())
}

async fn handle_request((_, recv): (quinn::SendStream, quinn::RecvStream)) -> std::vec::Vec<u8> {
    let req = recv
        .read_to_end(64 * 1024)
        .await
        .map_err(|e| anyhow!("failed reading request: {}", e))
        .unwrap();
    req
}

async fn handle_send(
    (mut send, _): (quinn::SendStream, quinn::RecvStream),
    payload: Vec<u8>,
) -> Result<()> {
    send.write_all(&payload)
        .await
        .map_err(|e| anyhow!("failed to send response: {}", e))?;
    send.finish()
        .await
        .map_err(|e| anyhow!("failed to shutdown stream: {}", e))?;
    Ok(())
}
