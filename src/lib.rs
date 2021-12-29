use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures_util::StreamExt;
use quinn::{Connection, Endpoint, IncomingBiStreams, ServerConfig};
use std::{error::Error, fs, net::SocketAddr, net::ToSocketAddrs, sync::Arc};
use url::Url;

#[async_trait]
pub trait QuicSocket {
    async fn new(addr: Option<SocketAddr>) -> Self;
    async fn send(&mut self, payload: Vec<u8>) -> Result<()>;
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize>;
}

pub struct QuicServer {
    pub endpoint: Endpoint,
    pub connection: Connection,
    pub bi_streams: IncomingBiStreams,
}

pub struct QuicClient {
    pub endpoint: Endpoint,
    pub connection: Connection,
    pub bi_streams: IncomingBiStreams,
}

#[async_trait]
impl QuicSocket for QuicServer {
    async fn new(addr: Option<SocketAddr>) -> QuicServer {
        let server_config = configure_server().unwrap();
        let (endpoint, mut incoming) =
            quinn::Endpoint::server(server_config, addr.unwrap()).unwrap();
        let new_conn = incoming.next().await.unwrap().await.unwrap();
        let quinn::NewConnection {
            connection: conn,
            bi_streams,
            ..
        } = new_conn;
        QuicServer {
            endpoint,
            connection: conn,
            bi_streams,
        }
    }
    async fn send(&mut self, payload: Vec<u8>) -> Result<()> {
        let (mut send, _) = self
            .connection
            .open_bi()
            .await
            .map_err(|e| anyhow!("failed to open stream: {}", e))
            .unwrap();
        send.write_all(&payload)
            .await
            .map_err(|e| anyhow!("failed to send request: {}", e))?;
        send.finish()
            .await
            .map_err(|e| anyhow!("failed to shutdown stream: {}", e))?;
        Ok(())
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let (_, mut recv) = self.bi_streams.next().await.unwrap().unwrap();
        let len = recv
            .read(buf)
            .await
            .map_err(|e| anyhow!("failed to read response: {}", e))?;
        Ok(len.unwrap())
    }
}

#[async_trait]
impl QuicSocket for QuicClient {
    async fn new(_addr: Option<SocketAddr>) -> Self {
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
        let remote_url = Url::parse("http://127.0.0.1:4442").unwrap();
        let host = Some("localhost".to_string());
        let remote = (
            remote_url.host_str().unwrap(),
            remote_url.port().unwrap_or(4433),
        )
            .to_socket_addrs()
            .unwrap()
            .next()
            .ok_or_else(|| anyhow!("couldn't resolve to an address"))
            .unwrap();

        let host = host
            .as_ref()
            .map_or_else(|| remote_url.host_str(), |x| Some(x))
            .ok_or_else(|| anyhow!("no hostname specified"))
            .unwrap();
        let new_conn = endpoint
            .connect(remote, host)
            .unwrap()
            .await
            .map_err(|e| anyhow!("failed to connect: {}", e))
            .unwrap();
        let quinn::NewConnection {
            connection: conn,
            bi_streams,
            ..
        } = new_conn;
        QuicClient {
            endpoint,
            connection: conn,
            bi_streams,
        }
    }
    async fn send(&mut self, payload: Vec<u8>) -> Result<()> {
        let (mut send, _) = self
            .connection
            .open_bi()
            .await
            .map_err(|e| anyhow!("failed to open stream: {}", e))
            .unwrap();
        send.write_all(&payload)
            .await
            .map_err(|e| anyhow!("failed to send request: {}", e))?;
        send.finish()
            .await
            .map_err(|e| anyhow!("failed to shutdown stream: {}", e))?;
        Ok(())
    }
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let (_, mut recv) = self.bi_streams.next().await.unwrap().unwrap();
        let len = recv
            .read(buf)
            .await
            .map_err(|e| anyhow!("failed to read response: {}", e))?;
        Ok(len.unwrap())
    }
}

#[allow(clippy::field_reassign_with_default)] // https://github.com/rust-lang/rust-clippy/issues/6527
fn configure_server() -> Result<ServerConfig, Box<dyn Error>> {
    let cert_chain = fs::read("./cert.der")?;
    let key = fs::read("./key.der")?;
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
pub fn gen_certificates() -> Result<(), Box<dyn Error>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = cert.serialize_der().unwrap();
    fs::write("./cert.der".to_string(), &cert_der).unwrap();
    let priv_key = cert.serialize_private_key_der();
    fs::write("./key.der".to_string(), &priv_key).unwrap();
    let key = rustls::PrivateKey(priv_key);
    let cert = vec![rustls::Certificate(cert_der.clone())];
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert, key)?;
    server_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    Ok(())
}

#[allow(unused)]
pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];
