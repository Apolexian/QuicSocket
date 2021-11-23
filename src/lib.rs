use anyhow::{anyhow, Context, Result};
use futures_util::StreamExt;
use quinn::{ClientConfig, Endpoint, Incoming, ServerConfig};
use std::{error::Error, fs, net::SocketAddr, net::ToSocketAddrs, path::PathBuf, sync::Arc};
use url::Url;

pub struct QuicListener {}

impl QuicListener {
    #[allow(clippy::field_reassign_with_default)] // https://github.com/rust-lang/rust-clippy/issues/6527
    pub async fn recv(
        key: PathBuf,
        cert: PathBuf,
        listen: SocketAddr,
    ) -> Result<std::vec::Vec<u8>> {
        let (certs, key) = {
            let key_path = &key;
            let cert_path = &cert;
            let key = fs::read(key_path).context("failed to read private key")?;
            let key = if key_path.extension().map_or(false, |x| x == "der") {
                rustls::PrivateKey(key)
            } else {
                let pkcs8 = rustls_pemfile::pkcs8_private_keys(&mut &*key)
                    .context("malformed PKCS #8 private key")?;
                match pkcs8.into_iter().next() {
                    Some(x) => rustls::PrivateKey(x),
                    None => {
                        let rsa = rustls_pemfile::rsa_private_keys(&mut &*key)
                            .context("malformed PKCS #1 private key")?;
                        match rsa.into_iter().next() {
                            Some(x) => rustls::PrivateKey(x),
                            None => {
                                anyhow::bail!("no private keys found");
                            }
                        }
                    }
                }
            };
            let cert_chain = fs::read(cert_path).context("failed to read certificate chain")?;
            let cert_chain = if cert_path.extension().map_or(false, |x| x == "der") {
                vec![rustls::Certificate(cert_chain)]
            } else {
                rustls_pemfile::certs(&mut &*cert_chain)
                    .context("invalid PEM-encoded certificate")?
                    .into_iter()
                    .map(rustls::Certificate)
                    .collect()
            };
            (cert_chain, key)
        };
        let mut server_crypto = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
        server_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
        Arc::get_mut(&mut server_config.transport)
            .unwrap()
            .max_concurrent_uni_streams(0_u8.into());
        let (_, mut incoming) = quinn::Endpoint::server(server_config, listen)?;
        let mut ret = None;
        while let Some(conn) = incoming.next().await {
            ret = Some(tokio::spawn(handle_connection(conn)));
        }
        Ok(ret.unwrap().await.unwrap().unwrap())
    }

    pub async fn send(
        ca: String,
        remote_url: Url,
        host: Option<String>,
        payload: &mut [u8],
    ) -> Result<()> {
        let remote = (
            remote_url.host_str().unwrap(),
            remote_url.port().unwrap_or(4433),
        )
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow!("couldn't resolve to an address"))
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(&rustls::Certificate(fs::read(&ca)?)).unwrap();
        let mut client_crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
        let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap())?;
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(client_crypto)));
        let host = host
            .as_ref()
            .map_or_else(|| remote_url.host_str(), |x| Some(x))
            .ok_or_else(|| anyhow!("no hostname specified"))?;
        let new_conn = endpoint
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
        send.write_all(payload)
            .await
            .map_err(|e| anyhow!("failed to send request: {}", e))?;
        send.finish()
            .await
            .map_err(|e| anyhow!("failed to shutdown stream: {}", e))?;
        conn.close(0u32.into(), b"done");
        endpoint.wait_idle().await;
        Ok(())
    }
}

#[allow(unused)]
pub fn make_client_endpoint(
    bind_addr: SocketAddr,
    server_certs: &[&[u8]],
) -> Result<Endpoint, Box<dyn Error>> {
    let client_cfg = configure_client(server_certs)?;
    let mut endpoint = Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_cfg);
    Ok(endpoint)
}

#[allow(unused)]
pub fn make_server_endpoint(bind_addr: SocketAddr) -> Result<(Incoming, Vec<u8>), Box<dyn Error>> {
    let (server_config, server_cert) = configure_server()?;
    let (_endpoint, incoming) = Endpoint::server(server_config, bind_addr)?;
    Ok((incoming, server_cert))
}

fn configure_client(server_certs: &[&[u8]]) -> Result<ClientConfig, Box<dyn Error>> {
    let mut certs = rustls::RootCertStore::empty();
    for cert in server_certs {
        certs.add(&rustls::Certificate(cert.to_vec()))?;
    }

    Ok(ClientConfig::with_root_certificates(certs))
}

#[allow(clippy::field_reassign_with_default)] // https://github.com/rust-lang/rust-clippy/issues/6527
fn configure_server() -> Result<(ServerConfig, Vec<u8>), Box<dyn Error>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = cert.serialize_der().unwrap();
    let priv_key = cert.serialize_private_key_der();
    let priv_key = rustls::PrivateKey(priv_key);
    let cert_chain = vec![rustls::Certificate(cert_der.clone())];

    let mut server_config = ServerConfig::with_single_cert(cert_chain, priv_key)?;
    Arc::get_mut(&mut server_config.transport)
        .unwrap()
        .max_concurrent_uni_streams(0_u8.into());

    Ok((server_config, cert_der))
}

#[allow(unused)]
pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

async fn handle_connection(conn: quinn::Connecting) -> Result<std::vec::Vec<u8>> {
    let quinn::NewConnection {
        connection: _,
        mut bi_streams,
        ..
    } = conn.await?;
    let mut req = None;
    async {
        while let Some(stream) = bi_streams.next().await {
            let stream = match stream {
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    return Ok(());
                }
                Err(e) => {
                    return Err(e);
                }
                Ok(s) => s,
            };
            req = Some(tokio::spawn(handle_request(stream)));
        }
        Ok(())
    }
    .await?;

    Ok(req.unwrap().await.unwrap().unwrap())
}

async fn handle_request(
    (_, recv): (quinn::SendStream, quinn::RecvStream),
) -> Result<std::vec::Vec<u8>> {
    let req = recv
        .read_to_end(64 * 1024)
        .await
        .map_err(|e| anyhow!("failed reading request: {}", e))?;
    Ok(req)
}
