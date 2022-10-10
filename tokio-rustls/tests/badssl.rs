use rustls::PrivateKey;
use rustls_pemfile::{certs, rsa_private_keys};
use std::convert::TryFrom;
use std::io;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{
    client::TlsStream,
    rustls::{self, ClientConfig, OwnedTrustAnchor},
    TlsConnector,
};

const CLIENT_CERT: &str = include_str!("client.cert");
const CLIENT_RSA: &str = include_str!("client.rsa");

async fn get(
    config: Arc<ClientConfig>,
    domain: &str,
    port: u16,
) -> io::Result<(TlsStream<TcpStream>, String)> {
    let connector = TlsConnector::from(config);
    let input = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", domain);

    let addr = (domain, port).to_socket_addrs()?.next().unwrap();
    let domain = rustls::ServerName::try_from(domain).unwrap();
    let mut buf = Vec::new();

    let stream = TcpStream::connect(&addr).await?;
    let mut stream = connector.connect(domain, stream).await?;
    stream.write_all(input.as_bytes()).await?;
    stream.flush().await?;
    stream.read_to_end(&mut buf).await?;

    Ok((stream, String::from_utf8(buf).unwrap()))
}

#[tokio::test]
async fn test_tls12() -> io::Result<()> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    let config = rustls::ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let config = Arc::new(config);
    let domain = "tls-v1-2.badssl.com";

    let (_, output) = get(config.clone(), domain, 1012).await?;
    assert!(
        output.contains("<title>tls-v1-2.badssl.com</title>"),
        "failed badssl test, output: {}",
        output
    );

    Ok(())
}

#[ignore]
#[should_panic]
#[test]
fn test_tls13() {
    unimplemented!("todo https://github.com/chromium/badssl.com/pull/373");
}

#[tokio::test]
async fn test_modern() -> io::Result<()> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let config = Arc::new(config);
    let domain = "mozilla-modern.badssl.com";

    let (_, output) = get(config.clone(), domain, 443).await?;
    assert!(
        output.contains("<title>mozilla-modern.badssl.com</title>"),
        "failed badssl test, output: {}",
        output
    );

    Ok(())
}

#[tokio::test]
async fn test_client() -> io::Result<()> {
    let cert = certs(&mut io::BufReader::new(CLIENT_CERT.as_bytes()))
        .unwrap()
        .drain(..)
        .map(rustls::Certificate)
        .collect();

    let mut keys = rsa_private_keys(&mut io::BufReader::new(io::Cursor::new(CLIENT_RSA))).unwrap();
    let mut keys = keys.drain(..).map(PrivateKey);

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_single_cert(cert, keys.next().unwrap())
        .unwrap();
    let config = Arc::new(config);
    let domain = "client.badssl.com";

    let (_, output) = get(config.clone(), domain, 443).await?;
    assert!(
        output.contains("<title>client.badssl.com</title>"),
        "failed badssl test, output: {}",
        output
    );

    Ok(())
}

#[tokio::test]
async fn test_client_cert_missing() -> io::Result<()> {
    let cert = certs(&mut io::BufReader::new(CLIENT_CERT.as_bytes()))
        .unwrap()
        .drain(..)
        .map(rustls::Certificate)
        .collect();

    let mut keys = rsa_private_keys(&mut io::BufReader::new(io::Cursor::new(CLIENT_RSA))).unwrap();
    let mut keys = keys.drain(..).map(PrivateKey);

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_single_cert(cert, keys.next().unwrap())
        .unwrap();
    let config = Arc::new(config);
    let domain = "client-cert-missing.badssl.com";

    let (_, output) = get(config.clone(), domain, 443).await?;
    assert!(
        output.contains("<title>400 The SSL certificate error</title>"),
        "failed badssl test, output: {}",
        output
    );

    Ok(())
}
