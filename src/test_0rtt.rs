use std::io;
use std::sync::Arc;
use std::net::ToSocketAddrs;
use futures::executor;
use futures::prelude::*;
use romio::tcp::TcpStream;
use rustls::ClientConfig;
use crate::{ TlsConnector, client::TlsStream };


async fn get(config: Arc<ClientConfig>, domain: &str, rtt0: bool)
    -> io::Result<(TlsStream<TcpStream>, String)>
{
    let connector = TlsConnector::from(config).early_data(rtt0);
    let input = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", domain);

    let addr = (domain, 443)
        .to_socket_addrs()?
        .next().unwrap();
    let domain = webpki::DNSNameRef::try_from_ascii_str(&domain).unwrap();
    let mut buf = Vec::new();

    let stream = TcpStream::connect(&addr).await?;
    let mut stream = connector.connect(domain, stream).await?;
    stream.write_all(input.as_bytes()).await?;
    stream.read_to_end(&mut buf).await?;

    Ok((stream, String::from_utf8(buf).unwrap()))
}

#[test]
fn test_0rtt() {
    let mut config = ClientConfig::new();
    config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    config.enable_early_data = true;
    let config = Arc::new(config);
    let domain = "mozilla-modern.badssl.com";

    let (_, output) = executor::block_on(get(config.clone(), domain, false)).unwrap();
    assert!(output.contains("<title>mozilla-modern.badssl.com</title>"));

    let (io, output) = executor::block_on(get(config.clone(), domain, true)).unwrap();
    assert!(output.contains("<title>mozilla-modern.badssl.com</title>"));

    assert_eq!(io.early_data.0, 0);
}
