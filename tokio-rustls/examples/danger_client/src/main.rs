use argh::FromArgs;
use std::io;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use tokio::io::{copy, split, stdin as tokio_stdin, stdout as tokio_stdout, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, rustls::ClientConfig, TlsConnector};

/// Tokio Rustls dangle client example
#[derive(FromArgs)]
struct Options {
    /// host
    #[argh(positional)]
    host: String,

    /// port
    #[argh(option, short = 'p', default = "443")]
    port: u16,
}

mod danger {
    use rustls;
    use tokio_rustls::webpki;

    pub struct NoCertificateVerification {}

    impl rustls::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _roots: &rustls::RootCertStore,
            _presented_certs: &[rustls::Certificate],
            _dns_name: webpki::DNSNameRef<'_>,
            _ocsp: &[u8],
        ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
            Ok(rustls::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::Certificate,
            _dss: &rustls::internal::msgs::handshake::DigitallySignedStruct,
        ) -> Result<rustls::HandshakeSignatureValid, rustls::TLSError> {
            Ok(rustls::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::Certificate,
            _dss: &rustls::internal::msgs::handshake::DigitallySignedStruct,
        ) -> Result<rustls::HandshakeSignatureValid, rustls::TLSError> {
            Ok(rustls::HandshakeSignatureValid::assertion())
        }
    }
}

async fn get_tcps_stream(tcp_stream: TcpStream) -> tokio::io::Result<TlsStream<TcpStream>> {
    let mut config = ClientConfig::new();
    config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(danger::NoCertificateVerification {}));

    let connector = TlsConnector::from(Arc::new(config));
    let domain = tokio_rustls::webpki::DNSNameRef::try_from_ascii_str("localhost")?;
    connector.connect(domain, tcp_stream).await
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let options: Options = argh::from_env();

    let addr = (options.host.as_str(), options.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;

    let stream = TcpStream::connect(addr).await.unwrap();
    let mut stream = get_tcps_stream(stream).await?;

    let content = format!("GET / HTTP/1.0\r\n\r\n");

    let (mut stdin, mut stdout) = (tokio_stdin(), tokio_stdout());

    stream.write_all(content.as_bytes()).await?;

    let (mut reader, mut writer) = split(stream);

    tokio::select! {
        ret = copy(&mut reader, &mut stdout) => {
            ret?;
        },
        ret = copy(&mut stdin, &mut writer) => {
            ret?;
            writer.shutdown().await?
        }
    }

    Ok(())
}
