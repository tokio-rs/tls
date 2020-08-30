use argh::FromArgs;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{copy, split, stdin as tokio_stdin, stdout as tokio_stdout, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{rustls::ClientConfig, webpki::DNSNameRef, TlsConnector};

/// Tokio Rustls client example
#[derive(FromArgs)]
struct Options {
    /// host
    #[argh(positional)]
    host: String,

    /// port
    #[argh(option, short = 'p', default = "443")]
    port: u16,

    /// domain
    #[argh(option, short = 'd')]
    domain: Option<String>,

    /// cafile
    #[argh(option, short = 'c')]
    cafile: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let options: Options = argh::from_env();

    let addr = (options.host.as_str(), options.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    let domain = options.domain.unwrap_or(options.host);
    let content = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", domain);

    let mut config = ClientConfig::new();
    if let Some(cafile) = &options.cafile {
        let mut pem = BufReader::new(File::open(cafile)?);
        config
            .root_store
            .add_pem_file(&mut pem)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))?;
    } else {
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    }
    let connector = TlsConnector::from(Arc::new(config));

    let stream = TcpStream::connect(&addr).await?;

    let (mut stdin, mut stdout) = (tokio_stdin(), tokio_stdout());

    let domain = DNSNameRef::try_from_ascii_str(&domain)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))?;

    let mut stream = connector.connect(domain, stream).await?;
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
