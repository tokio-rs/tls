use std::io;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;
use std::net::ToSocketAddrs;
use std::io::BufReader;
use futures_util::future;
use structopt::StructOpt;
use tokio::runtime;
use tokio::net::TcpStream;
use tokio::io::{
    AsyncWriteExt,
    copy, split,
    stdin as tokio_stdin, stdout as tokio_stdout
};
use tokio_rustls::{ TlsConnector, rustls::ClientConfig, webpki::DNSNameRef };


#[derive(StructOpt)]
struct Options {
    host: String,

    /// port
    #[structopt(short="p", long="port", default_value="443")]
    port: u16,

    /// domain
    #[structopt(short="d", long="domain")]
    domain: Option<String>,

    /// cafile
    #[structopt(short="c", long="cafile", parse(from_os_str))]
    cafile: Option<PathBuf>
}


fn main() -> io::Result<()> {
    let options = Options::from_args();

    let addr = (options.host.as_str(), options.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    let domain = options.domain.unwrap_or(options.host);
    let content = format!(
        "GET / HTTP/1.0\r\nHost: {}\r\n\r\n",
        domain
    );

    let mut runtime = runtime::Builder::new()
        .basic_scheduler()
        .enable_io()
        .build()?;
    let mut config = ClientConfig::new();
    if let Some(cafile) = &options.cafile {
        let mut pem = BufReader::new(File::open(cafile)?);
        config.root_store.add_pem_file(&mut pem)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))?;
    } else {
        config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    }
    let connector = TlsConnector::from(Arc::new(config));

    let fut = async {
        let stream = TcpStream::connect(&addr).await?;

        let (mut stdin, mut stdout) = (tokio_stdin(), tokio_stdout());

        let domain = DNSNameRef::try_from_ascii_str(&domain)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))?;

        let mut stream = connector.connect(domain, stream).await?;
        stream.write_all(content.as_bytes()).await?;

        let (mut reader, mut writer) = split(stream);
        future::select(
            copy(&mut reader, &mut stdout),
            copy(&mut stdin, &mut writer)
        )
            .await
            .factor_first()
            .0?;

        Ok(())
    };

    runtime.block_on(fut)
}
