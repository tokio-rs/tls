#![feature(async_await)]

use std::fs::File;
use std::sync::Arc;
use std::net::ToSocketAddrs;
use std::path::{ PathBuf, Path };
use std::io::{ self, BufReader };
use structopt::StructOpt;
use futures::task::SpawnExt;
use futures::prelude::*;
use futures::executor;
use romio::TcpListener;
use tokio_rustls::rustls::{ Certificate, NoClientAuth, PrivateKey, ServerConfig };
use tokio_rustls::rustls::internal::pemfile::{ certs, rsa_private_keys };
use tokio_rustls::TlsAcceptor;


#[derive(StructOpt)]
struct Options {
    addr: String,

    /// cert file
    #[structopt(short="c", long="cert", parse(from_os_str))]
    cert: PathBuf,

    /// key file
    #[structopt(short="k", long="key", parse(from_os_str))]
    key: PathBuf,

    /// echo mode
    #[structopt(short="e", long="echo-mode")]
    echo: bool
}

fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
}

fn load_keys(path: &Path) -> io::Result<Vec<PrivateKey>> {
    rsa_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
}


fn main() -> io::Result<()> {
    let options = Options::from_args();

    let addr = options.addr.to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::AddrNotAvailable))?;
    let certs = load_certs(&options.cert)?;
    let mut keys = load_keys(&options.key)?;
    let flag_echo = options.echo;

    let mut pool = executor::ThreadPool::new()?;
    let mut config = ServerConfig::new(NoClientAuth::new());
    config.set_single_cert(certs, keys.remove(0))
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let fut = async {
        let mut listener = TcpListener::bind(&addr)?;
        let mut incoming = listener.incoming();

        while let Some(stream) = incoming.next().await {
            let acceptor = acceptor.clone();

            let fut = async move {
                let stream = stream?;
                let peer_addr = stream.peer_addr()?;
                let mut stream = acceptor.accept(stream).await?;

                if flag_echo {
                    let (mut reader, mut writer) = stream.split();
                    let n = reader.copy_into(&mut writer).await?;
                    println!("Echo: {} - {}", peer_addr, n);
                } else {
                    stream.write_all(
                        &b"HTTP/1.0 200 ok\r\n\
                        Connection: close\r\n\
                        Content-length: 12\r\n\
                        \r\n\
                        Hello world!"[..]
                    ).await?;
                    stream.flush().await?;
                    println!("Hello: {}", peer_addr);
                }

                Ok(()) as io::Result<()>
            };

            pool.spawn(fut.unwrap_or_else(|err| eprintln!("{:?}", err))).unwrap();
        }

        Ok(())
    };

    executor::block_on(fut)
}
