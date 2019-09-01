use std::{ io, thread };
use std::io::{ BufReader, Cursor };
use std::sync::Arc;
use std::sync::mpsc::channel;
use std::net::SocketAddr;
use lazy_static::lazy_static;
use tokio::prelude::*;
use tokio::runtime::current_thread;
use tokio::net::{ TcpListener, TcpStream };
use futures_util::try_future::TryFutureExt;
use rustls::{ ServerConfig, ClientConfig };
use rustls::internal::pemfile::{ certs, rsa_private_keys };
use tokio_rustls::{ TlsConnector, TlsAcceptor };

const CERT: &str = include_str!("end.cert");
const CHAIN: &str = include_str!("end.chain");
const RSA: &str = include_str!("end.rsa");

lazy_static!{
    static ref TEST_SERVER: (SocketAddr, &'static str, &'static str) = {
        let cert = certs(&mut BufReader::new(Cursor::new(CERT))).unwrap();
        let mut keys = rsa_private_keys(&mut BufReader::new(Cursor::new(RSA))).unwrap();

        let mut config = ServerConfig::new(rustls::NoClientAuth::new());
        config.set_single_cert(cert, keys.pop().unwrap())
            .expect("invalid key or certificate");
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let (send, recv) = channel();

        thread::spawn(move || {
            let mut runtime = current_thread::Runtime::new().unwrap();
            let handle = runtime.handle();

            let done = async move {
                let addr = SocketAddr::from(([127, 0, 0, 1], 0));
                let listener = TcpListener::bind(&addr).await?;

                send.send(listener.local_addr()?).unwrap();

                let mut incoming = listener.incoming();
                while let Some(stream) = incoming.next().await {
                    let acceptor = acceptor.clone();
                    let fut = async move {
                        let mut stream = acceptor.accept(stream?).await?;

// TODO split
//                        let (mut reader, mut write) = stream.split();
//                        reader.copy(&mut write).await?;

                        let mut buf = vec![0; 8192];
                        let n = stream.read(&mut buf).await?;
                        stream.write(&buf[..n]).await?;

                        Ok(()) as io::Result<()>
                    };

                    handle.spawn(fut.unwrap_or_else(|err| eprintln!("{:?}", err))).unwrap();
                }

                Ok(()) as io::Result<()>
            };

            runtime.block_on(done.unwrap_or_else(|err| eprintln!("{:?}", err)));
        });

        let addr = recv.recv().unwrap();
        (addr, "localhost", CHAIN)
    };
}

fn start_server() -> &'static (SocketAddr, &'static str, &'static str) {
    &*TEST_SERVER
}

async fn start_client(addr: SocketAddr, domain: &str, config: Arc<ClientConfig>) -> io::Result<()> {
    const FILE: &'static [u8] = include_bytes!("../README.md");

    let domain = webpki::DNSNameRef::try_from_ascii_str(domain).unwrap();
    let config = TlsConnector::from(config);
    let mut buf = vec![0; FILE.len()];

    let stream = TcpStream::connect(&addr).await?;
    let mut stream = config.connect(domain, stream).await?;
    stream.write_all(FILE).await?;
    stream.read_exact(&mut buf).await?;

    assert_eq!(buf, FILE);

    stream.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn pass() -> io::Result<()> {
    let (addr, domain, chain) = start_server();

    // TODO: not sure how to resolve this right now but since
    // TcpStream::bind now returns a future it creates a race
    // condition until its ready sometimes.
    use std::time::*;
    let deadline = Instant::now() + Duration::from_secs(1);
    tokio::timer::delay(deadline);

    let mut config = ClientConfig::new();
    let mut chain = BufReader::new(Cursor::new(chain));
    config.root_store.add_pem_file(&mut chain).unwrap();
    let config = Arc::new(config);

    start_client(addr.clone(), domain, config.clone()).await?;

    Ok(())
}

#[tokio::test]
async fn fail() -> io::Result<()> {
    let (addr, domain, chain) = start_server();

    let mut config = ClientConfig::new();
    let mut chain = BufReader::new(Cursor::new(chain));
    config.root_store.add_pem_file(&mut chain).unwrap();
    let config = Arc::new(config);

    assert_ne!(domain, &"google.com");
    let ret = start_client(addr.clone(), "google.com", config).await;
    assert!(ret.is_err());

    Ok(())
}
