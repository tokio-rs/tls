extern crate rustls;
extern crate futures;
extern crate tokio;
extern crate tokio_rustls;
extern crate webpki;

use std::{ io, thread };
use std::io::{ BufReader, Cursor };
use std::sync::Arc;
use std::sync::mpsc::channel;
use std::net::{ SocketAddr, IpAddr, Ipv4Addr };
use tokio::prelude::*;
// use futures::{ FutureExt, StreamExt };
use tokio::net::{ TcpListener, TcpStream };
use tokio::io as aio;
use rustls::{ Certificate, PrivateKey, ServerConfig, ClientConfig };
use rustls::internal::pemfile::{ certs, rsa_private_keys };
use tokio_rustls::{ ClientConfigExt, ServerConfigExt };

const CERT: &str = include_str!("end.cert");
const CHAIN: &str = include_str!("end.chain");
const RSA: &str = include_str!("end.rsa");
const HELLO_WORLD: &[u8] = b"Hello world!";


fn start_server(cert: Vec<Certificate>, rsa: PrivateKey) -> SocketAddr {
    let mut config = ServerConfig::new(rustls::NoClientAuth::new());
    config.set_single_cert(cert, rsa);
    let config = Arc::new(config);

    let (send, recv) = channel();

    thread::spawn(move || {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        let listener = TcpListener::bind(&addr).unwrap();

        send.send(listener.local_addr().unwrap()).unwrap();

        let done = listener.incoming()
            .for_each(move |stream| {
                let done = config.accept_async(stream)
                    .and_then(|stream| aio::read_exact(stream, vec![0; HELLO_WORLD.len()]))
                    .and_then(|(stream, buf)| {
                        assert_eq!(buf, HELLO_WORLD);
                        aio::write_all(stream, HELLO_WORLD)
                    })
                    .map(drop)
                    .map_err(drop);

                tokio::spawn(done);
                Ok(())
            })
            .then(|_| Ok(()));

        tokio::runtime::run(done);
    });

    recv.recv().unwrap()
}

fn start_client(addr: &SocketAddr, domain: &str,
                chain: Option<BufReader<Cursor<&str>>>) -> io::Result<()> {
    let domain = webpki::DNSNameRef::try_from_ascii_str(domain).unwrap();
    let mut config = ClientConfig::new();
    if let Some(mut chain) = chain {
        config.root_store.add_pem_file(&mut chain).unwrap();
    }
    let config = Arc::new(config);

    let done = TcpStream::connect(addr)
        .and_then(|stream| config.connect_async(domain, stream))
        .and_then(|stream| aio::write_all(stream, HELLO_WORLD))
        .and_then(|(stream, _)| aio::read_exact(stream, vec![0; HELLO_WORLD.len()]))
        .and_then(|(_, buf)| {
            assert_eq!(buf, HELLO_WORLD);
            Ok(())
        });

    done.wait()
}


#[test]
fn main() {
    let cert = certs(&mut BufReader::new(Cursor::new(CERT))).unwrap();
    let mut keys = rsa_private_keys(&mut BufReader::new(Cursor::new(RSA))).unwrap();
    let chain = BufReader::new(Cursor::new(CHAIN));

    let addr = start_server(cert, keys.pop().unwrap());
    start_client(&addr, "localhost", Some(chain)).unwrap();
}

#[should_panic]
#[test]
fn fail() {
    let cert = certs(&mut BufReader::new(Cursor::new(CERT))).unwrap();
    let mut keys = rsa_private_keys(&mut BufReader::new(Cursor::new(RSA))).unwrap();
    let chain = BufReader::new(Cursor::new(CHAIN));

    let addr = start_server(cert, keys.pop().unwrap());

    start_client(&addr, "google.com", Some(chain)).unwrap();
}
