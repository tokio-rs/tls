extern crate rustls;
extern crate futures;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_rustls;

use std::{ io, thread };
use std::io::{ BufReader, Cursor };
use std::sync::Arc;
use std::sync::mpsc::channel;
use std::net::{ SocketAddr, IpAddr, Ipv4Addr };
use futures::{ Future, Stream };
use tokio_core::reactor::Core;
use tokio_core::net::{ TcpListener, TcpStream };
use tokio_io::io as aio;
use rustls::{ Certificate, PrivateKey, ServerConfig, ClientConfig };
use rustls::internal::pemfile::{ certs, rsa_private_keys };
use tokio_rustls::{ ClientConfigExt, ServerConfigExt };

const CERT: &str = include_str!("end.cert");
const CHAIN: &str = include_str!("end.chain");
const RSA: &str = include_str!("end.rsa");
const HELLO_WORLD: &[u8] = b"Hello world!";


fn start_server(cert: Vec<Certificate>, rsa: PrivateKey) -> SocketAddr {
    let mut config = ServerConfig::new();
    config.set_single_cert(cert, rsa);
    let config = Arc::new(config);

    let (send, recv) = channel();

    thread::spawn(move || {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        let mut core = Core::new().unwrap();
        let handle = core.handle();
        let listener = TcpListener::bind(&addr, &handle).unwrap();

        send.send(listener.local_addr().unwrap()).unwrap();

        let done = listener.incoming()
            .for_each(|(stream, _)| {
                let done = config.accept_async(stream)
                    .and_then(|stream| aio::read_exact(stream, vec![0; HELLO_WORLD.len()]))
                    .and_then(|(stream, buf)| {
                        assert_eq!(buf, HELLO_WORLD);
                        aio::write_all(stream, HELLO_WORLD)
                    })
                    .map(drop)
                    .map_err(drop);

                handle.spawn(done);
                Ok(())
            })
            .map(drop)
            .map_err(drop);
        core.run(done).unwrap();
    });

    recv.recv().unwrap()
}

fn start_client(addr: &SocketAddr, domain: Option<&str>, chain: Option<BufReader<Cursor<&str>>>) -> io::Result<()> {
    let mut config = ClientConfig::new();
    if let Some(mut chain) = chain {
        config.root_store.add_pem_file(&mut chain).unwrap();
    }
    let config = Arc::new(config);

    let mut core = Core::new()?;
    let handle = core.handle();

    #[allow(unreachable_code, unused_variables)]
    let done = TcpStream::connect(addr, &handle)
        .and_then(|stream| if let Some(domain) = domain {
            config.connect_async(domain, stream)
        } else {
            #[cfg(feature = "danger")]
            let c = config.danger_connect_async_without_providing_domain_for_certificate_verification_and_server_name_indication(stream);

            #[cfg(not(feature = "danger"))]
            let c = panic!();

            c
        })
        .and_then(|stream| aio::write_all(stream, HELLO_WORLD))
        .and_then(|(stream, _)| aio::read_exact(stream, vec![0; HELLO_WORLD.len()]))
        .and_then(|(_, buf)| {
            assert_eq!(buf, HELLO_WORLD);
            Ok(())
        });

    core.run(done)
}


#[test]
fn main() {
    let cert = certs(&mut BufReader::new(Cursor::new(CERT))).unwrap();
    let mut keys = rsa_private_keys(&mut BufReader::new(Cursor::new(RSA))).unwrap();
    let chain = BufReader::new(Cursor::new(CHAIN));

    let addr = start_server(cert, keys.pop().unwrap());

    start_client(&addr, Some("localhost"), Some(chain)).unwrap();

    #[cfg(feature = "danger")]
    start_client(&addr, None, None).unwrap();
}

#[should_panic]
#[test]
fn fail() {
    let cert = certs(&mut BufReader::new(Cursor::new(CERT))).unwrap();
    let mut keys = rsa_private_keys(&mut BufReader::new(Cursor::new(RSA))).unwrap();
    let chain = BufReader::new(Cursor::new(CHAIN));

    let addr = start_server(cert, keys.pop().unwrap());

    start_client(&addr, Some("google.com"), Some(chain)).unwrap();
}
