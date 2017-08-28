extern crate clap;
extern crate rustls;
extern crate futures;
extern crate tokio_io;
extern crate tokio_core;
extern crate webpki_roots;
extern crate tokio_rustls;

#[cfg(unix)]
extern crate tokio_file_unix;

use std::sync::Arc;
use std::net::ToSocketAddrs;
use std::io::{ BufReader, stdout, stdin };
use std::fs;
use futures::Future;
use tokio_core::net::TcpStream;
use tokio_core::reactor::Core;
use tokio_io::io;
use clap::{ App, Arg };
use rustls::ClientConfig;
use tokio_rustls::ClientConfigExt;

#[cfg(unix)]
use tokio_io::AsyncRead;

#[cfg(unix)]
use tokio_file_unix::{ StdFile, File };

#[cfg(not(unix))]
use std::io::{Read, Write};

fn app() -> App<'static, 'static> {
    App::new("client")
        .about("tokio-rustls client example")
        .arg(Arg::with_name("host").value_name("HOST").required(true))
        .arg(Arg::with_name("port").short("p").long("port").value_name("PORT").help("port, default `443`"))
        .arg(Arg::with_name("domain").short("d").long("domain").value_name("DOMAIN").help("domain"))
        .arg(Arg::with_name("cafile").short("c").long("cafile").value_name("FILE").help("CA certificate chain"))
}


fn main() {
    let matches = app().get_matches();

    let host = matches.value_of("host").unwrap();
    let port = if let Some(port) = matches.value_of("port") {
        port.parse().unwrap()
    } else {
        443
    };
    let domain = matches.value_of("domain").unwrap_or(host);
    let cafile = matches.value_of("cafile");
    let text = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", domain);

    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let addr = (host, port)
        .to_socket_addrs().unwrap()
        .next().unwrap();

    let mut config = ClientConfig::new();
    if let Some(cafile) = cafile {
        let mut pem = BufReader::new(fs::File::open(cafile).unwrap());
        config.root_store.add_pem_file(&mut pem).unwrap();
    } else {
        config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    }
    let arc_config = Arc::new(config);

    let socket = TcpStream::connect(&addr, &handle);

    // Use async non-blocking I/O for stdin/stdout on Unixy platforms.

    #[cfg(unix)]
    let stdin = stdin();

    #[cfg(unix)]
    let stdin = File::new_nb(StdFile(stdin.lock())).unwrap()
        .into_io(&handle).unwrap();

    #[cfg(unix)]
    let stdout = stdout();

    #[cfg(unix)]
    let stdout = File::new_nb(StdFile(stdout.lock())).unwrap()
        .into_io(&handle).unwrap();

    #[cfg(unix)]
    let resp = socket
        .and_then(|stream| arc_config.connect_async(domain, stream))
        .and_then(|stream| io::write_all(stream, text.as_bytes()))
        .and_then(|(stream, _)| {
            let (r, w) = stream.split();
            io::copy(r, stdout)
                .map(|_| ())
                .select(io::copy(stdin, w).map(|_| ()))
                .map_err(|(e, _)| e)
        });

    // XXX: For now, just use blocking I/O for stdin/stdout on other platforms.
    // The network I/O will still be asynchronous and non-blocking.

    #[cfg(not(unix))]
    let mut input = Vec::new();

    #[cfg(not(unix))]
    stdin().read_to_end(&mut input).unwrap();

    #[cfg(not(unix))]
    let resp = socket
        .and_then(|stream| arc_config.connect_async(domain, stream))
        .and_then(|stream| io::write_all(stream, text.as_bytes()))
        .and_then(|(stream, _)| io::write_all(stream, &input))
        .and_then(|(stream, _)| io::read_to_end(stream, Vec::new()))
        .and_then(|(_, output)| stdout().write_all(&output));

    core.run(resp).unwrap();
}
