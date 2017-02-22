extern crate clap;
extern crate futures;
extern crate tokio_core;
extern crate webpki_roots;
extern crate tokio_file_unix;
extern crate tokio_rustls;

use std::sync::Arc;
use std::net::ToSocketAddrs;
use std::io::{ BufReader, stdout };
use std::fs;
use futures::Future;
use tokio_core::io;
use tokio_core::net::TcpStream;
use tokio_core::reactor::Core;
use clap::{ App, Arg };
use tokio_file_unix::{ StdFile, File };
use tokio_rustls::{ ClientConfig, TlsConnectorExt };


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

    let stdout = stdout();
    let mut stdout = File::new_nb(StdFile(stdout.lock())).unwrap();
    stdout.set_nonblocking(true).unwrap();
    let stdout = stdout.into_io(&handle).unwrap();

    let mut config = ClientConfig::new();
    if let Some(cafile) = cafile {
        let mut pem = BufReader::new(fs::File::open(cafile).unwrap());
        config.root_store.add_pem_file(&mut pem).unwrap();
    } else {
        config.root_store.add_trust_anchors(&webpki_roots::ROOTS);
    }
    let arc_config = Arc::new(config);

    let socket = TcpStream::connect(&addr, &handle);
    let resp = socket
        .and_then(|stream| arc_config.connect_async(domain, stream))
        .and_then(|stream| io::write_all(stream, text.as_bytes()))
        .and_then(|(stream, _)| io::copy(stream, stdout));

    core.run(resp).unwrap();
}
