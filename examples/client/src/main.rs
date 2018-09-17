extern crate clap;
extern crate tokio;
extern crate webpki;
extern crate webpki_roots;
extern crate tokio_rustls;

extern crate tokio_stdin_stdout;

use std::sync::Arc;
use std::net::ToSocketAddrs;
use std::io::BufReader;
use std::fs;
use tokio::io;
use tokio::net::TcpStream;
use tokio::prelude::*;
use clap::{ App, Arg };
use tokio_rustls::{ TlsConnector, rustls::ClientConfig };
use tokio_stdin_stdout::{ stdin as tokio_stdin, stdout as tokio_stdout };

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
    let port = matches.value_of("port")
        .map(|port| port.parse().unwrap())
        .unwrap_or(443);
    let domain = matches.value_of("domain").unwrap_or(host).to_owned();
    let cafile = matches.value_of("cafile");
    let text = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", domain);

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
    let config = TlsConnector::from(Arc::new(config));

    let socket = TcpStream::connect(&addr);
    let (stdin, stdout) = (tokio_stdin(0), tokio_stdout(0));

    let done = socket
        .and_then(move |stream| {
            let domain = webpki::DNSNameRef::try_from_ascii_str(&domain).unwrap();
            config.connect(domain, stream)
        })
        .and_then(move |stream| io::write_all(stream, text))
        .and_then(move |(stream, _)| {
            let (r, w) = stream.split();
            io::copy(r, stdout)
                .map(drop)
                .select2(io::copy(stdin, w).map(drop))
                .map_err(|res| res.split().0)
        })
        .map(drop)
        .map_err(|err| eprintln!("{:?}", err));

    tokio::run(done);
}
