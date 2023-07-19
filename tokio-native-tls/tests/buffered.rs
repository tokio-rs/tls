use native_tls::TlsConnector;
use tokio::{io::BufWriter, net::TcpStream};

#[tokio::test]
async fn connect_using_bufwriter() {
    drop(env_logger::try_init());

    let socket = BufWriter::new(
        TcpStream::connect(("example.com", 443))
            .await
            .expect("connect socket"),
    );

    let connector = TlsConnector::builder()
        .build()
        .expect("build TLS connector");

    tokio_native_tls::TlsConnector::from(connector)
        .connect("example.com", BufWriter::new(socket))
        .await
        .expect("connect TLS");
}
