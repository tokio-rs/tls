#![cfg(feature = "early-data")]

use futures_util::{future, future::Future, ready};
use rustls::RootCertStore;
use std::convert::TryFrom;
use std::io::{self, BufRead, BufReader, Cursor};
use std::net::SocketAddr;
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::sleep;
use tokio_rustls::{
    client::TlsStream,
    rustls::{self, ClientConfig, OwnedTrustAnchor},
    TlsConnector,
};

struct Read1<T>(T);

impl<T: AsyncRead + Unpin> Future for Read1<T> {
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut buf = [0];
        let mut buf = &mut ReadBuf::new(&mut buf);
        ready!(Pin::new(&mut self.0).poll_read(cx, &mut buf))?;
        Poll::Pending
    }
}

async fn send(
    config: Arc<ClientConfig>,
    addr: SocketAddr,
    data: &[u8],
) -> io::Result<TlsStream<TcpStream>> {
    let connector = TlsConnector::from(config).early_data(true);
    let stream = TcpStream::connect(&addr).await?;
    let domain = rustls::ServerName::try_from("testserver.com").unwrap();

    let mut stream = connector.connect(domain, stream).await?;
    stream.write_all(data).await?;
    stream.flush().await?;

    // sleep 1s
    //
    // see https://www.mail-archive.com/openssl-users@openssl.org/msg84451.html
    let sleep1 = sleep(Duration::from_secs(1));
    futures_util::pin_mut!(sleep1);
    let mut stream = match future::select(Read1(stream), sleep1).await {
        future::Either::Right((_, Read1(stream))) => stream,
        future::Either::Left((Err(err), _)) => return Err(err),
        future::Either::Left((Ok(_), _)) => unreachable!(),
    };

    stream.shutdown().await?;

    Ok(stream)
}

struct DropKill(Child);

impl Drop for DropKill {
    fn drop(&mut self) {
        self.0.kill().unwrap();
    }
}

#[tokio::test]
async fn test_0rtt() -> io::Result<()> {
    let mut handle = Command::new("openssl")
        .arg("s_server")
        .arg("-early_data")
        .arg("-tls1_3")
        .args(&["-cert", "./tests/end.cert"])
        .args(&["-key", "./tests/end.rsa"])
        .args(&["-port", "12354"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map(DropKill)?;

    // wait openssl server
    sleep(Duration::from_secs(1)).await;

    let mut chain = BufReader::new(Cursor::new(include_str!("end.chain")));
    let certs = rustls_pemfile::certs(&mut chain).unwrap();
    let trust_anchors = certs
        .iter()
        .map(|cert| {
            let ta = webpki::TrustAnchor::try_from_cert_der(&cert[..]).unwrap();
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        })
        .collect::<Vec<_>>();
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(trust_anchors.into_iter());
    let mut config = rustls::ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.enable_early_data = true;
    let config = Arc::new(config);
    let addr = SocketAddr::from(([127, 0, 0, 1], 12354));

    let io = send(config.clone(), addr, b"hello").await?;
    assert!(!io.get_ref().1.is_early_data_accepted());

    let io = send(config, addr, b"world!").await?;
    assert!(io.get_ref().1.is_early_data_accepted());

    let stdout = handle.0.stdout.as_mut().unwrap();
    let mut lines = BufReader::new(stdout).lines();

    let has_msg1 = lines.by_ref().any(|line| line.unwrap().contains("hello"));
    let has_msg2 = lines.by_ref().any(|line| line.unwrap().contains("world!"));

    assert!(has_msg1 && has_msg2);

    Ok(())
}
