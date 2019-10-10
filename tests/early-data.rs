#![cfg(feature = "early-data")]

use std::io::{ self, BufReader, BufRead, Cursor };
use std::process::{ Command, Child, Stdio };
use std::net::SocketAddr;
use std::sync::Arc;
use std::marker::Unpin;
use std::pin::{ Pin };
use std::task::{ Context, Poll };
use std::time::Duration;
use tokio::prelude::*;
use tokio::net::TcpStream;
use tokio::timer::delay_for;
use futures_util::{ future, ready };
use rustls::ClientConfig;
use tokio_rustls::{ TlsConnector, client::TlsStream };


struct Read1<T>(T);

impl<T: AsyncRead + Unpin> Future for Read1<T> {
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut buf = [0];
        ready!(Pin::new(&mut self.0).poll_read(cx, &mut buf))?;
        Poll::Pending
    }
}

async fn send(config: Arc<ClientConfig>, addr: SocketAddr, data: &[u8])
    -> io::Result<TlsStream<TcpStream>>
{
    let connector = TlsConnector::from(config)
        .early_data(true);
    let stream = TcpStream::connect(&addr).await?;
    let domain = webpki::DNSNameRef::try_from_ascii_str("testserver.com").unwrap();

    let mut stream = connector.connect(domain, stream).await?;
    stream.write_all(data).await?;
    stream.flush().await?;

    // sleep 1s
    //
    // see https://www.mail-archive.com/openssl-users@openssl.org/msg84451.html
    let sleep1 = delay_for(Duration::from_secs(1));
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
        .stdout(Stdio::piped())
        .spawn()
        .map(DropKill)?;

    // wait openssl server
    delay_for(Duration::from_secs(1)).await;

    let mut config = ClientConfig::new();
    let mut chain = BufReader::new(Cursor::new(include_str!("end.chain")));
    config.root_store.add_pem_file(&mut chain).unwrap();
    config.versions = vec![rustls::ProtocolVersion::TLSv1_3];
    config.enable_early_data = true;
    let config = Arc::new(config);
    let addr = SocketAddr::from(([127, 0, 0, 1], 12354));

    let io = send(config.clone(), addr, b"hello").await?;
    assert!(!io.get_ref().1.is_early_data_accepted());

    let io = send(config, addr, b"world!").await?;
    assert!(io.get_ref().1.is_early_data_accepted());

    let stdout = handle.0.stdout.as_mut().unwrap();
    let mut lines = BufReader::new(stdout).lines();

    for line in lines.by_ref() {
        if line?.contains("hello") {
            break
        }
    }

    for line in lines.by_ref() {
        if line?.contains("world!") {
            break
        }
    }

    Ok(())
}
