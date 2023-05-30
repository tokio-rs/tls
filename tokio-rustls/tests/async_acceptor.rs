use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::oneshot,
};
use tokio_rustls::{server::AsyncAcceptor, TlsConnector};

#[tokio::test]
async fn test_async_acceptor_accept() -> Result<(), rustls::Error> {
    let (sconfig, cconfig) = utils::make_configs();
    use std::convert::TryFrom;

    let (cstream, sstream) = tokio::io::duplex(1200);
    let domain = rustls::ServerName::try_from("foobar.com").unwrap();

    tokio::spawn(async move {
        let connector = crate::TlsConnector::from(cconfig);
        let mut client = connector.connect(domain, cstream).await.unwrap();
        client.write_all(b"hello, world!").await.unwrap();

        let mut buf = Vec::new();
        client.read_to_end(&mut buf).await.unwrap();
    });

    let mut acceptor = AsyncAcceptor::new(sstream);
    let start = acceptor.accept().await.unwrap();
    let ch = start.client_hello();

    assert_eq!(ch.server_name(), Some("foobar.com"));
    assert_eq!(
        ch.alpn()
            .map(|protos| protos.collect::<Vec<_>>())
            .unwrap_or_default(),
        Vec::<&[u8]>::new()
    );

    let mut stream = start.into_stream(sconfig).await.unwrap();
    let mut buf = [0; 13];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf[..], b"hello, world!");

    stream.write_all(b"bye").await.unwrap();
    Ok(())
}

#[tokio::test]
async fn test_async_acceptor_take_io() -> Result<(), rustls::Error> {
    let (mut cstream, sstream) = tokio::io::duplex(1200);

    let (tx, rx) = oneshot::channel();

    tokio::spawn(async move {
        cstream.write_all(b"hello, world!").await.unwrap();

        let mut buf = Vec::new();
        cstream.read_to_end(&mut buf).await.unwrap();
        tx.send(buf).unwrap();
    });

    let mut acceptor = AsyncAcceptor::new(sstream);
    if let Err(err) = acceptor.accept().await {
        if let rustls::Error::InvalidMessage(_err) = err {
        } else {
            panic!("Unexpected Error {:?}", err);
        }
    } else {
        panic!("Expected Err(err)");
    }

    let server_msg = b"message from server";

    let some_io = acceptor.take_io();
    assert!(some_io.is_some(), "Expected Some(io)");
    some_io.unwrap().write_all(server_msg).await.unwrap();

    assert_eq!(rx.await.unwrap(), server_msg);

    assert!(
        acceptor.take_io().is_none(),
        "Should not be able to take twice"
    );
    Ok(())
}

// Include `utils` module
include!("utils.rs");
