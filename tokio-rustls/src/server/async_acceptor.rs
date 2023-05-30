use std::{
    future::poll_fn,
    task::{Context, Poll},
};

use crate::{common, StartHandshake};
use tokio::io::{self, AsyncRead};

/// Handle on a server-side connection before configuration is available.
/// For more details, refer to [`rustls::server::Acceptor`].
///
/// # Example
///
/// ```no_run
/// use tokio::io::AsyncWriteExt;
/// let listener = tokio::net::TcpListener::bind("127.0.0.1:4443").await.unwrap();
/// let (stream, _) = listener.accept().await.unwrap();
/// let mut acceptor = tokio_rustls::AsyncAcceptor::new(stream);
/// match acceptor.accept().await {
///     Ok(start) => {
///         let config = choose_server_config(start.client_hello()).await.unwrap();
///         let stream = start.into_stream(config).await.unwrap();
///         // Proceed with handling the ServerConnection...
///     }
///     Err(err) => {
///         if let Some(mut stream) = acceptor.take_io() {
///             stream
///                 .write_all(
///                     format!("HTTP/1.1 400 Invalid Input\r\n\r\n\r\n{:?}\n", err)
///                         .as_bytes()
///                 )
///                 .await
///                 .unwrap();
///         }
///     }
/// }
/// ```
pub struct AsyncAcceptor<IO> {
    acceptor: rustls::server::Acceptor,
    io: Option<IO>,
}

impl<IO> AsyncAcceptor<IO>
where
    IO: AsyncRead + Unpin,
{
    /// Return an empty Acceptor, ready to receive bytes from a new client connection (io).
    #[inline]
    pub fn new(io: IO) -> Self {
        Self {
            acceptor: rustls::server::Acceptor::default(),
            io: Some(io),
        }
    }

    /// Wait for the `ClientHello` message from client. Do not call this function more than once.
    ///
    /// Returns `Ok(accepted)` if the connection has been accepted.
    ///
    /// Returns `Err(err)` if an error occurred. Use [`take_io`] to retrieve the client connection.
    pub async fn accept(&mut self) -> Result<StartHandshake<IO>, rustls::Error> {
        poll_fn(|cx: &mut Context<'_>| loop {
            let io = match self.io.as_mut() {
                Some(io) => io,
                None => {
                    return Poll::Ready(Err(rustls::Error::General(
                        "acceptor cannot be polled after acceptance".into(),
                    )))
                }
            };

            let mut reader = common::SyncReadAdapter { io, cx };
            match self.acceptor.read_tls(&mut reader) {
                Ok(0) => return Poll::Ready(Err(rustls::Error::HandshakeNotComplete)),
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(e) => return Poll::Ready(Err(rustls::Error::General(e.to_string()))),
            }

            match self.acceptor.accept() {
                Ok(Some(accepted)) => {
                    let io = self.io.take().unwrap();
                    return Poll::Ready(Ok(StartHandshake { accepted, io }));
                }
                Ok(None) => continue,
                Err(err) => {
                    return Poll::Ready(Err(err));
                }
            }
        })
        .await
    }
    /// Takes back the client connection. Will return `None` if called more than once or if the
    /// connection has been accepted.
    pub fn take_io(&mut self) -> Option<IO> {
        self.io.take()
    }
}
