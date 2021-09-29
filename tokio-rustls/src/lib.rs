//! Asynchronous TLS/SSL streams for Tokio using [Rustls](https://github.com/ctz/rustls).
//!
//! # Why do I need to call `poll_flush`?
//!
//! Most TLS implementations will have an internal buffer to improve throughput,
//! and rustls is no exception.
//!
//! When we write data to `TlsStream`, we always write rustls buffer first,
//! then take out rustls encrypted data packet, and write it to data channel (like TcpStream).
//! When data channel is pending, some data may remain in rustls buffer.
//! at this point we must call flush to write again it into data channel.
//!
//! `tokio-rustls` To keep it simple and correct, [TlsStream] will behave like `BufWriter`.
//!
//! ## Why don't we write during `poll_read`?
//!
//! We did this in the early days of `tokio-rustls`, but it caused some bugs.
//! We can solve these bugs through some solutions, but this will cause performance degradation (reverse false wakeup).
//!
//! And reverse write will also prevent us implement full duplex in the future.
//!
//! see <https://github.com/tokio-rs/tls/issues/40>
//!
//! ## Why can't we handle it like `native-tls`?
//!
//! native-tls also needs to call flush, but it will be much less.
//!
//! When data channel returns to pending, `native-tls` will falsely report the number of bytes it consumes,
//! which does not conform to convention of `AsyncWrite` trait.
//! This means that if you give inconsistent data in two `poll_write`, it may cause unexpected behavior.
//!
//! see <https://github.com/tokio-rs/tls/issues/41>

macro_rules! ready {
    ( $e:expr ) => {
        match $e {
            std::task::Poll::Ready(t) => t,
            std::task::Poll::Pending => return std::task::Poll::Pending,
        }
    };
}

pub mod client;
mod common;
pub mod server;

use common::{MidHandshake, Stream, TlsState};
use rustls::{ClientConfig, ClientConnection, CommonState, ServerConfig, ServerConnection};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub use rustls;
pub use webpki;

/// A wrapper around a `rustls::ClientConfig`, providing an async `connect` method.
#[derive(Clone)]
pub struct TlsConnector {
    inner: Arc<ClientConfig>,
    #[cfg(feature = "early-data")]
    early_data: bool,
}

/// A wrapper around a `rustls::ServerConfig`, providing an async `accept` method.
#[derive(Clone)]
pub struct TlsAcceptor {
    inner: Arc<ServerConfig>,
}

impl From<Arc<ClientConfig>> for TlsConnector {
    fn from(inner: Arc<ClientConfig>) -> TlsConnector {
        TlsConnector {
            inner,
            #[cfg(feature = "early-data")]
            early_data: false,
        }
    }
}

impl From<Arc<ServerConfig>> for TlsAcceptor {
    fn from(inner: Arc<ServerConfig>) -> TlsAcceptor {
        TlsAcceptor { inner }
    }
}

impl TlsConnector {
    /// Enable 0-RTT.
    ///
    /// If you want to use 0-RTT,
    /// You must also set `ClientConfig.enable_early_data` to `true`.
    #[cfg(feature = "early-data")]
    pub fn early_data(mut self, flag: bool) -> TlsConnector {
        self.early_data = flag;
        self
    }

    #[inline]
    pub fn connect<IO>(&self, domain: rustls::ServerName, stream: IO) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        self.connect_with(domain, stream, |_| ())
    }

    pub fn connect_with<IO, F>(&self, domain: rustls::ServerName, stream: IO, f: F) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(&mut ClientConnection),
    {
        let mut session = match ClientConnection::new(self.inner.clone(), domain) {
            Ok(session) => session,
            Err(error) => {
                return Connect(MidHandshake::Error {
                    io: stream,
                    // TODO(eliza): should this really return an `io::Error`?
                    // Probably not...
                    error: io::Error::new(io::ErrorKind::Other, error),
                });
            }
        };
        f(&mut session);

        Connect(MidHandshake::Handshaking(client::TlsStream {
            io: stream,

            #[cfg(not(feature = "early-data"))]
            state: TlsState::Stream,

            #[cfg(feature = "early-data")]
            state: if self.early_data && session.early_data().is_some() {
                TlsState::EarlyData(0, Vec::new())
            } else {
                TlsState::Stream
            },

            session,
        }))
    }
}

impl TlsAcceptor {
    #[inline]
    pub fn accept<IO>(&self, stream: IO) -> Accept<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        self.accept_with(stream, |_| ())
    }

    pub fn accept_with<IO, F>(&self, stream: IO, f: F) -> Accept<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(&mut ServerConnection),
    {
        let mut session = match ServerConnection::new(self.inner.clone()) {
            Ok(session) => session,
            Err(error) => {
                return Accept(MidHandshake::Error {
                    io: stream,
                    // TODO(eliza): should this really return an `io::Error`?
                    // Probably not...
                    error: io::Error::new(io::ErrorKind::Other, error),
                });
            }
        };
        f(&mut session);

        Accept(MidHandshake::Handshaking(server::TlsStream {
            session,
            io: stream,
            state: TlsState::Stream,
        }))
    }
}

/// Future returned from `TlsConnector::connect` which will resolve
/// once the connection handshake has finished.
pub struct Connect<IO>(MidHandshake<client::TlsStream<IO>>);

/// Future returned from `TlsAcceptor::accept` which will resolve
/// once the accept handshake has finished.
pub struct Accept<IO>(MidHandshake<server::TlsStream<IO>>);

/// Like [Connect], but returns `IO` on failure.
pub struct FailableConnect<IO>(MidHandshake<client::TlsStream<IO>>);

/// Like [Accept], but returns `IO` on failure.
pub struct FailableAccept<IO>(MidHandshake<server::TlsStream<IO>>);

impl<IO> Connect<IO> {
    #[inline]
    pub fn into_failable(self) -> FailableConnect<IO> {
        FailableConnect(self.0)
    }
}

impl<IO> Accept<IO> {
    #[inline]
    pub fn into_failable(self) -> FailableAccept<IO> {
        FailableAccept(self.0)
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Connect<IO> {
    type Output = io::Result<client::TlsStream<IO>>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map_err(|(err, _)| err)
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Accept<IO> {
    type Output = io::Result<server::TlsStream<IO>>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map_err(|(err, _)| err)
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for FailableConnect<IO> {
    type Output = Result<client::TlsStream<IO>, (io::Error, IO)>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for FailableAccept<IO> {
    type Output = Result<server::TlsStream<IO>, (io::Error, IO)>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

/// Unified TLS stream type
///
/// This abstracts over the inner `client::TlsStream` and `server::TlsStream`, so you can use
/// a single type to keep both client- and server-initiated TLS-encrypted connections.
#[derive(Debug)]
pub enum TlsStream<T> {
    Client(client::TlsStream<T>),
    Server(server::TlsStream<T>),
}

impl<T> TlsStream<T> {
    pub fn get_ref(&self) -> (&T, &CommonState) {
        use TlsStream::*;
        match self {
            Client(io) => {
                let (io, session) = io.get_ref();
                (io, &*session)
            }
            Server(io) => {
                let (io, session) = io.get_ref();
                (io, &*session)
            }
        }
    }

    pub fn get_mut(&mut self) -> (&mut T, &mut CommonState) {
        use TlsStream::*;
        match self {
            Client(io) => {
                let (io, session) = io.get_mut();
                (io, &mut *session)
            }
            Server(io) => {
                let (io, session) = io.get_mut();
                (io, &mut *session)
            }
        }
    }
}

impl<T> From<client::TlsStream<T>> for TlsStream<T> {
    fn from(s: client::TlsStream<T>) -> Self {
        Self::Client(s)
    }
}

impl<T> From<server::TlsStream<T>> for TlsStream<T> {
    fn from(s: server::TlsStream<T>) -> Self {
        Self::Server(s)
    }
}

impl<T> AsyncRead for TlsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            TlsStream::Client(x) => Pin::new(x).poll_read(cx, buf),
            TlsStream::Server(x) => Pin::new(x).poll_read(cx, buf),
        }
    }
}

impl<T> AsyncWrite for TlsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            TlsStream::Client(x) => Pin::new(x).poll_write(cx, buf),
            TlsStream::Server(x) => Pin::new(x).poll_write(cx, buf),
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            TlsStream::Client(x) => Pin::new(x).poll_flush(cx),
            TlsStream::Server(x) => Pin::new(x).poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            TlsStream::Client(x) => Pin::new(x).poll_shutdown(cx),
            TlsStream::Server(x) => Pin::new(x).poll_shutdown(cx),
        }
    }
}
