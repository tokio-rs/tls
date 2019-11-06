//! Asynchronous TLS/SSL streams for Tokio using [Rustls](https://github.com/ctz/rustls).

pub mod client;
mod common;
pub mod server;

use common::Stream;
use futures_core as futures;
use pin_project::{pin_project, project};
use rustls::{ClientConfig, ClientSession, ServerConfig, ServerSession, Session};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::{io, mem};
use tokio_io::{AsyncRead, AsyncWrite};
use webpki::DNSNameRef;

pub use rustls;
pub use webpki;

#[derive(Debug, Copy, Clone)]
enum TlsState {
    #[cfg(feature = "early-data")]
    EarlyData,
    Stream,
    ReadShutdown,
    WriteShutdown,
    FullyShutdown,
}

impl TlsState {
    fn shutdown_read(&mut self) {
        match *self {
            TlsState::WriteShutdown | TlsState::FullyShutdown => *self = TlsState::FullyShutdown,
            _ => *self = TlsState::ReadShutdown,
        }
    }

    fn shutdown_write(&mut self) {
        match *self {
            TlsState::ReadShutdown | TlsState::FullyShutdown => *self = TlsState::FullyShutdown,
            _ => *self = TlsState::WriteShutdown,
        }
    }

    fn writeable(&self) -> bool {
        match *self {
            TlsState::WriteShutdown | TlsState::FullyShutdown => false,
            _ => true,
        }
    }

    fn readable(self) -> bool {
        match self {
            TlsState::ReadShutdown | TlsState::FullyShutdown => false,
            _ => true,
        }
    }
}

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
    /// Note that you want to use 0-RTT.
    /// You must set `enable_early_data` to `true` in `ClientConfig`.
    #[cfg(feature = "early-data")]
    pub fn early_data(mut self, flag: bool) -> TlsConnector {
        self.early_data = flag;
        self
    }

    pub fn connect<IO>(&self, domain: DNSNameRef, stream: IO) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        self.connect_with(domain, stream, |_| ())
    }

    #[inline]
    pub fn connect_with<IO, F>(&self, domain: DNSNameRef, stream: IO, f: F) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(&mut ClientSession),
    {
        let mut session = ClientSession::new(&self.inner, domain);
        f(&mut session);

        #[cfg(not(feature = "early-data"))]
        {
            Connect(client::MidHandshake::Handshaking(client::TlsStream {
                session,
                io: stream,
                state: TlsState::Stream,
            }))
        }

        #[cfg(feature = "early-data")]
        {
            Connect(if self.early_data {
                client::MidHandshake::EarlyData(client::TlsStream {
                    session,
                    io: stream,
                    state: TlsState::EarlyData,
                    early_data: (0, Vec::new()),
                })
            } else {
                client::MidHandshake::Handshaking(client::TlsStream {
                    session,
                    io: stream,
                    state: TlsState::Stream,
                    early_data: (0, Vec::new()),
                })
            })
        }
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
        F: FnOnce(&mut ServerSession),
    {
        let mut session = ServerSession::new(&self.inner);
        f(&mut session);

        Accept(server::MidHandshake::Handshaking(server::TlsStream {
            session,
            io: stream,
            state: TlsState::Stream,
        }))
    }
}

/// Future returned from `TlsConnector::connect` which will resolve
/// once the connection handshake has finished.
pub struct Connect<IO>(client::MidHandshake<IO>);

/// Future returned from `TlsAcceptor::accept` which will resolve
/// once the accept handshake has finished.
pub struct Accept<IO>(server::MidHandshake<IO>);

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Connect<IO> {
    type Output = io::Result<client::TlsStream<IO>>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Accept<IO> {
    type Output = io::Result<server::TlsStream<IO>>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

/// Unified TLS stream type
///
/// This abstracts over the inner `client::TlsStream` and `server::TlsStream`, so you can use
/// a single type to keep both client- and server-initiated TLS-encrypted connections.
#[pin_project]
pub enum TlsStream<T> {
    Client(#[pin] client::TlsStream<T>),
    Server(#[pin] server::TlsStream<T>),
}

impl<T> TlsStream<T> {
    pub fn get_ref(&self) -> (&T, &dyn Session) {
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

    pub fn get_mut(&mut self) -> (&mut T, &mut dyn Session) {
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
    #[project]
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        #[project]
        match self.project() {
            TlsStream::Client(x) => x.poll_read(cx, buf),
            TlsStream::Server(x) => x.poll_read(cx, buf),
        }
    }
}

impl<T> AsyncWrite for TlsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    #[project]
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        #[project]
        match self.project() {
            TlsStream::Client(x) => x.poll_write(cx, buf),
            TlsStream::Server(x) => x.poll_write(cx, buf),
        }
    }

    #[project]
    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        #[project]
        match self.project() {
            TlsStream::Client(x) => x.poll_flush(cx),
            TlsStream::Server(x) => x.poll_flush(cx),
        }
    }

    #[project]
    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        #[project]
        match self.project() {
            TlsStream::Client(x) => x.poll_shutdown(cx),
            TlsStream::Server(x) => x.poll_shutdown(cx),
        }
    }
}
