//! Asynchronous TLS/SSL streams for Tokio using [Rustls](https://github.com/ctz/rustls).

pub extern crate rustls;
pub extern crate webpki;

extern crate futures;
extern crate tokio_io;
extern crate bytes;
extern crate iovec;

mod common;
pub mod client;
pub mod server;

use std::{ io, mem };
use std::sync::Arc;
use webpki::DNSNameRef;
use rustls::{
    ClientSession, ServerSession,
    ClientConfig, ServerConfig
};
use futures::{Async, Future, Poll};
use tokio_io::{ AsyncRead, AsyncWrite, try_nb };
use common::Stream;


#[derive(Clone)]
pub struct TlsConnector {
    inner: Arc<ClientConfig>,
    early_data: bool
}

#[derive(Clone)]
pub struct TlsAcceptor {
    inner: Arc<ServerConfig>
}

impl From<Arc<ClientConfig>> for TlsConnector {
    fn from(inner: Arc<ClientConfig>) -> TlsConnector {
        TlsConnector { inner, early_data: false }
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
    pub fn early_data(mut self, flag: bool) -> TlsConnector {
        self.early_data = flag;
        self
    }

    pub fn connect<IO>(&self, domain: DNSNameRef, stream: IO) -> Connect<IO>
        where IO: AsyncRead + AsyncWrite
    {
        self.connect_with(domain, stream, |_| ())
    }

    #[inline]
    pub fn connect_with<IO, F>(&self, domain: DNSNameRef, stream: IO, f: F)
        -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite,
        F: FnOnce(&mut ClientSession)
    {
        let mut session = ClientSession::new(&self.inner, domain);
        f(&mut session);

        Connect(if self.early_data {
            client::MidHandshake::EarlyData(client::TlsStream {
                session, io: stream,
                state: client::TlsState::EarlyData,
                early_data: (0, Vec::new())
            })
        } else {
            client::MidHandshake::Handshaking(client::TlsStream {
                session, io: stream,
                state: client::TlsState::Stream,
                early_data: (0, Vec::new())
            })
        })
    }
}

impl TlsAcceptor {
    pub fn accept<IO>(&self, stream: IO) -> Accept<IO>
        where IO: AsyncRead + AsyncWrite,
    {
        self.accept_with(stream, |_| ())
    }

    #[inline]
    pub fn accept_with<IO, F>(&self, stream: IO, f: F)
        -> Accept<IO>
    where
        IO: AsyncRead + AsyncWrite,
        F: FnOnce(&mut ServerSession)
    {
        let mut session = ServerSession::new(&self.inner);
        f(&mut session);

        Accept(server::MidHandshake::Handshaking(server::TlsStream {
            session, io: stream,
            state: server::TlsState::Stream,
        }))
    }
}


/// Future returned from `ClientConfigExt::connect_async` which will resolve
/// once the connection handshake has finished.
pub struct Connect<IO>(client::MidHandshake<IO>);

/// Future returned from `ServerConfigExt::accept_async` which will resolve
/// once the accept handshake has finished.
pub struct Accept<IO>(server::MidHandshake<IO>);


impl<IO: AsyncRead + AsyncWrite> Future for Connect<IO> {
    type Item = client::TlsStream<IO>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

impl<IO: AsyncRead + AsyncWrite> Future for Accept<IO> {
    type Item = server::TlsStream<IO>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

#[cfg(test)]
mod test_0rtt;
