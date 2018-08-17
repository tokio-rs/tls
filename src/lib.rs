//! Asynchronous TLS/SSL streams for Tokio using [Rustls](https://github.com/ctz/rustls).

#![cfg_attr(feature = "nightly", feature(specialization))]

pub extern crate rustls;
pub extern crate webpki;

#[cfg(feature = "tokio-support")]
extern crate tokio;
#[cfg(feature = "nightly")]
#[cfg(feature = "tokio-support")]
extern crate bytes;
#[cfg(feature = "nightly")]
#[cfg(feature = "tokio-support")]
extern crate iovec;


mod common;
#[cfg(feature = "tokio-support")] mod tokio_impl;

use std::io;
use std::sync::Arc;
use webpki::DNSNameRef;
use rustls::{
    Session, ClientSession, ServerSession,
    ClientConfig, ServerConfig,
};
use common::Stream;


/// Extension trait for the `Arc<ClientConfig>` type in the `rustls` crate.
pub trait ClientConfigExt: sealed::Sealed {
    fn connect_async<S>(&self, domain: DNSNameRef, stream: S)
        -> ConnectAsync<S>
        where S: io::Read + io::Write;
}

/// Extension trait for the `Arc<ServerConfig>` type in the `rustls` crate.
pub trait ServerConfigExt: sealed::Sealed {
    fn accept_async<S>(&self, stream: S)
        -> AcceptAsync<S>
        where S: io::Read + io::Write;
}


/// Future returned from `ClientConfigExt::connect_async` which will resolve
/// once the connection handshake has finished.
pub struct ConnectAsync<S>(MidHandshake<S, ClientSession>);

/// Future returned from `ServerConfigExt::accept_async` which will resolve
/// once the accept handshake has finished.
pub struct AcceptAsync<S>(MidHandshake<S, ServerSession>);

impl sealed::Sealed for Arc<ClientConfig> {}

impl ClientConfigExt for Arc<ClientConfig> {
    fn connect_async<S>(&self, domain: DNSNameRef, stream: S)
        -> ConnectAsync<S>
        where S: io::Read + io::Write
    {
        connect_async_with_session(stream, ClientSession::new(self, domain))
    }
}

#[inline]
pub fn connect_async_with_session<S>(stream: S, session: ClientSession)
    -> ConnectAsync<S>
    where S: io::Read + io::Write
{
    ConnectAsync(MidHandshake {
        inner: Some(TlsStream { session, io: stream, is_shutdown: false, eof: false })
    })
}

impl sealed::Sealed for Arc<ServerConfig> {}

impl ServerConfigExt for Arc<ServerConfig> {
    fn accept_async<S>(&self, stream: S)
        -> AcceptAsync<S>
        where S: io::Read + io::Write
    {
        accept_async_with_session(stream, ServerSession::new(self))
    }
}

#[inline]
pub fn accept_async_with_session<S>(stream: S, session: ServerSession)
    -> AcceptAsync<S>
    where S: io::Read + io::Write
{
    AcceptAsync(MidHandshake {
        inner: Some(TlsStream { session, io: stream, is_shutdown: false, eof: false })
    })
}


struct MidHandshake<S, C> {
    inner: Option<TlsStream<S, C>>
}


/// A wrapper around an underlying raw stream which implements the TLS or SSL
/// protocol.
#[derive(Debug)]
pub struct TlsStream<S, C> {
    is_shutdown: bool,
    eof: bool,
    io: S,
    session: C
}

impl<S, C> TlsStream<S, C> {
    #[inline]
    pub fn get_ref(&self) -> (&S, &C) {
        (&self.io, &self.session)
    }

    #[inline]
    pub fn get_mut(&mut self) -> (&mut S, &mut C) {
        (&mut self.io, &mut self.session)
    }
}

impl<S, C> io::Read for TlsStream<S, C>
    where S: io::Read + io::Write, C: Session
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.eof {
            return Ok(0);
        }

        match Stream::new(&mut self.session, &mut self.io).read(buf) {
            Ok(0) => { self.eof = true; Ok(0) },
            Ok(n) => Ok(n),
            Err(ref e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                self.eof = true;
                self.is_shutdown = true;
                self.session.send_close_notify();
                Ok(0)
            },
            Err(e) => Err(e)
        }
    }
}

impl<S, C> io::Write for TlsStream<S, C>
    where S: io::Read + io::Write, C: Session
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Stream::new(&mut self.session, &mut self.io).write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Stream::new(&mut self.session, &mut self.io).flush()?;
        self.io.flush()
    }
}

mod sealed {
    pub trait Sealed {}
}
