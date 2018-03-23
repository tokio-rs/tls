//! Asynchronous TLS/SSL streams for Tokio using [Rustls](https://github.com/ctz/rustls).

extern crate rustls;
extern crate webpki;

#[cfg(feature = "tokio")] mod tokio_impl;
#[cfg(feature = "unstable-futures")] mod futures_impl;

use std::io;
use std::sync::Arc;
use rustls::{
    Session, ClientSession, ServerSession,
    ClientConfig, ServerConfig,
    Stream
};


/// Extension trait for the `Arc<ClientConfig>` type in the `rustls` crate.
pub trait ClientConfigExt: sealed::Sealed {
    fn connect_async<S>(&self, domain: webpki::DNSNameRef, stream: S)
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
    fn connect_async<S>(&self, domain: webpki::DNSNameRef, stream: S)
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
    ConnectAsync(MidHandshake { inner: Some(TlsStream::new(stream, session)) })
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
    AcceptAsync(MidHandshake { inner: Some(TlsStream::new(stream, session)) })
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

impl<S, C> TlsStream<S, C>
    where S: io::Read + io::Write, C: Session
{
    #[inline]
    fn new(io: S, session: C) -> TlsStream<S, C> {
        TlsStream {
            is_shutdown: false,
            eof: false,
            io: io,
            session: session
        }
    }

    fn do_read(session: &mut C, io: &mut S, eof: &mut bool) -> io::Result<bool> {
        if !*eof && session.wants_read() {
            if session.read_tls(io)? == 0 {
                *eof = true;
            }

            if let Err(err) = session.process_new_packets() {
                // flush queued messages before returning an Err in
                // order to send alerts instead of abruptly closing
                // the socket
                if session.wants_write() {
                    // ignore result to avoid masking original error
                    let _ = session.write_tls(io);
                }
                return Err(io::Error::new(io::ErrorKind::InvalidData, err));
            }

            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn do_write(session: &mut C, io: &mut S) -> io::Result<bool> {
        if session.wants_write() {
            session.write_tls(io)?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    #[inline]
    pub fn do_io(session: &mut C, io: &mut S, eof: &mut bool) -> io::Result<()> {
        macro_rules! try_wouldblock {
            ( $r:expr ) => {
                match $r {
                    Ok(true) => continue,
                    Ok(false) => false,
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => true,
                    Err(e) => return Err(e)
                }
            };
        }

        loop {
            let write_would_block = try_wouldblock!(Self::do_write(session, io));
            let read_would_block = try_wouldblock!(Self::do_read(session, io, eof));

            if write_would_block || read_would_block {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            } else {
                return Ok(());
            }
        }
    }
}

macro_rules! try_ignore {
    ( $r:expr ) => {
        match $r {
            Ok(_) => (),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => (),
            Err(e) => return Err(e)
        }
    }
}

impl<S, C> io::Read for TlsStream<S, C>
    where S: io::Read + io::Write, C: Session
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let (io, session) = self.get_mut();
        let mut stream = Stream::new(session, io);

        match stream.read(buf) {
            Ok(n) => Ok(n),
            Err(ref e) if e.kind() == io::ErrorKind::ConnectionAborted => Ok(0),
            Err(e) => Err(e)
        }
    }
}

impl<S, C> io::Write for TlsStream<S, C>
    where S: io::Read + io::Write, C: Session
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let (io, session) = self.get_mut();
        let mut stream = Stream::new(session, io);

        stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        {
            let (io, session) = self.get_mut();
            let mut stream = Stream::new(session, io);
            stream.flush()?;
        }

        self.io.flush()
    }
}

mod sealed {
    pub trait Sealed {}
}
