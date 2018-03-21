//! Asynchronous TLS/SSL streams for Tokio using [Rustls](https://github.com/ctz/rustls).

extern crate rustls;
extern crate webpki;

#[cfg(feature = "tokio")] mod tokio_impl;
#[cfg(feature = "futures")] mod futures_impl;

use std::io;
use std::sync::Arc;
use rustls::{
    Session, ClientSession, ServerSession,
    ClientConfig, ServerConfig
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
    pub fn get_ref(&self) -> (&S, &C) {
        (&self.io, &self.session)
    }

    pub fn get_mut(&mut self) -> (&mut S, &mut C) {
        (&mut self.io, &mut self.session)
    }
}


macro_rules! try_wouldblock {
    ( continue $r:expr ) => {
        match $r {
            Ok(true) => continue,
            Ok(false) => false,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => true,
            Err(e) => return Err(e)
        }
    };
    ( ignore $r:expr ) => {
        match $r {
            Ok(_) => (),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => (),
            Err(e) => return Err(e)
        }
    };
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

    fn do_read(&mut self) -> io::Result<bool> {
        if !self.eof && self.session.wants_read() {
            if self.session.read_tls(&mut self.io)? == 0 {
                self.eof = true;
            }

            if let Err(err) = self.session.process_new_packets() {
                // flush queued messages before returning an Err in
                // order to send alerts instead of abruptly closing
                // the socket
                if self.session.wants_write() {
                    // ignore result to avoid masking original error
                    let _ = self.session.write_tls(&mut self.io);
                }
                return Err(io::Error::new(io::ErrorKind::InvalidData, err));
            }

            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn do_write(&mut self) -> io::Result<bool> {
        if self.session.wants_write() {
            self.session.write_tls(&mut self.io)?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    #[inline]
    pub fn do_io(&mut self) -> io::Result<()> {
        loop {
            let write_would_block = try_wouldblock!(continue self.do_write());
            let read_would_block = try_wouldblock!(continue self.do_read());

            if write_would_block || read_would_block {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            } else {
                return Ok(());
            }
        }
    }
}

impl<S, C> io::Read for TlsStream<S, C>
    where S: io::Read + io::Write, C: Session
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        try_wouldblock!(ignore self.do_io());

        loop {
            match self.session.read(buf) {
                Ok(0) if !self.eof => while self.do_read()? {},
                Ok(n) => return Ok(n),
                Err(e) => if e.kind() == io::ErrorKind::ConnectionAborted {
                    try_wouldblock!(ignore self.do_read());
                    return if self.eof { Ok(0) } else { Err(e) }
                } else {
                    return Err(e)
                }
            }
        }
    }
}

impl<S, C> io::Write for TlsStream<S, C>
    where S: io::Read + io::Write, C: Session
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        try_wouldblock!(ignore self.do_io());

        let mut wlen = self.session.write(buf)?;

        loop {
            match self.do_write() {
                Ok(true) => continue,
                Ok(false) if wlen == 0 => (),
                Ok(false) => break,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock =>
                    if wlen == 0 {
                        // Both rustls buffer and IO buffer are blocking.
                        return Err(io::Error::from(io::ErrorKind::WouldBlock));
                    } else {
                        continue
                    },
                Err(e) => return Err(e)
            }

            assert_eq!(wlen, 0);
            wlen = self.session.write(buf)?;
        }

        Ok(wlen)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.session.flush()?;
        while self.do_write()? {};
        self.io.flush()
    }
}

mod sealed {
    pub trait Sealed {}
}
