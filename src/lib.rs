//! Asynchronous TLS/SSL streams for Tokio using [Rustls](https://github.com/ctz/rustls).


#[cfg_attr(feature = "tokio-proto", macro_use)] extern crate futures;
extern crate tokio_io;
extern crate rustls;

pub mod proto;

use std::io;
use std::sync::Arc;
use futures::{ Future, Poll, Async };
use tokio_io::{ AsyncRead, AsyncWrite };
use rustls::{ Session, ClientSession, ServerSession };
use rustls::{ ClientConfig, ServerConfig };


/// Extension trait for the `Arc<ClientConfig>` type in the `rustls` crate.
pub trait ClientConfigExt {
    fn connect_async<S>(&self, domain: &str, stream: S)
        -> ConnectAsync<S>
        where S: AsyncRead + AsyncWrite;
}

/// Extension trait for the `Arc<ServerConfig>` type in the `rustls` crate.
pub trait ServerConfigExt {
    fn accept_async<S>(&self, stream: S)
        -> AcceptAsync<S>
        where S: AsyncRead + AsyncWrite;
}


/// Future returned from `ClientConfigExt::connect_async` which will resolve
/// once the connection handshake has finished.
pub struct ConnectAsync<S>(MidHandshake<S, ClientSession>);

/// Future returned from `ServerConfigExt::accept_async` which will resolve
/// once the accept handshake has finished.
pub struct AcceptAsync<S>(MidHandshake<S, ServerSession>);


impl ClientConfigExt for Arc<ClientConfig> {
    fn connect_async<S>(&self, domain: &str, stream: S)
        -> ConnectAsync<S>
        where S: AsyncRead + AsyncWrite
    {
        ConnectAsync(MidHandshake {
            inner: Some(TlsStream::new(stream, ClientSession::new(self, domain)))
        })
    }
}

impl ServerConfigExt for Arc<ServerConfig> {
    fn accept_async<S>(&self, stream: S)
        -> AcceptAsync<S>
        where S: AsyncRead + AsyncWrite
    {
        AcceptAsync(MidHandshake {
            inner: Some(TlsStream::new(stream, ServerSession::new(self)))
        })
    }
}

impl<S: AsyncRead + AsyncWrite> Future for ConnectAsync<S> {
    type Item = TlsStream<S, ClientSession>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

impl<S: AsyncRead + AsyncWrite> Future for AcceptAsync<S> {
    type Item = TlsStream<S, ServerSession>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}


struct MidHandshake<S, C> {
    inner: Option<TlsStream<S, C>>
}

impl<S, C> Future for MidHandshake<S, C>
    where S: AsyncRead + AsyncWrite, C: Session
{
    type Item = TlsStream<S, C>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            let stream = self.inner.as_mut().unwrap();
            if !stream.session.is_handshaking() { break };

            match stream.do_io() {
                Ok(()) => match (stream.eof, stream.session.is_handshaking()) {
                    (true, true) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                    (false, true) => continue,
                    (..) => break
                },
                Err(e) => match (e.kind(), stream.session.is_handshaking()) {
                    (io::ErrorKind::WouldBlock, true) => return Ok(Async::NotReady),
                    (io::ErrorKind::WouldBlock, false) => break,
                    (..) => return Err(e)
                }
            }
        }

        Ok(Async::Ready(self.inner.take().unwrap()))
    }
}


/// A wrapper around an underlying raw stream which implements the TLS or SSL
/// protocol.
#[derive(Debug)]
pub struct TlsStream<S, C> {
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

impl<S, C> TlsStream<S, C>
    where S: AsyncRead + AsyncWrite, C: Session
{
    #[inline]
    pub fn new(io: S, session: C) -> TlsStream<S, C> {
        TlsStream {
            eof: false,
            io: io,
            session: session
        }
    }

    pub fn do_io(&mut self) -> io::Result<()> {
        loop {
            let read_would_block = if !self.eof && self.session.wants_read() {
                match self.session.read_tls(&mut self.io) {
                    Ok(0) => {
                        self.eof = true;
                        continue
                    },
                    Ok(_) => {
                        self.session.process_new_packets()
                            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
                        continue
                    },
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => true,
                    Err(e) => return Err(e)
                }
            } else {
                false
            };

            let write_would_block = if self.session.wants_write() {
                match self.session.write_tls(&mut self.io) {
                    Ok(_) => continue,
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => true,
                    Err(e) => return Err(e)
                }
            } else {
                false
            };

            if read_would_block || write_would_block {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            } else {
                return Ok(());
            }
        }
    }
}

impl<S, C> io::Read for TlsStream<S, C>
    where S: AsyncRead + AsyncWrite, C: Session
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.session.read(buf) {
                Ok(0) if !self.eof => self.do_io()?,
                Ok(n) => return Ok(n),
                Err(e) => if e.kind() == io::ErrorKind::ConnectionAborted {
                    self.do_io()?;
                    return if self.eof { Ok(0) } else { Err(e) }
                } else {
                    return Err(e)
                }
            }
        }
    }
}

impl<S, C> io::Write for TlsStream<S, C>
    where S: AsyncRead + AsyncWrite, C: Session
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let output = self.session.write(buf)?;

        while self.session.wants_write() {
            match self.session.write_tls(&mut self.io) {
                Ok(_) => (),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e)
            }
        }

        Ok(output)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.session.flush()?;
        while self.session.wants_write() {
            self.session.write_tls(&mut self.io)?;
        }
        Ok(())
    }
}

impl<S, C> AsyncRead for TlsStream<S, C>
    where
        S: AsyncRead + AsyncWrite,
        C: Session
{}

impl<S, C> AsyncWrite for TlsStream<S, C>
    where
        S: AsyncRead + AsyncWrite,
        C: Session
{
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        self.session.send_close_notify();
        self.io.shutdown()
    }
}
