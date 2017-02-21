extern crate futures;
extern crate tokio_core;
extern crate rustls;

use std::io;
use std::sync::Arc;
use futures::{ Future, Poll, Async };
use tokio_core::io::Io;
use rustls::{ Session, ClientSession, ServerSession };
pub use rustls::{ ClientConfig, ServerConfig };


pub trait TlsConnectorExt {
    fn connect_async<S>(&self, domain: &str, stream: S)
        -> ConnectAsync<S>
        where S: Io;
}

pub trait TlsAcceptorExt {
    fn accept_async<S>(&self, stream: S)
        -> AcceptAsync<S>
        where S: Io;
}


pub struct ConnectAsync<S>(MidHandshake<S, ClientSession>);

pub struct AcceptAsync<S>(MidHandshake<S, ServerSession>);


impl TlsConnectorExt for Arc<ClientConfig> {
    fn connect_async<S>(&self, domain: &str, stream: S)
        -> ConnectAsync<S>
        where S: Io
    {
        ConnectAsync(MidHandshake {
            inner: Some(TlsStream::new(stream, ClientSession::new(self, domain)))
        })
    }
}

impl TlsAcceptorExt for Arc<ServerConfig> {
    fn accept_async<S>(&self, stream: S)
        -> AcceptAsync<S>
        where S: Io
    {
        AcceptAsync(MidHandshake {
            inner: Some(TlsStream::new(stream, ServerSession::new(self)))
        })
    }
}

impl<S: Io> Future for ConnectAsync<S> {
    type Item = TlsStream<S, ClientSession>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

impl<S: Io> Future for AcceptAsync<S> {
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
    where S: Io, C: Session
{
    type Item = TlsStream<S, C>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            let stream = self.inner.as_mut().unwrap_or_else(|| unreachable!());
            if !stream.session.is_handshaking() { break };

            match stream.do_io() {
                Ok(()) => continue,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => (),
                Err(e) => return Err(e)
            }
            if !stream.session.is_handshaking() { break };

            if stream.eof {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            } else {
                return Ok(Async::NotReady);
            }
        }

        Ok(Async::Ready(self.inner.take().unwrap_or_else(|| unreachable!())))
    }
}


pub struct TlsStream<S, C> {
    eof: bool,
    io: S,
    session: C
}

impl<S, C> TlsStream<S, C>
    where S: Io, C: Session
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
            let read_would_block = match (!self.eof && self.session.wants_read(), self.io.poll_read()) {
                (true, Async::Ready(())) => {
                    match self.session.read_tls(&mut self.io) {
                        Ok(0) => self.eof = true,
                        Ok(_) => self.session.process_new_packets()
                            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?,
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => (),
                        Err(e) => return Err(e)
                    };
                    continue
                },
                (true, Async::NotReady) => true,
                (false, _) => false,
            };

            let write_would_block = match (self.session.wants_write(), self.io.poll_write()) {
                (true, Async::Ready(())) => match self.session.write_tls(&mut self.io) {
                    Ok(_) => continue,
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(e) => return Err(e)
                },
                (true, Async::NotReady) => true,
                (false, _) => false
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
    where S: Io, C: Session
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.do_io()?;
        if self.eof {
            Ok(0)
        } else {
            self.session.read(buf)
        }
    }
}

impl<S, C> io::Write for TlsStream<S, C>
    where S: Io, C: Session
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        while self.session.wants_write() && self.io.poll_write().is_ready() {
            self.session.write_tls(&mut self.io)?;
        }
        self.session.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.session.flush()?;
        while self.session.wants_write() && self.io.poll_write().is_ready() {
            self.session.write_tls(&mut self.io)?;
        }
        Ok(())
    }
}

impl<S, C> Io for TlsStream<S, C> where S: Io, C: Session {}
