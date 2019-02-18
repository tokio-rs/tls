//! Asynchronous TLS/SSL streams for Tokio using [Rustls](https://github.com/ctz/rustls).

pub extern crate rustls;
pub extern crate webpki;

extern crate futures;
extern crate tokio_io;
extern crate bytes;
extern crate iovec;


mod common;
mod tokio_impl;

use std::mem;
use std::io::{ self, Write };
use std::sync::Arc;
use webpki::DNSNameRef;
use rustls::{
    Session, ClientSession, ServerSession,
    ClientConfig, ServerConfig
};
use tokio_io::{ AsyncRead, AsyncWrite };
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
            MidHandshake::EarlyData(TlsStream {
                session, io: stream,
                state: TlsState::EarlyData,
                early_data: (0, Vec::new())
            })
        } else {
            MidHandshake::Handshaking(TlsStream {
                session, io: stream,
                state: TlsState::Stream,
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

        Accept(MidHandshake::Handshaking(TlsStream {
            session, io: stream,
            state: TlsState::Stream,
            early_data: (0, Vec::new())
        }))
    }
}


/// Future returned from `ClientConfigExt::connect_async` which will resolve
/// once the connection handshake has finished.
pub struct Connect<IO>(MidHandshake<IO, ClientSession>);

/// Future returned from `ServerConfigExt::accept_async` which will resolve
/// once the accept handshake has finished.
pub struct Accept<IO>(MidHandshake<IO, ServerSession>);

enum MidHandshake<IO, S> {
    Handshaking(TlsStream<IO, S>),
    EarlyData(TlsStream<IO, S>),
    End
}


/// A wrapper around an underlying raw stream which implements the TLS or SSL
/// protocol.
#[derive(Debug)]
pub struct TlsStream<IO, S> {
    io: IO,
    session: S,
    state: TlsState,
    early_data: (usize, Vec<u8>)
}

#[derive(Debug)]
enum TlsState {
    EarlyData,
    Stream,
    Eof,
    Shutdown
}

impl<IO, S> TlsStream<IO, S> {
    #[inline]
    pub fn get_ref(&self) -> (&IO, &S) {
        (&self.io, &self.session)
    }

    #[inline]
    pub fn get_mut(&mut self) -> (&mut IO, &mut S) {
        (&mut self.io, &mut self.session)
    }

    #[inline]
    pub fn into_inner(self) -> (IO, S) {
        (self.io, self.session)
    }
}

impl<IO> io::Read for TlsStream<IO, ClientSession>
where IO: AsyncRead + AsyncWrite
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut stream = Stream::new(&mut self.io, &mut self.session);

        match self.state {
            TlsState::EarlyData => {
                let (pos, data) = &mut self.early_data;

                // complete handshake
                if stream.session.is_handshaking() {
                    stream.complete_io()?;
                }

                // write early data (fallback)
                if !stream.session.is_early_data_accepted() {
                    while *pos < data.len() {
                        let len = stream.write(&data[*pos..])?;
                        *pos += len;
                    }
                }

                // end
                self.state = TlsState::Stream;
                data.clear();
                stream.read(buf)
            },
            TlsState::Stream => match stream.read(buf) {
                Ok(0) => {
                    self.state = TlsState::Eof;
                    Ok(0)
                },
                Ok(n) => Ok(n),
                Err(ref e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                    self.state = TlsState::Shutdown;
                    stream.session.send_close_notify();
                    Ok(0)
                },
                Err(e) => Err(e)
            },
            TlsState::Eof | TlsState::Shutdown => Ok(0),
        }
    }
}

impl<IO> io::Read for TlsStream<IO, ServerSession>
where IO: AsyncRead + AsyncWrite
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut stream = Stream::new(&mut self.io, &mut self.session);

        match self.state {
            TlsState::Stream => match stream.read(buf) {
                Ok(0) => {
                    self.state = TlsState::Eof;
                    Ok(0)
                },
                Ok(n) => Ok(n),
                Err(ref e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                    self.state = TlsState::Shutdown;
                    stream.session.send_close_notify();
                    Ok(0)
                },
                Err(e) => Err(e)
            },
            TlsState::Eof | TlsState::Shutdown => Ok(0),
            TlsState::EarlyData => unreachable!()
        }
    }
}

impl<IO> io::Write for TlsStream<IO, ClientSession>
where IO: AsyncRead + AsyncWrite
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut stream = Stream::new(&mut self.io, &mut self.session);

        match self.state {
            TlsState::EarlyData => {
                let (pos, data) = &mut self.early_data;

                // write early data
                if let Some(mut early_data) = stream.session.early_data() {
                    let len = early_data.write(buf)?;
                    data.extend_from_slice(&buf[..len]);
                    return Ok(len);
                }

                // complete handshake
                if stream.session.is_handshaking() {
                    stream.complete_io()?;
                }

                // write early data (fallback)
                if !stream.session.is_early_data_accepted() {
                    while *pos < data.len() {
                        let len = stream.write(&data[*pos..])?;
                        *pos += len;
                    }
                }

                // end
                self.state = TlsState::Stream;
                data.clear();
                stream.write(buf)
            },
            _ => stream.write(buf)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Stream::new(&mut self.io, &mut self.session).flush()?;
        self.io.flush()
    }
}

impl<IO> io::Write for TlsStream<IO, ServerSession>
where IO: AsyncRead + AsyncWrite
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut stream = Stream::new(&mut self.io, &mut self.session);
        stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Stream::new(&mut self.io, &mut self.session).flush()?;
        self.io.flush()
    }
}

#[cfg(test)]
mod test_0rtt;
