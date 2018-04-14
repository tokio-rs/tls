extern crate futures_core;
extern crate futures_io;

use super::*;
use self::futures_core::{ Future, Poll, Async };
use self::futures_core::task::Context;
use self::futures_io::{ Error, AsyncRead, AsyncWrite };


impl<S: AsyncRead + AsyncWrite> Future for ConnectAsync<S> {
    type Item = TlsStream<S, ClientSession>;
    type Error = io::Error;

    fn poll(&mut self, ctx: &mut Context) -> Poll<Self::Item, Self::Error> {
        self.0.poll(ctx)
    }
}

impl<S: AsyncRead + AsyncWrite> Future for AcceptAsync<S> {
    type Item = TlsStream<S, ServerSession>;
    type Error = io::Error;

    fn poll(&mut self, ctx: &mut Context) -> Poll<Self::Item, Self::Error> {
        self.0.poll(ctx)
    }
}

macro_rules! async {
    ( to $r:expr ) => {
        match $r {
            Ok(Async::Ready(n)) => Ok(n),
            Ok(Async::Pending) => Err(io::ErrorKind::WouldBlock.into()),
            Err(e) => Err(e)
        }
    };
    ( from $r:expr ) => {
        match $r {
            Ok(n) => Ok(Async::Ready(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(Async::Pending),
            Err(e) => Err(e)
        }
    };
}

struct TaskStream<'a, 'b: 'a, S: 'a> {
    io: &'a mut S,
    task: &'a mut Context<'b>
}

impl<'a, 'b, S> io::Read for TaskStream<'a, 'b, S>
    where S: AsyncRead + AsyncWrite
{
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        async!(to self.io.poll_read(self.task, buf))
    }
}

impl<'a, 'b, S> io::Write for TaskStream<'a, 'b, S>
    where S: AsyncRead + AsyncWrite
{
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        async!(to self.io.poll_write(self.task, buf))
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        async!(to self.io.poll_flush(self.task))
    }
}

impl<S, C> Future for MidHandshake<S, C>
    where S: AsyncRead + AsyncWrite, C: Session
{
    type Item = TlsStream<S, C>;
    type Error = io::Error;

    fn poll(&mut self, ctx: &mut Context) -> Poll<Self::Item, Self::Error> {
        loop {
            let stream = self.inner.as_mut().unwrap();
            if !stream.session.is_handshaking() { break };

            let (io, session) = stream.get_mut();
            let mut taskio = TaskStream { io, task: ctx };

            match session.complete_io(&mut taskio) {
                Ok(_) => (),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(Async::Pending),
                Err(e) => return Err(e)
            }
        }

        Ok(Async::Ready(self.inner.take().unwrap()))
    }
}

impl<S, C> AsyncRead for TlsStream<S, C>
    where
        S: AsyncRead + AsyncWrite,
        C: Session
{
    fn poll_read(&mut self, ctx: &mut Context, buf: &mut [u8]) -> Poll<usize, Error> {
        if self.eof {
            return Ok(Async::Ready(0));
        }

        // TODO nll
        let result = {
            let (io, session) = self.get_mut();
            let mut taskio = TaskStream { io, task: ctx };
            let mut stream = Stream::new(session, &mut taskio);
            io::Read::read(&mut stream, buf)
        };

        match result {
            Ok(0) => { self.eof = true; Ok(Async::Ready(0)) },
            Ok(n) => Ok(Async::Ready(n)),
            Err(ref e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                self.eof = true;
                self.is_shutdown = true;
                self.session.send_close_notify();
                Ok(Async::Ready(0))
            },
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(Async::Pending),
            Err(e) => Err(e)
        }
    }
}

impl<S, C> AsyncWrite for TlsStream<S, C>
    where
        S: AsyncRead + AsyncWrite,
        C: Session
{
    fn poll_write(&mut self, ctx: &mut Context, buf: &[u8]) -> Poll<usize, Error> {
        let (io, session) = self.get_mut();
        let mut taskio = TaskStream { io, task: ctx };
        let mut stream = Stream::new(session, &mut taskio);

        async!(from io::Write::write(&mut stream, buf))
    }

    fn poll_flush(&mut self, ctx: &mut Context) -> Poll<(), Error> {
        let (io, session) = self.get_mut();
        let mut taskio = TaskStream { io, task: ctx };

        {
            let mut stream = Stream::new(session, &mut taskio);
            async!(from io::Write::flush(&mut stream))?;
        }

        async!(from io::Write::flush(&mut taskio))
    }

    fn poll_close(&mut self, ctx: &mut Context) -> Poll<(), Error> {
        if !self.is_shutdown {
            self.session.send_close_notify();
            self.is_shutdown = true;
        }

        {
            let (io, session) = self.get_mut();
            let mut taskio = TaskStream { io, task: ctx };
            async!(from session.complete_io(&mut taskio))?;
        }

        self.io.poll_close(ctx)
    }
}
