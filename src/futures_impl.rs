extern crate futures;

use super::*;
use self::futures::{ Future, Poll, Async };
use self::futures::io::{ Error, AsyncRead, AsyncWrite };
use self::futures::task::Context;


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

            let mut taskio = TaskStream { io: &mut stream.io, task: ctx };

            match TlsStream::do_io(&mut stream.session, &mut taskio, &mut stream.eof) {
                Ok(()) => match (stream.eof, stream.session.is_handshaking()) {
                    (true, true) => return Err(io::ErrorKind::UnexpectedEof.into()),
                    (false, true) => continue,
                    (..) => break
                },
                Err(e) => match (e.kind(), stream.session.is_handshaking()) {
                    (io::ErrorKind::WouldBlock, true) => return Ok(Async::Pending),
                    (io::ErrorKind::WouldBlock, false) => break,
                    (..) => return Err(e)
                }
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
        let mut taskio = TaskStream { io: &mut self.io, task: ctx };
        // FIXME TlsStream + TaskStream
        async!(from io::Read::read(&mut taskio, buf))
    }
}

impl<S, C> AsyncWrite for TlsStream<S, C>
    where
        S: AsyncRead + AsyncWrite,
        C: Session
{
    fn poll_write(&mut self, ctx: &mut Context, buf: &[u8]) -> Poll<usize, Error> {
        let mut taskio = TaskStream { io: &mut self.io, task: ctx };
        // FIXME TlsStream + TaskStream
        async!(from io::Write::write(&mut taskio, buf))
    }

    fn poll_flush(&mut self, ctx: &mut Context) -> Poll<(), Error> {
        let mut taskio = TaskStream { io: &mut self.io, task: ctx };
        // FIXME TlsStream + TaskStream
        async!(from io::Write::flush(&mut taskio))
    }

    fn poll_close(&mut self, ctx: &mut Context) -> Poll<(), Error> {
        if !self.is_shutdown {
            self.session.send_close_notify();
            self.is_shutdown = true;
        }

        {
            let mut taskio = TaskStream { io: &mut self.io, task: ctx };
            while TlsStream::do_write(&mut self.session, &mut taskio)? {};
        }

        self.io.poll_close(ctx)
    }
}
