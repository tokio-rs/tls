extern crate futures;

use super::*;
use self::futures::{ Future, Poll, Async };
use self::futures::io::{ Error, AsyncRead, AsyncWrite };
use self::futures::task::Context;


impl<S: io::Read + io::Write> Future for ConnectAsync<S> {
    type Item = TlsStream<S, ClientSession>;
    type Error = io::Error;

    fn poll(&mut self, ctx: &mut Context) -> Poll<Self::Item, Self::Error> {
        self.0.poll(ctx)
    }
}

impl<S: io::Read + io::Write> Future for AcceptAsync<S> {
    type Item = TlsStream<S, ServerSession>;
    type Error = io::Error;

    fn poll(&mut self, ctx: &mut Context) -> Poll<Self::Item, Self::Error> {
        self.0.poll(ctx)
    }
}

impl<S, C> Future for MidHandshake<S, C>
    where S: io::Read + io::Write, C: Session
{
    type Item = TlsStream<S, C>;
    type Error = io::Error;

    fn poll(&mut self, _: &mut Context) -> Poll<Self::Item, Self::Error> {
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
    fn poll_read(&mut self, _: &mut Context, buf: &mut [u8]) -> Poll<usize, Error> {
        unimplemented!()
    }
}

impl<S, C> AsyncWrite for TlsStream<S, C>
    where
        S: AsyncRead + AsyncWrite,
        C: Session
{
    fn poll_write(&mut self, _: &mut Context, buf: &[u8]) -> Poll<usize, Error> {
        unimplemented!()
    }

    fn poll_flush(&mut self, _: &mut Context) -> Poll<(), Error> {
        unimplemented!()
    }

    fn poll_close(&mut self, _: &mut Context) -> Poll<(), Error> {
        unimplemented!()
    }
}
