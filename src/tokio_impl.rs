use super::*;
use tokio_io::{ AsyncRead, AsyncWrite };
use futures::{Async, Future, Poll};
use common::Stream;


macro_rules! try_async {
    ( $e:expr ) => {
        match $e {
            Ok(n) => n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock =>
                return Ok(Async::NotReady),
            Err(e) => return Err(e)
        }
    }
}

impl<IO: AsyncRead + AsyncWrite> Future for Connect<IO> {
    type Item = TlsStream<IO, ClientSession>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

impl<IO: AsyncRead + AsyncWrite> Future for Accept<IO> {
    type Item = TlsStream<IO, ServerSession>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

impl<IO, S> Future for MidHandshake<IO, S>
where
    IO: AsyncRead + AsyncWrite,
    S: Session
{
    type Item = TlsStream<IO, S>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self {
            MidHandshake::Handshaking(stream) => {
                let (io, session) = stream.get_mut();
                let mut stream = Stream::new(io, session);

                if stream.session.is_handshaking() {
                    try_async!(stream.complete_io());
                }

                if stream.session.wants_write() {
                    try_async!(stream.complete_io());
                }
            },
            _ => ()
        }

        match mem::replace(self, MidHandshake::End) {
            MidHandshake::Handshaking(stream)
            | MidHandshake::EarlyData(stream) => Ok(Async::Ready(stream)),
            MidHandshake::End => panic!()
        }
    }
}

impl<IO> AsyncRead for TlsStream<IO, ClientSession>
where IO: AsyncRead + AsyncWrite
{
    unsafe fn prepare_uninitialized_buffer(&self, _: &mut [u8]) -> bool {
        false
    }
}

impl<IO> AsyncRead for TlsStream<IO, ServerSession>
where IO: AsyncRead + AsyncWrite
{
    unsafe fn prepare_uninitialized_buffer(&self, _: &mut [u8]) -> bool {
        false
    }
}

impl<IO> AsyncWrite for TlsStream<IO, ClientSession>
where IO: AsyncRead + AsyncWrite,
{
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        match self.state {
            TlsState::Shutdown => (),
            _ => {
                self.session.send_close_notify();
                self.state = TlsState::Shutdown;
            }
        }

        {
            let mut stream = Stream::new(&mut self.io, &mut self.session);
            try_async!(stream.complete_io());
        }
        self.io.shutdown()
    }
}

impl<IO> AsyncWrite for TlsStream<IO, ServerSession>
where IO: AsyncRead + AsyncWrite,
{
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        match self.state {
            TlsState::Shutdown => (),
            _ => {
                self.session.send_close_notify();
                self.state = TlsState::Shutdown;
            }
        }

        {
            let mut stream = Stream::new(&mut self.io, &mut self.session);
            try_async!(stream.complete_io());
        }
        self.io.shutdown()
    }
}
