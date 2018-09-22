use super::*;
use tokio::prelude::*;
use tokio::io::{ AsyncRead, AsyncWrite };
use tokio::prelude::Poll;
use common::Stream;


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
    where IO: io::Read + io::Write, S: Session
{
    type Item = TlsStream<IO, S>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        {
            let stream = self.inner.as_mut().unwrap();
            if stream.session.is_handshaking() {
                let (io, session) = stream.get_mut();
                let mut stream = Stream::new(session, io);

                match stream.complete_io() {
                    Ok(_) => (),
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(Async::NotReady),
                    Err(e) => return Err(e)
                }
            }
        }

        Ok(Async::Ready(self.inner.take().unwrap()))
    }
}

impl<IO, S> AsyncRead for TlsStream<IO, S>
    where
        IO: AsyncRead + AsyncWrite,
        S: Session
{
    unsafe fn prepare_uninitialized_buffer(&self, _: &mut [u8]) -> bool {
        false
    }
}

impl<IO, S> AsyncWrite for TlsStream<IO, S>
    where
        IO: AsyncRead + AsyncWrite,
        S: Session
{
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        if !self.is_shutdown {
            self.session.send_close_notify();
            self.is_shutdown = true;
        }

        match self.session.complete_io(&mut self.io) {
            Ok(_) => (),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(Async::NotReady),
            Err(e) => return Err(e)
        }

        self.io.shutdown()
    }
}
