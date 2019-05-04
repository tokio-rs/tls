// mod vecbuf;

use std::pin::Pin;
use std::task::Poll;
use std::marker::Unpin;
use std::io::{ self, Read, Write };
use rustls::Session;
use rustls::WriteV;
use futures::task::Context;
use futures::io::{ AsyncRead, AsyncWrite, IoVec };
use smallvec::SmallVec;


pub struct Stream<'a, IO, S> {
    pub io: &'a mut IO,
    pub session: &'a mut S,
}

pub trait WriteTls<IO: AsyncWrite, S: Session> {
    fn write_tls(&mut self, cx: &mut Context) -> io::Result<usize>;
}

#[derive(Clone, Copy)]
enum Focus {
    Empty,
    Readable,
    Writable
}

impl<'a, IO: AsyncRead + AsyncWrite + Unpin, S: Session> Stream<'a, IO, S> {
    pub fn new(io: &'a mut IO, session: &'a mut S) -> Self {
        Stream { io, session }
    }

    pub fn complete_io(&mut self, cx: &mut Context) -> Poll<io::Result<(usize, usize)>> {
        self.complete_inner_io(cx, Focus::Empty)
    }

    fn complete_read_io(&mut self, cx: &mut Context) -> Poll<io::Result<usize>> {
        struct Reader<'a, 'b, T> {
            io: &'a mut T,
            cx: &'a mut Context<'b>
        }

        impl<'a, 'b, T: AsyncRead + Unpin> Read for Reader<'a, 'b, T> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                match Pin::new(&mut self.io).poll_read(self.cx, buf) {
                    Poll::Ready(result) => result,
                    Poll::Pending => Err(io::ErrorKind::WouldBlock.into())
                }
            }
        }

        let mut reader = Reader { io: self.io, cx };

        let n = match self.session.read_tls(&mut reader) {
            Ok(n) => n,
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
            Err(err) => return Poll::Ready(Err(err))
        };

        self.session.process_new_packets()
            .map_err(|err| {
                // In case we have an alert to send describing this error,
                // try a last-gasp write -- but don't predate the primary
                // error.
                let _ = self.write_tls(cx);

                io::Error::new(io::ErrorKind::InvalidData, err)
            })?;

        Poll::Ready(Ok(n))
    }

    fn complete_write_io(&mut self, cx: &mut Context) -> Poll<io::Result<usize>> {
        match self.write_tls(cx) {
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            result => Poll::Ready(result)
        }
    }

    fn complete_inner_io(&mut self, cx: &mut Context, focus: Focus) -> Poll<io::Result<(usize, usize)>> {
        let mut wrlen = 0;
        let mut rdlen = 0;
        let mut eof = false;

        loop {
            let mut write_would_block = false;
            let mut read_would_block = false;

            while self.session.wants_write() {
                match self.complete_write_io(cx) {
                    Poll::Ready(Ok(n)) => wrlen += n,
                    Poll::Pending => {
                        write_would_block = true;
                        break
                    },
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err))
                }
            }

            if !eof && self.session.wants_read() {
                match self.complete_read_io(cx) {
                    Poll::Ready(Ok(0)) => eof = true,
                    Poll::Ready(Ok(n)) => rdlen += n,
                    Poll::Pending => read_would_block = true,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err))
                }
            }

            let would_block = match focus {
                Focus::Empty => write_would_block || read_would_block,
                Focus::Readable => read_would_block,
                Focus::Writable => write_would_block,
            };

            match (eof, self.session.is_handshaking(), would_block) {
                (true, true, _) => return Poll::Pending,
                (_, false, true) => {
                    let would_block = match focus {
                        Focus::Empty => rdlen == 0 && wrlen == 0,
                        Focus::Readable => rdlen == 0,
                        Focus::Writable => wrlen == 0
                    };

                    return if would_block {
                        Poll::Pending
                    } else {
                        Poll::Ready(Ok((rdlen, wrlen)))
                    };
                },
                (_, false, _) => return Poll::Ready(Ok((rdlen, wrlen))),
                (_, true, true) => return Poll::Pending,
                (..) => ()
            }
        }
    }
}

impl<'a, IO: AsyncRead + AsyncWrite + Unpin, S: Session> WriteTls<IO, S> for Stream<'a, IO, S> {
    fn write_tls(&mut self, cx: &mut Context) -> io::Result<usize> {
        struct Writer<'a, 'b, IO> {
            io: &'a mut IO,
            cx: &'a mut Context<'b>
        }

        impl<'a, 'b, IO: AsyncWrite + Unpin> WriteV for Writer<'a, 'b, IO> {
            fn writev(&mut self, vbytes: &[&[u8]]) -> io::Result<usize> {
                let vbytes = vbytes
                    .into_iter()
                    .try_fold(SmallVec::<[&'_ IoVec; 16]>::new(), |mut sum, next| {
                        sum.push(IoVec::from_bytes(next)?);
                        Some(sum)
                    })
                    .unwrap_or_default();

                match Pin::new(&mut self.io).poll_vectored_write(self.cx, &vbytes) {
                    Poll::Ready(result) => result,
                    Poll::Pending => Err(io::ErrorKind::WouldBlock.into())
                }
            }
        }

        let mut vecio = Writer { io: self.io, cx };
        self.session.writev_tls(&mut vecio)
    }
}

impl<'a, IO: AsyncRead + AsyncWrite + Unpin, S: Session> Stream<'a, IO, S> {
    fn poll_read(&mut self, cx: &mut Context, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        while self.session.wants_read() {
            match self.complete_inner_io(cx, Focus::Readable) {
                Poll::Ready(Ok((0, _))) => break,
                Poll::Ready(Ok(_)) => (),
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err))
            }
        }

        // FIXME rustls always ready ?
        Poll::Ready(self.session.read(buf))
    }

    fn poll_write(&mut self, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        let len = self.session.write(buf)?;
        while self.session.wants_write() {
            match self.complete_inner_io(cx, Focus::Writable) {
                Poll::Ready(Ok(_)) => (),
                Poll::Pending if len != 0 => break,
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err))
            }
        }

        if len != 0 || buf.is_empty() {
            Poll::Ready(Ok(len))
        } else {
            // not write zero
            match self.session.write(buf) {
                Ok(0) => Poll::Pending,
                Ok(n) => Poll::Ready(Ok(n)),
                Err(err) => Poll::Ready(Err(err))
            }
        }
    }

    fn poll_flush(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        self.session.flush()?;
        while self.session.wants_write() {
            match self.complete_inner_io(cx, Focus::Writable) {
                Poll::Ready(Ok(_)) => (),
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err))
            }
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod test_stream;
