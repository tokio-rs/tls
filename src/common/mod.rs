use std::pin::Pin;
use std::task::{ Poll, Context };
use std::marker::Unpin;
use std::io::{ self, Read, Write };
use rustls::Session;
use tokio_io::{ AsyncRead, AsyncWrite };
use futures_core as futures;


pub struct Stream<'a, IO, S> {
    pub io: &'a mut IO,
    pub session: &'a mut S,
    pub eof: bool
}

impl<'a, IO: AsyncRead + AsyncWrite + Unpin, S: Session> Stream<'a, IO, S> {
    pub fn new(io: &'a mut IO, session: &'a mut S) -> Self {
        Stream {
            io,
            session,
            // The state so far is only used to detect EOF, so either Stream
            // or EarlyData state should both be all right.
            eof: false,
        }
    }

    pub fn set_eof(mut self, eof: bool) -> Self {
        self.eof = eof;
        self
    }

    pub fn as_mut_pin(&mut self) -> Pin<&mut Self> {
        Pin::new(self)
    }

    fn process_new_packets(&mut self, cx: &mut Context) -> io::Result<()> {
        self.session.process_new_packets()
            .map_err(|err| {
                // In case we have an alert to send describing this error,
                // try a last-gasp write -- but don't predate the primary
                // error.
                let _ = self.write_io(cx);

                io::Error::new(io::ErrorKind::InvalidData, err)
            })
    }

    fn read_io(&mut self, cx: &mut Context) -> Poll<io::Result<usize>> {
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

        Poll::Ready(Ok(n))
    }

    fn write_io(&mut self, cx: &mut Context) -> Poll<io::Result<usize>> {
        struct Writer<'a, 'b, T> {
            io: &'a mut T,
            cx: &'a mut Context<'b>
        }

        impl<'a, 'b, T: AsyncWrite + Unpin> Write for Writer<'a, 'b, T> {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                match Pin::new(&mut self.io).poll_write(self.cx, buf) {
                    Poll::Ready(result) => result,
                    Poll::Pending => Err(io::ErrorKind::WouldBlock.into())
                }
            }

            fn flush(&mut self) -> io::Result<()> {
                match Pin::new(&mut self.io).poll_flush(self.cx) {
                    Poll::Ready(result) => result,
                    Poll::Pending => Err(io::ErrorKind::WouldBlock.into())
                }
            }
        }

        let mut writer = Writer { io: self.io, cx };

        match self.session.write_tls(&mut writer) {
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            result => Poll::Ready(result)
        }
    }

    pub fn handshake(&mut self, cx: &mut Context) -> Poll<io::Result<(usize, usize)>> {
        let mut wrlen = 0;
        let mut rdlen = 0;

        loop {
            let mut write_would_block = false;
            let mut read_would_block = false;

            while self.session.wants_write() {
                match self.write_io(cx) {
                    Poll::Ready(Ok(n)) => wrlen += n,
                    Poll::Pending => {
                        write_would_block = true;
                        break
                    },
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err))
                }
            }

            while !self.eof && self.session.wants_read() {
                match self.read_io(cx) {
                    Poll::Ready(Ok(0)) => self.eof = true,
                    Poll::Ready(Ok(n)) => rdlen += n,
                    Poll::Pending => {
                        read_would_block = true;
                        break
                    },
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err))
                }
            }

            self.process_new_packets(cx)?;

            return match (self.eof, self.session.is_handshaking()) {
                (true, true) => {
                    let err = io::Error::new(io::ErrorKind::UnexpectedEof, "tls handshake eof");
                    Poll::Ready(Err(err))
                },
                (_, false) => Poll::Ready(Ok((rdlen, wrlen))),
                (_, true) if write_would_block || read_would_block => if rdlen != 0 || wrlen != 0 {
                    Poll::Ready(Ok((rdlen, wrlen)))
                } else {
                    Poll::Pending
                },
                (..) => continue
            }
        }
    }
}

impl<'a, IO: AsyncRead + AsyncWrite + Unpin, S: Session> AsyncRead for Stream<'a, IO, S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut pos = 0;

        while pos != buf.len() {
            let mut would_block = false;

            // read a packet
            while this.session.wants_read() {
                match this.read_io(cx) {
                    Poll::Ready(Ok(0)) => {
                        this.eof = true;
                        break
                    },
                    Poll::Ready(Ok(_)) => (),
                    Poll::Pending => {
                        would_block = true;
                        break
                    },
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err))
                }
            }

            this.process_new_packets(cx)?;

            return match this.session.read(&mut buf[pos..]) {
                Ok(0) if pos == 0 && would_block => Poll::Pending,
                Ok(n) if this.eof || would_block => Poll::Ready(Ok(pos + n)),
                Ok(n) => {
                    pos += n;
                    continue
                },
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
                Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted && pos != 0 =>
                    Poll::Ready(Ok(pos)),
                Err(err) => Poll::Ready(Err(err))
            }
        }

        Poll::Ready(Ok(pos))
    }
}

impl<'a, IO: AsyncRead + AsyncWrite + Unpin, S: Session> AsyncWrite for Stream<'a, IO, S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut pos = 0;

        while pos != buf.len() {
            let mut would_block = false;

            match this.session.write(&buf[pos..]) {
                Ok(n) => pos += n,
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => (),
                Err(err) => return Poll::Ready(Err(err))
            };

            while this.session.wants_write() {
                match this.write_io(cx) {
                    Poll::Ready(Ok(0)) | Poll::Pending => {
                        would_block = true;
                        break
                    },
                    Poll::Ready(Ok(_)) => (),
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err))
                }
            }

            return match (pos, would_block) {
                (0, true) => Poll::Pending,
                (n, true) => Poll::Ready(Ok(n)),
                (_, false) => continue
            }
        }

        Poll::Ready(Ok(pos))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        this.session.flush()?;
        while this.session.wants_write() {
            futures::ready!(this.write_io(cx))?;
        }
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        while this.session.wants_write() {
            futures::ready!(this.write_io(cx))?;
        }

        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod test_stream;
