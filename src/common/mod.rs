mod vecbuf;

use std::io::{ self, Read, Write };
use rustls::Session;
use rustls::WriteV;
use tokio_io::{ AsyncRead, AsyncWrite };


pub struct Stream<'a, IO: 'a, S: 'a> {
    pub io: &'a mut IO,
    pub session: &'a mut S
}

pub trait WriteTls<'a, IO: AsyncRead + AsyncWrite, S: Session>: Read + Write {
    fn write_tls(&mut self) -> io::Result<usize>;
}

impl<'a, IO: AsyncRead + AsyncWrite, S: Session> Stream<'a, IO, S> {
    pub fn new(io: &'a mut IO, session: &'a mut S) -> Self {
        Stream { io, session }
    }

    pub fn complete_io(&mut self) -> io::Result<(usize, usize)> {
        // fork from https://github.com/ctz/rustls/blob/master/src/session.rs#L161

        let until_handshaked = self.session.is_handshaking();
        let mut eof = false;
        let mut wrlen = 0;
        let mut rdlen = 0;

        loop {
            while self.session.wants_write() {
                wrlen += self.write_tls()?;
            }

            if !until_handshaked && wrlen > 0 {
                return Ok((rdlen, wrlen));
            }

            if !eof && self.session.wants_read() {
                match self.session.read_tls(self.io)? {
                    0 => eof = true,
                    n => rdlen += n
                }
            }

            match self.session.process_new_packets() {
                Ok(_) => {},
                Err(e) => {
                    // In case we have an alert to send describing this error,
                    // try a last-gasp write -- but don't predate the primary
                    // error.
                    let _ignored = self.write_tls();

                    return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                },
            };

            match (eof, until_handshaked, self.session.is_handshaking()) {
                (_, true, false) => return Ok((rdlen, wrlen)),
                (_, false, _) => return Ok((rdlen, wrlen)),
                (true, true, true) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                (..) => ()
            }
        }
    }
}

impl<'a, IO: AsyncRead + AsyncWrite, S: Session> WriteTls<'a, IO, S> for Stream<'a, IO, S> {
    fn write_tls(&mut self) -> io::Result<usize> {
        use futures::Async;
        use self::vecbuf::VecBuf;

        struct V<'a, IO: 'a>(&'a mut IO);

        impl<'a, IO: AsyncWrite> WriteV for V<'a, IO> {
            fn writev(&mut self, vbytes: &[&[u8]]) -> io::Result<usize> {
                let mut vbytes = VecBuf::new(vbytes);
                match self.0.write_buf(&mut vbytes) {
                    Ok(Async::Ready(n)) => Ok(n),
                    Ok(Async::NotReady) => Err(io::ErrorKind::WouldBlock.into()),
                    Err(err) => Err(err)
                }
            }
        }

        let mut vecio = V(self.io);
        self.session.writev_tls(&mut vecio)
    }
}

impl<'a, IO: AsyncRead + AsyncWrite, S: Session> Read for Stream<'a, IO, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.session.wants_read() {
            if let (0, 0) = self.complete_io()? {
                break
            }
        }
        self.session.read(buf)
    }
}

impl<'a, IO: AsyncRead + AsyncWrite, S: Session> Write for Stream<'a, IO, S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = self.session.write(buf)?;
        while self.session.wants_write() {
            match self.complete_io() {
                Ok(_) => (),
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock && len != 0 => break,
                Err(err) => return Err(err)
            }
        }

        if len != 0 || buf.is_empty() {
            Ok(len)
        } else {
            // not write zero
            self.session.write(buf)
                .and_then(|len| if len != 0 {
                    Ok(len)
                } else {
                    Err(io::ErrorKind::WouldBlock.into())
                })
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.session.flush()?;
        if self.session.wants_write() {
            self.complete_io()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test_stream;
