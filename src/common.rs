use std::cmp::{ self, Ordering };
use std::io::{ self, Read, Write };
use rustls::{ Session, WriteV };
use tokio::prelude::Async;
use tokio::io::AsyncWrite;
use bytes::Buf;
use iovec::IoVec;


pub struct Stream<'a, S: 'a, IO: 'a> {
    session: &'a mut S,
    io: &'a mut IO
}

pub trait CompleteIo<'a, S: Session, IO: Read + Write>: Read + Write {
    fn write_tls(&mut self) -> io::Result<usize>;
    fn complete_io(&mut self) -> io::Result<(usize, usize)>;
}

impl<'a, S: Session, IO: Read + Write> Stream<'a, S, IO> {
    pub fn new(session: &'a mut S, io: &'a mut IO) -> Self {
        Stream { session, io }
    }
}

impl<'a, S: Session, IO: Read + Write> CompleteIo<'a, S, IO> for Stream<'a, S, IO> {
    default fn write_tls(&mut self) -> io::Result<usize> {
        self.session.write_tls(self.io)
    }

    fn complete_io(&mut self) -> io::Result<(usize, usize)> {
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

impl<'a, S: Session, IO: Read + Write> Read for Stream<'a, S, IO> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.session.wants_read() {
            if let (0, 0) = self.complete_io()? {
                break
            }
        }

        self.session.read(buf)
    }
}

impl<'a, S: Session, IO: Read + Write> io::Write for Stream<'a, S, IO> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = self.session.write(buf)?;
        self.complete_io()?;
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.session.flush()?;
        if self.session.wants_write() {
            self.complete_io()?;
        }
        Ok(())
    }
}

impl<'a, S: Session, IO: Read + AsyncWrite> CompleteIo<'a, S, IO> for Stream<'a, S, IO> {
    fn write_tls(&mut self) -> io::Result<usize> {
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

        let mut vecbuf = V(self.io);
        self.session.writev_tls(&mut vecbuf)
    }
}


// TODO test
struct VecBuf<'a, 'b: 'a> {
    pos: usize,
    cur: usize,
    inner: &'a [&'b [u8]]
}

impl<'a, 'b> VecBuf<'a, 'b> {
    fn new(vbytes: &'a [&'b [u8]]) -> Self {
        VecBuf { pos: 0, cur: 0, inner: vbytes }
    }
}

impl<'a, 'b> Buf for VecBuf<'a, 'b> {
    fn remaining(&self) -> usize {
        let sum = self.inner
            .iter()
            .skip(self.pos)
            .map(|bytes| bytes.len())
            .sum::<usize>();
        sum - self.cur
    }

    fn bytes(&self) -> &[u8] {
        &self.inner[self.pos][self.cur..]
    }

    fn advance(&mut self, cnt: usize) {
        let current = self.inner[self.pos].len();
        match (self.cur + cnt).cmp(&current) {
            Ordering::Equal => {
                if self.pos < self.inner.len() {
                    self.pos += 1;
                }
                self.cur = 0;
            },
            Ordering::Greater => {
                if self.pos < self.inner.len() {
                    self.pos += 1;
                }
                let remaining = self.cur + cnt - current;
                self.advance(remaining);
            },
            Ordering::Less => self.cur += cnt,
        }
    }

    fn bytes_vec<'c>(&'c self, dst: &mut [&'c IoVec]) -> usize {
        let len = cmp::min(self.inner.len() - self.pos, dst.len());

        for i in 0..len {
            dst[i] = self.inner[self.pos + i].into();
        }

        len
    }
}
