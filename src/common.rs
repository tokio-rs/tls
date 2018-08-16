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

pub trait WriteTls<'a, S: Session, IO: Read + Write>: Read + Write {
    fn write_tls(&mut self) -> io::Result<usize>;
}

impl<'a, S: Session, IO: Read + Write> Stream<'a, S, IO> {
    pub fn new(session: &'a mut S, io: &'a mut IO) -> Self {
        Stream { session, io }
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

impl<'a, S: Session, IO: Read + Write> WriteTls<'a, S, IO> for Stream<'a, S, IO> {
    default fn write_tls(&mut self) -> io::Result<usize> {
        self.session.write_tls(self.io)
    }
}

impl<'a, S: Session, IO: Read + AsyncWrite> WriteTls<'a, S, IO> for Stream<'a, S, IO> {
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
            Ordering::Equal => if self.pos + 1 < self.inner.len() {
                self.pos += 1;
                self.cur = 0;
            } else {
                self.cur += cnt;
            },
            Ordering::Greater => {
                if self.pos + 1 < self.inner.len() {
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

#[cfg(test)]
mod test_vecbuf {
    use super::*;

    #[test]
    fn test_fresh_cursor_vec() {
        let mut buf = VecBuf::new(&[b"he", b"llo"]);

        assert_eq!(buf.remaining(), 5);
        assert_eq!(buf.bytes(), b"he");

        buf.advance(2);

        assert_eq!(buf.remaining(), 3);
        assert_eq!(buf.bytes(), b"llo");

        buf.advance(3);

        assert_eq!(buf.remaining(), 0);
        assert_eq!(buf.bytes(), b"");
    }

    #[test]
    fn test_get_u8() {
        let mut buf = VecBuf::new(&[b"\x21z", b"omg"]);
        assert_eq!(0x21, buf.get_u8());
    }

    #[test]
    fn test_get_u16() {
        let mut buf = VecBuf::new(&[b"\x21\x54z", b"omg"]);
        assert_eq!(0x2154, buf.get_u16_be());
        let mut buf = VecBuf::new(&[b"\x21\x54z", b"omg"]);
        assert_eq!(0x5421, buf.get_u16_le());
    }

    #[test]
    #[should_panic]
    fn test_get_u16_buffer_underflow() {
        let mut buf = VecBuf::new(&[b"\x21"]);
        buf.get_u16_be();
    }

    #[test]
    fn test_bufs_vec() {
        let buf = VecBuf::new(&[b"he", b"llo"]);

        let b1: &[u8] = &mut [0];
        let b2: &[u8] = &mut [0];

        let mut dst: [&IoVec; 2] =
            [b1.into(), b2.into()];

        assert_eq!(2, buf.bytes_vec(&mut dst[..]));
    }
}
