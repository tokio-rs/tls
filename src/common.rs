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

/*
impl<'a, S: Session, IO: Write> Stream<'a, S, IO> {
    pub default fn write_tls(&mut self) -> io::Result<usize> {
        self.session.write_tls(self.io)
    }
}
*/

impl<'a, S: Session, IO: AsyncWrite> Stream<'a, S, IO> {
    pub fn write_tls(&mut self) -> io::Result<usize> {
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
