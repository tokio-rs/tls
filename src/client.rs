use super::*;
use rustls::Session;
use std::io::Write;

/// A wrapper around an underlying raw stream which implements the TLS or SSL
/// protocol.
#[derive(Debug)]
pub struct TlsStream<IO> {
    pub(crate) io: IO,
    pub(crate) session: ClientSession,
    pub(crate) state: TlsState,

    #[cfg(feature = "early-data")]
    pub(crate) early_data: (usize, Vec<u8>),
}

pub(crate) enum MidHandshake<IO> {
    Handshaking(TlsStream<IO>),
    #[cfg(feature = "early-data")]
    EarlyData(TlsStream<IO>),
    End,
}

impl<IO> TlsStream<IO> {
    #[inline]
    pub fn get_ref(&self) -> (&IO, &ClientSession) {
        (&self.io, &self.session)
    }

    #[inline]
    pub fn get_mut(&mut self) -> (&mut IO, &mut ClientSession) {
        (&mut self.io, &mut self.session)
    }

    #[inline]
    pub fn into_inner(self) -> (IO, ClientSession) {
        (self.io, self.session)
    }
}

impl<IO> Future for MidHandshake<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Output = io::Result<TlsStream<IO>>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        if let MidHandshake::Handshaking(stream) = &mut *self {
            let (io, session) = stream.get_mut();
            let mut stream = Stream::new(io, session);

            if stream.session.is_handshaking() {
                try_ready!(stream.complete_io(cx));
            }

            if stream.session.wants_write() {
                try_ready!(stream.complete_io(cx));
            }
        }

        match mem::replace(&mut *self, MidHandshake::End) {
            MidHandshake::Handshaking(stream) => Poll::Ready(Ok(stream)),
            #[cfg(feature = "early-data")]
            MidHandshake::EarlyData(stream) => Poll::Ready(Ok(stream)),
            MidHandshake::End => panic!(),
        }
    }
}

impl<IO> AsyncRead for TlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    unsafe fn initializer(&self) -> Initializer {
        // TODO
        Initializer::nop()
    }

    fn poll_read(self: Pin<&mut Self>, cx: &mut Context, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        match self.state {
            #[cfg(feature = "early-data")]
            TlsState::EarlyData => {
                let this = self.get_mut();

                let mut stream = Stream::new(&mut this.io, &mut this.session);
                let (pos, data) = &mut this.early_data;

                // complete handshake
                if stream.session.is_handshaking() {
                    try_ready!(stream.complete_io(cx));
                }

                // write early data (fallback)
                if !stream.session.is_early_data_accepted() {
                    while *pos < data.len() {
                        let len = try_ready!(stream.poll_write(cx, &data[*pos..]));
                        *pos += len;
                    }
                }

                // end
                this.state = TlsState::Stream;
                data.clear();

                Pin::new(this).poll_read(cx, buf)
            }
            TlsState::Stream | TlsState::WriteShutdown => {
                let this = self.get_mut();
                let mut stream = Stream::new(&mut this.io, &mut this.session);

                match stream.poll_read(cx, buf) {
                    Poll::Ready(Ok(0)) => {
                        this.state.shutdown_read();
                        Poll::Ready(Ok(0))
                    }
                    Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
                    Poll::Ready(Err(ref e)) if e.kind() == io::ErrorKind::ConnectionAborted => {
                        this.state.shutdown_read();
                        if this.state.writeable() {
                            stream.session.send_close_notify();
                            this.state.shutdown_write();
                        }
                        Poll::Ready(Ok(0))
                    }
                    Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                    Poll::Pending => Poll::Pending
                }
            }
            TlsState::ReadShutdown | TlsState::FullyShutdown => Poll::Ready(Ok(0)),
        }
    }
}

impl<IO> AsyncWrite for TlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut stream = Stream::new(&mut this.io, &mut this.session);

        match this.state {
            #[cfg(feature = "early-data")]
            TlsState::EarlyData => {
                let (pos, data) = &mut this.early_data;

                // write early data
                if let Some(mut early_data) = stream.session.early_data() {
                    let len = early_data.write(buf)?; // TODO check pending
                    data.extend_from_slice(&buf[..len]);
                    return Poll::Ready(Ok(len));
                }

                // complete handshake
                if stream.session.is_handshaking() {
                    try_ready!(stream.complete_io(cx));
                }

                // write early data (fallback)
                if !stream.session.is_early_data_accepted() {
                    while *pos < data.len() {
                        let len = try_ready!(stream.poll_write(cx, &data[*pos..]));
                        *pos += len;
                    }
                }

                // end
                this.state = TlsState::Stream;
                data.clear();
                stream.poll_write(cx, buf)
            }
            _ => stream.poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Stream::new(&mut this.io, &mut this.session).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        if self.state.writeable() {
            self.session.send_close_notify();
            self.state.shutdown_write();
        }

        let this = self.get_mut();
        let mut stream = Stream::new(&mut this.io, &mut this.session);
        try_ready!(stream.poll_flush(cx));
        Pin::new(&mut this.io).poll_close(cx)
    }
}
