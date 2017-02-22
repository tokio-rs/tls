//! Wrappers for `tokio-proto`
//!
//! This module contains wrappers for protocols defined by the `tokio-proto`
//! crate. These wrappers will all attempt to negotiate a TLS connection first
//! and then delegate all further protocol information to the protocol
//! specified.
//!
//! This module requires the `tokio-proto` feature to be enabled.

#![cfg(feature = "tokio-proto")]

extern crate tokio_proto;

use std::io;
use std::sync::Arc;
use futures::{ Future, IntoFuture, Poll };
use rustls::{ ServerConfig, ClientConfig, ServerSession, ClientSession };
use self::tokio_proto::multiplex;
use self::tokio_proto::pipeline;
use self::tokio_proto::streaming;
use tokio_core::io::Io;

use { TlsStream, ServerConfigExt, ClientConfigExt, AcceptAsync, ConnectAsync };

/// TLS server protocol wrapper.
///
/// This structure is a wrapper for other implementations of `ServerProto` in
/// the `tokio-proto` crate. This structure will negotiate a TLS connection
/// first and then delegate all further operations to the `ServerProto`
/// implementation for the underlying type.
pub struct Server<T> {
    inner: Arc<T>,
    acceptor: Arc<ServerConfig>,
}

impl<T> Server<T> {
    /// Constructs a new TLS protocol which will delegate to the underlying
    /// `protocol` specified.
    ///
    /// The `acceptor` provided will be used to accept TLS connections. All new
    /// connections will go through the TLS acceptor first and then further I/O
    /// will go through the negotiated TLS stream through the `protocol`
    /// specified.
    pub fn new(protocol: T, acceptor: ServerConfig) -> Server<T> {
        Server {
            inner: Arc::new(protocol),
            acceptor: Arc::new(acceptor),
        }
    }
}

/// Future returned from `bind_transport` in the `ServerProto` implementation.
pub struct ServerPipelineBind<T, I>
    where T: pipeline::ServerProto<TlsStream<I, ServerSession>>,
          I: Io + 'static,
{
    state: PipelineState<T, I>,
}

enum PipelineState<T, I>
    where T: pipeline::ServerProto<TlsStream<I, ServerSession>>,
          I: Io + 'static,
{
    First(AcceptAsync<I>, Arc<T>),
    Next(<T::BindTransport as IntoFuture>::Future),
}

impl<T, I> pipeline::ServerProto<I> for Server<T>
    where T: pipeline::ServerProto<TlsStream<I, ServerSession>>,
          I: Io + 'static,
{
    type Request = T::Request;
    type Response = T::Response;
    type Transport = T::Transport;
    type BindTransport = ServerPipelineBind<T, I>;

    fn bind_transport(&self, io: I) -> Self::BindTransport {
        let proto = self.inner.clone();

        ServerPipelineBind {
            state: PipelineState::First(self.acceptor.accept_async(io), proto),
        }
    }
}

impl<T, I> Future for ServerPipelineBind<T, I>
    where T: pipeline::ServerProto<TlsStream<I, ServerSession>>,
          I: Io + 'static,
{
    type Item = T::Transport;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<T::Transport, io::Error> {
        loop {
            let next = match self.state {
                PipelineState::First(ref mut a, ref state) => {
                    let res = a.poll().map_err(|e| {
                        io::Error::new(io::ErrorKind::Other, e)
                    });
                    state.bind_transport(try_ready!(res))
                }
                PipelineState::Next(ref mut b) => return b.poll(),
            };
            self.state = PipelineState::Next(next.into_future());
        }
    }
}

/// Future returned from `bind_transport` in the `ServerProto` implementation.
pub struct ServerMultiplexBind<T, I>
    where T: multiplex::ServerProto<TlsStream<I, ServerSession>>,
          I: Io + 'static,
{
    state: MultiplexState<T, I>,
}

enum MultiplexState<T, I>
    where T: multiplex::ServerProto<TlsStream<I, ServerSession>>,
          I: Io + 'static,
{
    First(AcceptAsync<I>, Arc<T>),
    Next(<T::BindTransport as IntoFuture>::Future),
}

impl<T, I> multiplex::ServerProto<I> for Server<T>
    where T: multiplex::ServerProto<TlsStream<I, ServerSession>>,
          I: Io + 'static,
{
    type Request = T::Request;
    type Response = T::Response;
    type Transport = T::Transport;
    type BindTransport = ServerMultiplexBind<T, I>;

    fn bind_transport(&self, io: I) -> Self::BindTransport {
        let proto = self.inner.clone();

        ServerMultiplexBind {
            state: MultiplexState::First(self.acceptor.accept_async(io), proto),
        }
    }
}

impl<T, I> Future for ServerMultiplexBind<T, I>
    where T: multiplex::ServerProto<TlsStream<I, ServerSession>>,
          I: Io + 'static,
{
    type Item = T::Transport;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<T::Transport, io::Error> {
        loop {
            let next = match self.state {
                MultiplexState::First(ref mut a, ref state) => {
                    let res = a.poll().map_err(|e| {
                        io::Error::new(io::ErrorKind::Other, e)
                    });
                    state.bind_transport(try_ready!(res))
                }
                MultiplexState::Next(ref mut b) => return b.poll(),
            };
            self.state = MultiplexState::Next(next.into_future());
        }
    }
}

/// Future returned from `bind_transport` in the `ServerProto` implementation.
pub struct ServerStreamingPipelineBind<T, I>
    where T: streaming::pipeline::ServerProto<TlsStream<I, ServerSession>>,
          I: Io + 'static,
{
    state: StreamingPipelineState<T, I>,
}

enum StreamingPipelineState<T, I>
    where T: streaming::pipeline::ServerProto<TlsStream<I, ServerSession>>,
          I: Io + 'static,
{
    First(AcceptAsync<I>, Arc<T>),
    Next(<T::BindTransport as IntoFuture>::Future),
}

impl<T, I> streaming::pipeline::ServerProto<I> for Server<T>
    where T: streaming::pipeline::ServerProto<TlsStream<I, ServerSession>>,
          I: Io + 'static,
{
    type Request = T::Request;
    type RequestBody = T::RequestBody;
    type Response = T::Response;
    type ResponseBody = T::ResponseBody;
    type Error = T::Error;
    type Transport = T::Transport;
    type BindTransport = ServerStreamingPipelineBind<T, I>;

    fn bind_transport(&self, io: I) -> Self::BindTransport {
        let proto = self.inner.clone();

        ServerStreamingPipelineBind {
            state: StreamingPipelineState::First(self.acceptor.accept_async(io), proto),
        }
    }
}

impl<T, I> Future for ServerStreamingPipelineBind<T, I>
    where T: streaming::pipeline::ServerProto<TlsStream<I, ServerSession>>,
          I: Io + 'static,
{
    type Item = T::Transport;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<T::Transport, io::Error> {
        loop {
            let next = match self.state {
                StreamingPipelineState::First(ref mut a, ref state) => {
                    let res = a.poll().map_err(|e| {
                        io::Error::new(io::ErrorKind::Other, e)
                    });
                    state.bind_transport(try_ready!(res))
                }
                StreamingPipelineState::Next(ref mut b) => return b.poll(),
            };
            self.state = StreamingPipelineState::Next(next.into_future());
        }
    }
}

/// Future returned from `bind_transport` in the `ServerProto` implementation.
pub struct ServerStreamingMultiplexBind<T, I>
    where T: streaming::multiplex::ServerProto<TlsStream<I, ServerSession>>,
          I: Io + 'static,
{
    state: StreamingMultiplexState<T, I>,
}

enum StreamingMultiplexState<T, I>
    where T: streaming::multiplex::ServerProto<TlsStream<I, ServerSession>>,
          I: Io + 'static,
{
    First(AcceptAsync<I>, Arc<T>),
    Next(<T::BindTransport as IntoFuture>::Future),
}

impl<T, I> streaming::multiplex::ServerProto<I> for Server<T>
    where T: streaming::multiplex::ServerProto<TlsStream<I, ServerSession>>,
          I: Io + 'static,
{
    type Request = T::Request;
    type RequestBody = T::RequestBody;
    type Response = T::Response;
    type ResponseBody = T::ResponseBody;
    type Error = T::Error;
    type Transport = T::Transport;
    type BindTransport = ServerStreamingMultiplexBind<T, I>;

    fn bind_transport(&self, io: I) -> Self::BindTransport {
        let proto = self.inner.clone();

        ServerStreamingMultiplexBind {
            state: StreamingMultiplexState::First(self.acceptor.accept_async(io), proto),
        }
    }
}

impl<T, I> Future for ServerStreamingMultiplexBind<T, I>
    where T: streaming::multiplex::ServerProto<TlsStream<I, ServerSession>>,
          I: Io + 'static,
{
    type Item = T::Transport;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<T::Transport, io::Error> {
        loop {
            let next = match self.state {
                StreamingMultiplexState::First(ref mut a, ref state) => {
                    let res = a.poll().map_err(|e| {
                        io::Error::new(io::ErrorKind::Other, e)
                    });
                    state.bind_transport(try_ready!(res))
                }
                StreamingMultiplexState::Next(ref mut b) => return b.poll(),
            };
            self.state = StreamingMultiplexState::Next(next.into_future());
        }
    }
}

/// TLS client protocol wrapper.
///
/// This structure is a wrapper for other implementations of `ClientProto` in
/// the `tokio-proto` crate. This structure will negotiate a TLS connection
/// first and then delegate all further operations to the `ClientProto`
/// implementation for the underlying type.
pub struct Client<T> {
    inner: Arc<T>,
    connector: Arc<ClientConfig>,
    hostname: String,
}

impl<T> Client<T> {
    /// Constructs a new TLS protocol which will delegate to the underlying
    /// `protocol` specified.
    ///
    /// The `connector` provided will be used to configure the TLS connection. Further I/O
    /// will go through the negotiated TLS stream through the `protocol` specified.
    pub fn new(protocol: T,
               connector: ClientConfig,
               hostname: &str) -> Client<T> {
        Client {
            inner: Arc::new(protocol),
            connector: Arc::new(connector),
            hostname: hostname.to_string(),
        }
    }
}

/// Future returned from `bind_transport` in the `ClientProto` implementation.
pub struct ClientPipelineBind<T, I>
    where T: pipeline::ClientProto<TlsStream<I, ClientSession>>,
          I: Io + 'static,
{
    state: ClientPipelineState<T, I>,
}

enum ClientPipelineState<T, I>
    where T: pipeline::ClientProto<TlsStream<I, ClientSession>>,
          I: Io + 'static,
{
    First(ConnectAsync<I>, Arc<T>),
    Next(<T::BindTransport as IntoFuture>::Future),
}

impl<T, I> pipeline::ClientProto<I> for Client<T>
    where T: pipeline::ClientProto<TlsStream<I, ClientSession>>,
          I: Io + 'static,
{
    type Request = T::Request;
    type Response = T::Response;
    type Transport = T::Transport;
    type BindTransport = ClientPipelineBind<T, I>;

    fn bind_transport(&self, io: I) -> Self::BindTransport {
        let proto = self.inner.clone();
        let io = self.connector.connect_async(&self.hostname, io);

        ClientPipelineBind {
            state: ClientPipelineState::First(io, proto),
        }
    }
}

impl<T, I> Future for ClientPipelineBind<T, I>
    where T: pipeline::ClientProto<TlsStream<I, ClientSession>>,
          I: Io + 'static,
{
    type Item = T::Transport;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<T::Transport, io::Error> {
        loop {
            let next = match self.state {
                ClientPipelineState::First(ref mut a, ref state) => {
                    let res = a.poll().map_err(|e| {
                        io::Error::new(io::ErrorKind::Other, e)
                    });
                    state.bind_transport(try_ready!(res))
                }
                ClientPipelineState::Next(ref mut b) => return b.poll(),
            };
            self.state = ClientPipelineState::Next(next.into_future());
        }
    }
}

/// Future returned from `bind_transport` in the `ClientProto` implementation.
pub struct ClientMultiplexBind<T, I>
    where T: multiplex::ClientProto<TlsStream<I, ClientSession>>,
          I: Io + 'static,
{
    state: ClientMultiplexState<T, I>,
}

enum ClientMultiplexState<T, I>
    where T: multiplex::ClientProto<TlsStream<I, ClientSession>>,
          I: Io + 'static,
{
    First(ConnectAsync<I>, Arc<T>),
    Next(<T::BindTransport as IntoFuture>::Future),
}

impl<T, I> multiplex::ClientProto<I> for Client<T>
    where T: multiplex::ClientProto<TlsStream<I, ClientSession>>,
          I: Io + 'static,
{
    type Request = T::Request;
    type Response = T::Response;
    type Transport = T::Transport;
    type BindTransport = ClientMultiplexBind<T, I>;

    fn bind_transport(&self, io: I) -> Self::BindTransport {
        let proto = self.inner.clone();
        let io = self.connector.connect_async(&self.hostname, io);

        ClientMultiplexBind {
            state: ClientMultiplexState::First(io, proto),
        }
    }
}

impl<T, I> Future for ClientMultiplexBind<T, I>
    where T: multiplex::ClientProto<TlsStream<I, ClientSession>>,
          I: Io + 'static,
{
    type Item = T::Transport;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<T::Transport, io::Error> {
        loop {
            let next = match self.state {
                ClientMultiplexState::First(ref mut a, ref state) => {
                    let res = a.poll().map_err(|e| {
                        io::Error::new(io::ErrorKind::Other, e)
                    });
                    state.bind_transport(try_ready!(res))
                }
                ClientMultiplexState::Next(ref mut b) => return b.poll(),
            };
            self.state = ClientMultiplexState::Next(next.into_future());
        }
    }
}

/// Future returned from `bind_transport` in the `ClientProto` implementation.
pub struct ClientStreamingPipelineBind<T, I>
    where T: streaming::pipeline::ClientProto<TlsStream<I, ClientSession>>,
          I: Io + 'static,
{
    state: ClientStreamingPipelineState<T, I>,
}

enum ClientStreamingPipelineState<T, I>
    where T: streaming::pipeline::ClientProto<TlsStream<I, ClientSession>>,
          I: Io + 'static,
{
    First(ConnectAsync<I>, Arc<T>),
    Next(<T::BindTransport as IntoFuture>::Future),
}

impl<T, I> streaming::pipeline::ClientProto<I> for Client<T>
    where T: streaming::pipeline::ClientProto<TlsStream<I, ClientSession>>,
          I: Io + 'static,
{
    type Request = T::Request;
    type RequestBody = T::RequestBody;
    type Response = T::Response;
    type ResponseBody = T::ResponseBody;
    type Error = T::Error;
    type Transport = T::Transport;
    type BindTransport = ClientStreamingPipelineBind<T, I>;

    fn bind_transport(&self, io: I) -> Self::BindTransport {
        let proto = self.inner.clone();
        let io = self.connector.connect_async(&self.hostname, io);

        ClientStreamingPipelineBind {
            state: ClientStreamingPipelineState::First(io, proto),
        }
    }
}

impl<T, I> Future for ClientStreamingPipelineBind<T, I>
    where T: streaming::pipeline::ClientProto<TlsStream<I, ClientSession>>,
          I: Io + 'static,
{
    type Item = T::Transport;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<T::Transport, io::Error> {
        loop {
            let next = match self.state {
                ClientStreamingPipelineState::First(ref mut a, ref state) => {
                    let res = a.poll().map_err(|e| {
                        io::Error::new(io::ErrorKind::Other, e)
                    });
                    state.bind_transport(try_ready!(res))
                }
                ClientStreamingPipelineState::Next(ref mut b) => return b.poll(),
            };
            self.state = ClientStreamingPipelineState::Next(next.into_future());
        }
    }
}

/// Future returned from `bind_transport` in the `ClientProto` implementation.
pub struct ClientStreamingMultiplexBind<T, I>
    where T: streaming::multiplex::ClientProto<TlsStream<I, ClientSession>>,
          I: Io + 'static,
{
    state: ClientStreamingMultiplexState<T, I>,
}

enum ClientStreamingMultiplexState<T, I>
    where T: streaming::multiplex::ClientProto<TlsStream<I, ClientSession>>,
          I: Io + 'static,
{
    First(ConnectAsync<I>, Arc<T>),
    Next(<T::BindTransport as IntoFuture>::Future),
}

impl<T, I> streaming::multiplex::ClientProto<I> for Client<T>
    where T: streaming::multiplex::ClientProto<TlsStream<I, ClientSession>>,
          I: Io + 'static,
{
    type Request = T::Request;
    type RequestBody = T::RequestBody;
    type Response = T::Response;
    type ResponseBody = T::ResponseBody;
    type Error = T::Error;
    type Transport = T::Transport;
    type BindTransport = ClientStreamingMultiplexBind<T, I>;

    fn bind_transport(&self, io: I) -> Self::BindTransport {
        let proto = self.inner.clone();
        let io = self.connector.connect_async(&self.hostname, io);

        ClientStreamingMultiplexBind {
            state: ClientStreamingMultiplexState::First(io, proto),
        }
    }
}

impl<T, I> Future for ClientStreamingMultiplexBind<T, I>
    where T: streaming::multiplex::ClientProto<TlsStream<I, ClientSession>>,
          I: Io + 'static,
{
    type Item = T::Transport;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<T::Transport, io::Error> {
        loop {
            let next = match self.state {
                ClientStreamingMultiplexState::First(ref mut a, ref state) => {
                    let res = a.poll().map_err(|e| {
                        io::Error::new(io::ErrorKind::Other, e)
                    });
                    state.bind_transport(try_ready!(res))
                }
                ClientStreamingMultiplexState::Next(ref mut b) => return b.poll(),
            };
            self.state = ClientStreamingMultiplexState::Next(next.into_future());
        }
    }
}
