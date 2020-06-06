//! Asynchronous TLS/SSL streams for Tokio using [Rustls](https://github.com/ctz/rustls).

#[cfg(feature = "client")]
pub mod client;
#[cfg(any(feature = "client", feature = "server"))]
mod common;
#[cfg(feature = "server")]
pub mod server;
#[cfg(all(feature = "client", feature = "server"))]
mod stream;

#[cfg(feature = "client")]
pub use client::{Connect, FailableConnect, TlsConnector};
#[cfg(feature = "server")]
pub use server::{Accept, FailableAccept, TlsAcceptor};
#[cfg(all(feature = "client", feature = "server"))]
pub use stream::TlsStream;

pub use rustls;
#[cfg(feature = "client")]
pub use webpki;
