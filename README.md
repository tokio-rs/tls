# tokio-rustls
[![crates](https://img.shields.io/crates/v/tokio-rustls.svg)](https://crates.io/crates/tokio-rustls) [![license](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/quininer/tokio-rustls/blob/master/LICENSE-MIT) [![license](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/quininer/tokio-rustls/blob/master/LICENSE-APACHE) [![docs.rs](https://docs.rs/tokio-rustls/badge.svg)](https://docs.rs/tokio-rustls/)

Asynchronous TLS/SSL streams for [Tokio](https://tokio.rs/) using
[Rustls](https://github.com/ctz/rustls).

### Basic Structure of a Client

```rust
// ...

use rustls::ClientConfig;
use tokio_rustls::ClientConfigExt;

let mut config = ClientConfig::new();
config.root_store.add_trust_anchors(&webpki_roots::ROOTS);
let config = Arc::new(config);

TcpStream::connect(&addr, &handle)
	.and_then(|socket| config.connect_async("www.rust-lang.org", socket))

// ...
```

### Client Example Program

See [examples/client.rs](examples/client.rs). You can run it with:

```sh
cargo run --example client google.com
```

### Server Example Program

See [examples/server.rs](examples/server.rs). You can run it with:

```sh
cargo run --example server -- 127.0.0.1 --cert mycert.der --key mykey.der
```

### License & Origin

tokio-rustls is primarily distributed under the terms of both the [MIT license](LICENSE-MIT) and
the [Apache License (Version 2.0)](LICENSE-APACHE), with portions covered by various BSD-like
licenses.

This started as a fork of [tokio-tls](https://github.com/tokio-rs/tokio-tls).
