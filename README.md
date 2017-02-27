# tokio-rustls
[![crates](https://img.shields.io/crates/v/tokio-rustls.svg)](https://crates.io/crates/tokio-rustls)
[![license](https://img.shields.io/github/license/quininer/tokio-rustls.svg)](https://github.com/quininer/tokio-rustls/blob/master/LICENSE)
[![docs.rs](https://docs.rs/tokio-rustls/badge.svg)](https://docs.rs/tokio-rustls/)

[tokio-tls](https://github.com/tokio-rs/tokio-tls) fork, use [rustls](https://github.com/ctz/rustls).

### exmaple

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
