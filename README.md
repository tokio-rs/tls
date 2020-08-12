# Tokio Tls

## Overview

This crate contains a collection of Tokio based TLS libraries.

- [`tokio-native-tls`](tokio-native-tls)
- [`tokio-rustls`](tokio-rustls)

## Getting Help

First, see if the answer to your question can be found in the [Tutorials] or the
[API documentation]. If the answer is not there, there is an active community in
the [Tokio Discord server][chat]. We would be happy to try to answer your
question. Last, if that doesn't work, try opening an [issue] with the question.

[Tutorials]: https://tokio.rs/tokio/tutorial
[API documentation]: https://docs.rs/tokio/latest/tokio
[chat]: https://discord.gg/tokio
[issue]: https://github.com/tokio-rs/tls/issues/new

## Contributing

:balloon: Thanks for your help improving the project! We are so happy to have
you! We have a [contributing guide][guide] to help you get involved in the Tokio
project.

[guide]: CONTRIBUTING.md

## Related Projects

In addition to the crates in this repository, the Tokio project also maintains
several other libraries, including:

* [`tokio`]: A runtime for writing reliable, asynchronous, and slim applications with the Rust programming language.

* [`tracing`] (formerly `tokio-trace`): A framework for application-level
  tracing and async-aware diagnostics.

* [`mio`]: A low-level, cross-platform abstraction over OS I/O APIs that powers
  `tokio`.

* [`bytes`]: Utilities for working with bytes, including efficient byte buffers.

[`tokio`]: https://github.com/tokio-rs/tokio
[`tracing`]: https://github.com/tokio-rs/tracing
[`mio`]: https://github.com/tokio-rs/mio
[`bytes`]: https://github.com/tokio-rs/bytes

## Supported Rust Versions

Tokio is built against the latest stable, nightly, and beta Rust releases. The
minimum version supported is the stable release from three months before the
current stable release version. For example, if the latest stable Rust is 1.29,
the minimum version supported is 1.26. The current Tokio version is not
guaranteed to build on Rust versions earlier than the minimum supported version.

## License

This project is licensed under the [MIT license](LICENSE).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in Tokio by you, shall be licensed as MIT, without any additional
terms or conditions.
