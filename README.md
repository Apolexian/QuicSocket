# QuicSocket

A wrapper around [Quinn](https://github.com/quinn-rs/quinn) that allows easy an establishment of a QUIC connection and transfer of data.

This was built for my undergraduate dissertation prototype and is probably not suitable for any actual use.

The code is heavily influenced by the example code in Quinn.

## Usage

QuicSocket provides functions for the generation of TLS certificates, establishment of connection and sending, and receiving data.

To use QuickSocket add it to your `Cargo.toml`.

Use `gen_certificates()` to generate TLS certificates then `new()` in either `QuicClient` or `QuicServer`. This method attempts to create a connection so requires the remote url and hostname in the case of a client.
You can then use `send` and `recv` for data transfer.
