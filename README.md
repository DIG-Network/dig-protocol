# dig-protocol

DIG Network L2 protocol types — a superset of [`chia-protocol`](https://crates.io/crates/chia-protocol).

This crate re-exports the full Chia protocol ecosystem (`chia-protocol`, `chia-sdk-client`,
`chia-ssl`, `chia-traits`, `chia_streamable_macro`) plus DIG-specific extensions (wire
opcodes **200–219**). Consumers depend on `dig-protocol` alone instead of importing
multiple `chia-*` crates directly.

## Install

```toml
[dependencies]
dig-protocol = { version = "0.1", features = ["rustls"] }
```

## Features

| Flag         | Forwards to                   | Enables                                            |
|--------------|-------------------------------|----------------------------------------------------|
| `native-tls` | `chia-sdk-client/native-tls`  | OS-native TLS — `Client`, `Connector`, connectors  |
| `rustls`     | `chia-sdk-client/rustls`      | Pure-Rust TLS — `Client`, `Connector`, connectors  |

Neither is enabled by default. Without one, protocol types still compile but TLS-dependent
re-exports (`Client`, `ClientState`, `Connector`) are unavailable.

## What you get

### Chia re-exports

- **`chia-protocol`** — all wire types (`Message`, `Handshake`, `ProtocolMessageTypes`, `NodeType`, …)
- **`chia-sdk-client`** — `Peer`, `PeerOptions`, `Network`, `RateLimiter`, `load_ssl_cert`
- **`chia-ssl`** — `ChiaCertificate`
- **`chia-traits`** — `Streamable`
- **`chia_streamable_macro`** — `#[streamable]` proc macro

### DIG extensions

| Item                        | Opcode | Purpose                                    |
|-----------------------------|--------|--------------------------------------------|
| `DigMessage`                | any    | Wire message with raw `u8` opcode (200+)   |
| `DigMessageType`            | 200–219| Typed DIG extension discriminants          |
| `RegisterPeer` / `RegisterAck` | 218/219 | Introducer self-registration (DSC-005) |
| `RequestPeersIntroducer` / `RespondPeersIntroducer` | 63/64 | Chia-standard introducer |

`chia_protocol::Message::from_bytes` rejects opcodes not in `ProtocolMessageTypes`.
`DigMessage` uses the same wire layout but keeps `msg_type` as `u8`, decoding any opcode.
Convert with `DigMessage::from_chia_message` / `DigMessage::try_into_chia_message`.

## Public API

```rust
use dig_protocol::{
    // re-exported from chia
    Bytes, Handshake, Message, NodeType, Peer, PeerOptions, ProtocolMessageTypes, Streamable,
    // DIG extensions
    DigMessage, DigMessageType, RegisterPeer, RegisterAck,
};

let rp = RegisterPeer::new("1.2.3.4".into(), 9444, NodeType::FullNode);
let wire = rp.to_dig_message(Some(1)).unwrap();
assert_eq!(wire.msg_type, DigMessageType::RegisterPeer as u8);
```

## License

Apache-2.0
