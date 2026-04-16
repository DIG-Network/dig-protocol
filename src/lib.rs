//! # dig-protocol
//!
//! DIG Network L2 protocol types — a superset of `chia-protocol`.
//!
//! This crate re-exports the entire Chia protocol ecosystem (`chia-protocol`,
//! `chia-sdk-client`, `chia-ssl`, `chia-traits`) plus DIG-specific extensions
//! (opcodes 200–219). Consumers depend on `dig-protocol` alone instead of
//! importing multiple `chia-*` crates individually.
//!
//! ## What's included
//!
//! | Source crate | What's re-exported |
//! |-------------|-------------------|
//! | `chia-protocol` | All wire types: `Message`, `Handshake`, `ProtocolMessageTypes`, `NodeType`, etc. |
//! | `chia-sdk-client` | `Peer`, `Client`, `ClientError`, `ClientState`, `Network`, `PeerOptions`, rate limiting, TLS connectors |
//! | `chia-ssl` | `ChiaCertificate` |
//! | `chia-traits` | `Streamable` trait |
//! | `chia_streamable_macro` | `#[streamable]` proc macro |
//! | **DIG extensions** | `DigMessage`, `DigMessageType`, `RegisterPeer`, `RegisterAck`, introducer wire types |
//!
//! ## Feature flags
//!
//! | Flag | Forwards to | Effect |
//! |------|-------------|--------|
//! | `native-tls` | `chia-sdk-client/native-tls` | OS-native TLS; enables `Client`, `ClientState`, `Connector`, `create_native_tls_connector` |
//! | `rustls` | `chia-sdk-client/rustls` | Pure-Rust TLS; enables `Client`, `ClientState`, `Connector`, `create_rustls_connector` |
//!
//! Neither feature is enabled by default. The crate builds without either but TLS-dependent
//! re-exports (`Client`, `ClientState`, `Connector`) become unavailable.

// ============================================================================
// Re-export: chia-protocol (all wire types)
// ============================================================================
pub use chia_protocol::*;

// ============================================================================
// Re-export: chia-sdk-client (peer IO, TLS, rate limiting)
// ============================================================================
// Backend-agnostic types — always available.
pub use chia_sdk_client::{
    load_ssl_cert, ClientError, Network, Peer, PeerOptions, RateLimit, RateLimiter, RateLimits,
    V2_RATE_LIMITS,
};

// `Client`, `ClientState`, and `Connector` require a TLS backend in `chia-sdk-client`.
// Enable either the `native-tls` or `rustls` feature to use them.
#[cfg(any(feature = "native-tls", feature = "rustls"))]
pub use chia_sdk_client::{Client, ClientState, Connector};

#[cfg(feature = "native-tls")]
pub use chia_sdk_client::create_native_tls_connector;

#[cfg(feature = "rustls")]
pub use chia_sdk_client::create_rustls_connector;

// ============================================================================
// Re-export: chia-ssl (certificate types)
// ============================================================================
pub use chia_ssl::ChiaCertificate;

// ============================================================================
// Re-export: chia-traits (serialization)
// ============================================================================
pub use chia_traits::Streamable;

// ============================================================================
// Re-export: chia_streamable_macro (proc macro for wire structs)
// ============================================================================
pub use chia_streamable_macro::streamable;

// ============================================================================
// DIG extensions
// ============================================================================
mod dig_message;
mod dig_message_type;
mod introducer_wire;

pub use dig_message::DigMessage;
pub use dig_message_type::{DigMessageType, UnknownDigMessageType};
pub use introducer_wire::{
    RegisterAck, RegisterPeer, RequestPeersIntroducer, RespondPeersIntroducer,
};
