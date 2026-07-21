//! # dig-peer-protocol
//!
//! DIG Network L2 protocol types — a superset of `chia-protocol`.
//!
//! This crate re-exports the entire Chia protocol ecosystem (`chia-protocol`,
//! `chia-sdk-client`, `chia-ssl`, `chia-traits`) plus DIG-specific extensions
//! (the `200..=219` consensus opcodes plus [`DIG_MESSAGE`] = 220, the directed
//! dig-message envelope opcode). Consumers depend on `dig-peer-protocol` alone instead
//! of importing multiple `chia-*` crates individually.
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

/// Wire opcode for a directed **dig-message** envelope (WU6, epic #796).
///
/// The `200..=219` band is the DIG L2 **consensus** band ([`DigMessageType`]); `220..=255`
/// is the **free** band for directed application protocols. Opcode **220** carries a
/// `dig-message` directed envelope as OPAQUE bytes in [`DigMessage::data`] — the transport
/// (dig-gossip) never seals, opens, or parses it; end-to-end sealing to the recipient's DID
/// key is `dig-message`'s job.
///
/// This is a cross-repo **canonical** constant — it MUST NOT drift. `dig-gossip` mirrors it
/// as `dig_gossip::DIG_MESSAGE` (and `ProtocolMessageTypes::DigMessage`) for its transport.
pub const DIG_MESSAGE: u8 = 220;

#[cfg(test)]
mod dig_message_opcode_tests {
    use super::{DigMessage, DigMessageType, DIG_MESSAGE};

    /// The opcode frames a real [`DigMessage`] and survives a wire round-trip with its
    /// `msg_type` intact — the canonical value (220) exercised through the actual encoder.
    #[test]
    fn dig_message_opcode_frames_and_round_trips() {
        let msg = DigMessage::new(DIG_MESSAGE, Some(9), vec![1, 2, 3].into());
        let back = DigMessage::from_bytes(&msg.to_bytes()).expect("round-trip");
        assert_eq!(back.msg_type, 220);
        assert_eq!(back.msg_type, DIG_MESSAGE);
        assert_eq!(back.data.as_ref(), &[1, 2, 3]);
    }

    /// 220 is in the free band: it is NOT a consensus `DigMessageType` discriminant, so a
    /// consensus-band decode of the opcode fails — the two bands can never collide.
    #[test]
    fn dig_message_opcode_is_not_a_consensus_type() {
        assert!(DigMessageType::try_from(DIG_MESSAGE).is_err());
    }
}
