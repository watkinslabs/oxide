//! Event payloads.
//!
//! Module manifest:
//! - `conn`: link lifecycle and the pairing prompts.
//! - `key`: the four key-delivery events, each carrying a store hint.
//! - `misc`: controller-wide notifications, advertising, monitors and mesh.
//!
//! `INDEX_ADDED`, `INDEX_REMOVED`, their unconfigured forms, and
//! `NEW_CONFIG_OPTIONS` have no payload beyond the header's index. The
//! extended index events carry `mgmt::index::encode_ext_index_event`, and
//! `DEVICE_FOUND` and `DISCOVERING` live with discovery in `mgmt::discovery`.

pub mod conn;
pub mod key;
pub mod misc;
