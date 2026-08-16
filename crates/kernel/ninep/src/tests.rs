// Hosted test suite. Nothing in this crate is target-gated, so every module
// here actually compiles and runs under `cargo test`.
//
// Module manifest:
//   * `server`     — the scripted in-memory server the client runs against.
//   * `codec`      — wire primitives and composite bodies, both directions.
//   * `tags`       — tag occupancy: the reply-matching contract.
//   * `fids`       — fid lifetime: clunk exactly once, never twice, never zero.
//   * `session`    — version negotiation rules.
//   * `sizing`     — transfer-size arithmetic and message-size enforcement.
//   * `errors`     — error replies in each dialect.
//   * `options`    — mount-option parsing and its derived defaults.
//   * `end_to_end` — attach, walk, open, read, write, readdir against `server`.

pub mod server;

mod codec;
mod tags;
mod fids;
mod session;
mod sizing;
mod errors;
mod options;
mod end_to_end;
