// Hosted test suite. Nothing in this crate is target-gated except how a caller
// parks, so every module here compiles and runs under `cargo test`.
//
// Each child below is a sibling file in `src/tests/`, which is where a plain
// `mod` inside this file resolves to.
//
// Module manifest:
//   * `server`     — the scripted server the client runs against.
//   * `xdr`        — the representation: padding, bounds, big-endian order.
//   * `frag`       — record marking and multi-fragment reassembly.
//   * `auth`       — credential marshalling and reply-verifier checking.
//   * `msg`        — call and reply headers, every status branch.
//   * `timeout`    — the retransmission schedule's two deadlines.
//   * `pending`    — xid occupancy: the reply-matching contract.
//   * `end_to_end` — the whole engine against `server`.

pub mod server;

mod xdr;
mod frag;
mod auth;
mod msg;
mod timeout;
mod pending;
mod end_to_end;
