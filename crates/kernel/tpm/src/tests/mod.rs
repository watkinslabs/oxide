// Hosted test manifest. Every module here compiles unconditionally under
// `cargo test -p tpm`: nothing in this crate is target-gated, so no test in
// this tree can silently compile out.
//
//   support.rs  — hex helpers and the simulated register files
//   alg_t.rs    — algorithm identity and digest widths
//   rc_t.rs     — response-code decode, both formats
//   pcr_t.rs    — extend arithmetic, known-answer vectors, bank agility
//   codec_t.rs  — command encoding and response framing
//   objects_t.rs — object, sealing and non-volatile command framing
//   tis_t.rs    — FIFO handshake, including access ORDER
//   crb_t.rs    — control-buffer handshake, including access ORDER
//   eventlog_t.rs — log walk bounds, round trips, malformed records
//   device_t.rs — the chip: what actually reaches the transport
//   chip_t.rs   — device-file transaction model
//   space_t.rs  — resource-manager handle mapping and close semantics

mod support;
mod alg_t;
mod rc_t;
mod pcr_t;
mod device_t;
mod codec_t;
mod objects_t;
mod tis_t;
mod crb_t;
mod eventlog_t;
mod chip_t;
mod space_t;
