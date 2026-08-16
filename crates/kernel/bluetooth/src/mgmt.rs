//! The management interface: the command and event surface a Bluetooth daemon
//! speaks to drive the stack.
//!
//! Module manifest:
//! - `codec`: the bounds-checked little-endian reader and writer every record
//!   is decoded and encoded through.
//! - `hdr`: the six-byte frame header, and the command-complete and
//!   command-status reply shapes.
//! - `table`: the opcode-indexed contract table — parameter width and the four
//!   dispatch properties, as data.
//! - `validate`: command admission, whose ORDER is the contract.
//! - `advertised`: the command and event lists `READ_COMMANDS` reports.
//! - `status`: controller status and errno to management status.
//! - `settings`: the supported and current settings words.
//! - `index`: the three controller enumerations.
//! - `discovery`: scan admission, the discovering event, the device report.
//! - `eir`: the `[len][type][value]` walk, its bound, and the two appenders.
//! - `types`: records shared across commands and events.
//! - `cmd`, `rsp`, `event`: the request, response and event payloads.

pub mod codec;
pub mod hdr;
pub mod table;
pub mod validate;
pub mod advertised;
pub mod status;
pub mod settings;
pub mod index;
pub mod discovery;
pub mod eir;
pub mod types;
pub mod cmd;
pub mod rsp;
pub mod event;
