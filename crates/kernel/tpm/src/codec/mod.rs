// Module manifest — command/response wire coding.
//
//   error.rs — the one error type every coder returns
//   reader.rs — bounds-checked big-endian reads over a response body
//   cmd.rs   — command buffer builder (header, handles, auth area, params)
//   rsp.rs   — response header validation and body access
//   cmds.rs  — the specific commands this kernel builds and parses
//   objects.rs — object, sealing and non-volatile-index commands

mod error;
mod reader;
mod cmd;
mod rsp;
pub mod cmds;
pub mod objects;

pub use error::CodecError;
pub use reader::Reader;
pub use cmd::CmdBuf;
pub use rsp::Response;
