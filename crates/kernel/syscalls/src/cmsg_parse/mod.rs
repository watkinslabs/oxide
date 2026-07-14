// Module manifest: `parse` owns SCM_RIGHTS parsing; `raw` owns INET send controls;
// `send` owns sendmsg transfers.

mod parse;
mod raw;
mod send;
#[cfg(test)]
mod raw_tests;

pub use raw::parse_raw_control;
pub use send::{sendmsg_unix_dgram_with_fds, sendmsg_unix_stream_with_fds, try_sendmsg_with_control, validate_non_unix_control};
