// Module manifest: `parse` owns SCM_RIGHTS parsing; `send` owns sendmsg transfers.

mod parse;
mod send;

pub use send::{sendmsg_unix_dgram_with_fds, sendmsg_unix_stream_with_fds, try_sendmsg_with_control, validate_non_unix_control};
