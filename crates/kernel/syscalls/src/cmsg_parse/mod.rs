// Module manifest: `parse` owns SCM_RIGHTS parsing; `send` owns sendmsg transfers.

mod parse;
mod send;

pub use parse::parse_scm_rights;
pub use send::{sendmsg_unix_dgram_with_fds, sendmsg_unix_stream_with_fds, try_sendmsg_with_fds};
