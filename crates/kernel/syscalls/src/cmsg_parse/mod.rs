// Module manifest: `parse` owns SCM_RIGHTS cmsg parsing constants;
// `send` owns sendmsg-with-fds paths; `recv` owns recvmsg cmsg writeback.

mod parse;
mod recv;
mod send;

pub use parse::parse_scm_rights;
pub use recv::{recvmsg_unix_msgpair, recvmsg_unix_stream};
pub use send::{sendmsg_unix_dgram_with_fds, sendmsg_unix_stream_with_fds, try_sendmsg_with_fds};
