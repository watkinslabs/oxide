// Module manifest: `entry` owns syscall admission order (and asks the layout
// owner, `crate::msg_layout`, which message shape the call speaks); `dispatch`
// pins/routes sockets; protocol children own receive waits and copyout.

pub(crate) mod dispatch;
pub(crate) mod entry;
pub(crate) mod inet;
pub(crate) mod netlink;
pub(crate) mod rx_trace;
pub(crate) mod vsock;

pub(crate) use dispatch::{from_file, lookup, recv};
