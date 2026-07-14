// Module manifest: `dispatch` pins/routes sockets; `layout` owns native ABI shape;
// protocol children own receive waits and copyout.

pub(crate) mod dispatch;
pub(crate) mod inet;
pub(crate) mod layout;
pub(crate) mod netlink;
pub(crate) mod vsock;

pub(crate) use dispatch::{from_file, lookup, recv};
