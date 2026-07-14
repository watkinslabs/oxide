// Module manifest: `dispatch` routes imported destinations; protocol children own copyout.

pub(crate) mod dispatch;
pub(crate) mod inet;
pub(crate) mod netlink;
pub(crate) mod vsock;

pub(crate) use dispatch::recv;
