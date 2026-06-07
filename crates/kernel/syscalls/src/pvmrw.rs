// process_vm_readv / process_vm_writev (slots 310/311). Per docs/53 §0
// each syscall lives in its own file; shared iovec/foreign-mm helpers
// live in pvmrw_common. This module re-exports the two handlers so the
// dispatch table's `crate::pvmrw::sys_process_vm_*` paths keep resolving.

#![cfg(target_os = "oxide-kernel")]

#[path = "pvmrw_common.rs"] mod pvmrw_common;
#[path = "310_process_vm_readv.rs"] mod s310_process_vm_readv;
#[path = "311_process_vm_writev.rs"] mod s311_process_vm_writev;

pub use s310_process_vm_readv::sys_process_vm_readv;
pub use s311_process_vm_writev::sys_process_vm_writev;
