// Shared machinery for process_vm_readv / process_vm_writev (slots
// 310/311). Module manifest:
//
//   pvmrw_common/decide.rs  iov import rules, errno order, transfer
//                           accounting — NOT kernel-gated, hosted-tested
//                           by tests/pvmrw_decide_hosted.rs
//   pvmrw_common/import.rs  fetching an iov array from the caller's AS
//   pvmrw_common/task.rs    pid → mm plus the ptrace access gate
//   pvmrw_common/xfer.rs    the copy engine both slots run

#![cfg(target_os = "oxide-kernel")]

#[path = "pvmrw_common/decide.rs"] pub mod decide;
#[path = "pvmrw_common/import.rs"] pub mod import;
#[path = "pvmrw_common/task.rs"]   pub mod task;
#[path = "pvmrw_common/xfer.rs"]   pub mod xfer;

pub(crate) use import::read_iovs;
