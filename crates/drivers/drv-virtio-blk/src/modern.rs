// Modern virtio-blk runtime engine (arch-neutral). The transport backend brings
// up cap discovery, BAR mapping, queue-0 program, and DRIVER_OK; once that
// finishes it hands persistent kernel-side addresses + device-cfg here via
// `init_blk`.

extern crate alloc;

use alloc::sync::Arc;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use sync::{Spinlock, TaskList as DriverLockClass};

#[cfg(target_os = "oxide-kernel")]
use sched::live::wait_list::WaitList;

use block::{BlockCompletion, BlockDevice, BlockError, BlockOp, BlockRequest, KResult};
use virtio::blk;

mod state;
pub use state::{
    transport_profile,
    wanted_features,
    BlkInit,
    BlkState,
    DRIVER_ID,
    VIRTIO_ID_BLOCK,
};
#[cfg(target_os = "oxide-kernel")]
pub use state::wake_completions;
use state::*;

mod engine;
mod request;
mod wait;

mod init;
pub use init::{disk_name, init_blk, remove_blk, shutdown_blk};
#[cfg(test)]
pub(crate) use init::{test_has_record, test_publish_record, test_read_device_config};
