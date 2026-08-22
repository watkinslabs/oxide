// Modern virtio-blk runtime engine (arch-neutral). The transport backend brings
// up cap discovery, BAR mapping, queue-0 program, and DRIVER_OK; once that
// finishes it hands persistent kernel-side addresses + device-cfg here via
// `init_blk`.

extern crate alloc;

use alloc::sync::Arc;
use alloc::string::String;
use alloc::vec::Vec;
#[cfg(feature = "debug-hibernate")]
use core::sync::atomic::AtomicU16;
use core::sync::atomic::{AtomicU32, Ordering};

use sync::{Spinlock, TaskList as DriverLockClass};

#[cfg(target_os = "oxide-kernel")]
use sched::live::wait_list::WaitList;

use block::{BlockCompletion, BlockDevice, BlockError, BlockOp, BlockRequest, KResult};
use virtio::blk;

mod state;
pub use state::{
    arm_hibernate_sync_trace,
    completion_interrupt_count,
    transport_profile,
    wanted_features,
    BlkInit,
    BlkState,
    DRIVER_ID,
    VIRTIO_ID_BLOCK,
};
#[cfg(target_os = "oxide-kernel")]
pub use state::wake_completions;
#[cfg(test)]
pub(crate) use state::note_completion_interrupt_for_tests;
use state::*;

mod drain;
mod engine;
mod post;
mod queues;
mod request;
use request::InHeader;
mod pm_impl;
pub use pm_impl::{freeze_blk, prepare_restore_blk, unquiesce_blk, BlkFreeze};
mod zoned;
mod teardown;
mod wait;
pub use queues::BlkQueue;
#[cfg(test)]
pub use queues::suppress_queue_interrupts_for_tests;
use queues::*;
use engine::block_error_for_status;

mod init;
pub use init::{disk_name, init_blk, remove_blk, shutdown_blk};
#[cfg(test)]
pub(crate) use init::{test_has_record, test_publish_record, test_read_device_config};
