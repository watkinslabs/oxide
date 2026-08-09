//! Bottom-half gate for locks shared with the `BlockIo` completion softirq.
//!
//! `DiskState` (`registry/core.rs`) and `MappingState` (`bdev/mapping.rs`) are
//! both taken inside the completion softirq — `SubmissionToken::drop` retires
//! the in-flight count there, and `complete_page` clears a page's writeback
//! tag there. A process-context holder acquired bare can therefore be
//! interrupted by that softirq on its own CPU, which then spins forever on
//! the lock whose owner it interrupted — the one-CPU deadlock class B2007
//! fixed in virtio-gpu.
//!
//! Every acquisition of these locks goes through `lock_bh::<BlockBh>()`,
//! softirq context included: the disable/enable pair counts, the enable never
//! drains except at the outermost level outside IRQ context, so nesting from
//! inside the softirq is exactly Linux `spin_lock_bh` semantics.

/// Real softirq exclusion in the kernel; a no-op under hosted tests, which
/// have no softirqs to exclude.
#[cfg(target_os = "oxide-kernel")]
pub(crate) type BlockBh = sched::bh::SchedBh;
#[cfg(not(target_os = "oxide-kernel"))]
pub(crate) type BlockBh = sync::NoopBh;
