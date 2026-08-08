// `BPF_ENABLE_STATS` — the refcounted run-time statistics switch.
//
// Enabling hands back a descriptor and increments a count; closing that
// descriptor decrements it, and the last close turns collection back off.
// The count is the whole mechanism: nothing else may enable or disable
// collection, so a caller cannot turn off statistics another caller is
// still holding open.

extern crate alloc;
use alloc::sync::Arc;

use core::sync::atomic::{AtomicI32, Ordering};

use syscall::errno::Errno;
use vfs::{FileType, InodeBuilder, InodeRef, default_file_ops, default_inode_ops, mk_mode};

use super::super::attr::{self, Attr, Caps};
use super::super::uapi;
use super::super::{BPF_FD_MODE, ids, install_fd};

/// Number of descriptors currently holding run-time statistics enabled.
static ENABLED: AtomicI32 = AtomicI32::new(0);

/// Nesting ceiling. Half of `INT_MAX` leaves the count unable to overflow
/// however the remaining descriptors are ordered.
const MAX_NESTING: i32 = i32::MAX / 2;

/// Descriptors currently holding the switch on. Nothing accumulates
/// per-run statistics yet, so the count has no reader outside this
/// module — see the run-time-statistics row in `scratch/known_issues.md`.
fn held() -> i32 { ENABLED.load(Ordering::Acquire) }

/// One descriptor's hold on the switch. The count falls when the last
/// reference to the object behind the fd goes away.
struct BpfStatsInode;

impl Drop for BpfStatsInode {
    fn drop(&mut self) { ENABLED.fetch_sub(1, Ordering::AcqRel); }
}

/// Verdict for one nesting attempt, given the count already held.
/// # C: O(1)
fn nesting_verdict(held: i32) -> Result<(), Errno> {
    if held > MAX_NESTING { return Err(Errno::Ebusy); }
    Ok(())
}

fn inode() -> InodeRef {
    InodeBuilder::new(ids::INO_STATS, mk_mode(FileType::CharDev, BPF_FD_MODE),
        default_inode_ops(), default_file_ops())
        .private(Arc::new(BpfStatsInode))
        .build()
}

/// Turn run-time statistics on for as long as the returned descriptor is
/// open. # C: O(fd words)
fn enable_run_time() -> Result<i64, Errno> {
    nesting_verdict(held())?;
    let object = inode();
    ENABLED.fetch_add(1, Ordering::AcqRel);
    match install_fd(object, "bpf-stats") {
        Ok(fd) => Ok(fd),
        // The object never reached a descriptor; its Drop already
        // decremented, so nothing is left holding the switch on.
        Err(e) => Err(e),
    }
}

/// Which statistic a request names, if any this kernel collects.
/// # C: O(1)
fn stats_type_verdict(stats_type: u32) -> Result<(), Errno> {
    if stats_type == uapi::stats_type::RUN_TIME { return Ok(()); }
    Err(Errno::Einval)
}

/// `bpf_enable_stats()`. # C: O(fd words)
pub(in super::super) fn enable(a: &Attr, caps: Caps) -> Result<i64, Errno> {
    use uapi::off::enable_stats as o;
    attr::check_attr(a, o::LAST_END)?;
    if !caps.sys_admin { return Err(Errno::Eperm); }
    stats_type_verdict(a.u32_at(o::TYPE))?;
    enable_run_time()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admin() -> Caps { Caps { bpf: false, sys_admin: true, net_admin: false, perfmon: false } }

    fn attr_with(stats_type: u32) -> Attr {
        let mut a = Attr::zeroed();
        let off = uapi::off::enable_stats::TYPE;
        a.bytes[off..off + 4].copy_from_slice(&stats_type.to_ne_bytes());
        a
    }

    #[test]
    fn check_attr_boundary_is_offsetofend_enable_stats_type() {
        assert_eq!(uapi::off::enable_stats::LAST_END, 4);
        let mut a = attr_with(uapi::stats_type::RUN_TIME);
        a.bytes[uapi::off::enable_stats::LAST_END] = 1;
        assert_eq!(enable(&a, admin()), Err(Errno::Einval));
    }

    /// The zero-tail check precedes the capability check; a well-formed
    /// request from an unprivileged caller is EPERM, and that precedes
    /// the statistic-type check.
    #[test]
    fn capability_is_checked_after_the_tail_and_before_the_type() {
        assert_eq!(enable(&attr_with(uapi::stats_type::RUN_TIME), Caps::default()), Err(Errno::Eperm));
        assert_eq!(enable(&attr_with(9), Caps::default()), Err(Errno::Eperm));
        assert_eq!(enable(&attr_with(9), admin()), Err(Errno::Einval));
    }

    #[test]
    fn run_time_is_the_only_collectable_statistic() {
        assert_eq!(stats_type_verdict(uapi::stats_type::RUN_TIME), Ok(()));
        for other in [1u32, 2, u32::MAX] {
            assert_eq!(stats_type_verdict(other), Err(Errno::Einval));
        }
    }

    #[test]
    fn excessive_nesting_is_ebusy_rather_than_an_overflowing_count() {
        assert_eq!(nesting_verdict(0), Ok(()));
        assert_eq!(nesting_verdict(MAX_NESTING), Ok(()));
        assert_eq!(nesting_verdict(MAX_NESTING + 1), Err(Errno::Ebusy));
        assert_eq!(nesting_verdict(i32::MAX), Err(Errno::Ebusy));
    }

    /// The switch is the count, and the count is what a dropped hold
    /// releases: the last release turns collection off, an earlier one
    /// leaves it on.
    #[test]
    fn the_last_dropped_hold_turns_collection_off() {
        assert_eq!(held(), 0);
        let first = BpfStatsInode;
        ENABLED.fetch_add(1, Ordering::AcqRel);
        assert!(held() > 0);
        let second = BpfStatsInode;
        ENABLED.fetch_add(1, Ordering::AcqRel);
        drop(first);
        assert!(held() > 0);
        drop(second);
        assert_eq!(held(), 0);
    }
}
