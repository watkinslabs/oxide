//! The dynamic counter must never mint a number a fixed `/proc` file already
//! owns, and every fixed identity must sit inside a declared range.

use vfs::pseudo_ino::{PROCFS_DYNAMIC, PROCFS_NET, PROCFS_PID, PROCFS_STATIC};

use super::{next_ino, pid_ino, PID_INO_TAG_PERSONALITY, PID_INO_TAG_PROJID_MAP};
use crate::ids;

/// Every fixed `/proc` identity, so the coverage check below cannot silently
/// miss one added later.
const FIXED_STATIC: &[u64] = &[
    ids::SELF_STATUS, ids::SELF_CMDLINE, ids::SELF_STAT, ids::SELF_MAPS, ids::SELF_FD_DIR,
    ids::SELF_COMM, ids::SELF_ENVIRON, ids::UPTIME, ids::MEMINFO, ids::SWAPS, ids::LOADAVG,
    ids::HOSTNAME, ids::CMDLINE, ids::STAT, ids::CPUINFO, ids::VMSTAT, ids::PARTITIONS,
    ids::DISKSTATS, ids::INTERRUPTS, ids::DEVICES, ids::FILESYSTEMS, ids::BUDDYINFO,
    ids::MOUNTS, ids::MOUNTINFO, ids::FDINFO_ROOT, ids::FDINFO_FILE, ids::PROC_LINK_STDIN,
    ids::PROC_LINK_STDOUT, ids::PROC_LINK_STDERR, ids::SMAPS, ids::SELF_IO, ids::SELF_LIMITS,
    ids::RANDOM_UUID, ids::SYS_RANDOM_UUID, ids::CPU_ROOT, ids::CPU_ATTR_ONLINE,
    ids::CPU_ATTR_OFFLINE, ids::CPU_ATTR_KERNEL_MAX, ids::CPU_ATTR_UEVENT, ids::CPU_DIR,
    ids::CPU_ONLINE, ids::CPU_UEVENT, ids::CPU_TOPOLOGY_DIR, ids::CPU_TOPOLOGY_ATTR,
    ids::PRESSURE_CPU, ids::PRESSURE_MEMORY, ids::PRESSURE_IO, ids::PROC_ROOT,
    ids::PROC_SELF_LINK, ids::PROC_THREAD_SELF_LINK,
];

/// The `/proc/net/*` identities, which take a range of their own.
const FIXED_NET: &[u64] = &[
    ids::NET_DEV, ids::NET_TCP, ids::NET_UDP, ids::MODULES, ids::NET_ROUTE, ids::NET_ARP,
    ids::NET_UNIX, ids::NET_IF_INET6, ids::NET_SNMP, ids::NET_TCP6, ids::NET_UDP6,
    ids::NET_RAW, ids::NET_RAW6, ids::NET_NETSTAT, ids::NS_GENERATED,
];

#[test]
fn fixed_identities_sit_inside_a_declared_region() {
    for ino in FIXED_STATIC { assert!(PROCFS_STATIC.contains(*ino), "{ino:#x} outside procfs-static"); }
    for ino in FIXED_NET { assert!(PROCFS_NET.contains(*ino), "{ino:#x} outside procfs-net"); }
}

/// The defect: the counter shared a range with the fixed identities, so after
/// enough allocations it handed out `/proc/mounts`' number.
#[test]
fn the_dynamic_counter_can_never_mint_a_fixed_identity() {
    for _ in 0..8192 {
        let ino = next_ino();
        assert!(PROCFS_DYNAMIC.contains(ino), "{ino:#x} left procfs-dynamic");
        assert!(!FIXED_STATIC.contains(&ino), "{ino:#x} is a fixed /proc identity");
        assert!(!FIXED_NET.contains(&ino), "{ino:#x} is a fixed /proc/net identity");
    }
}

/// Driving the allocator past the range's length wraps inside it rather than
/// running into the neighbour above.
#[test]
fn the_dynamic_counter_stays_inside_its_region_when_it_wraps() {
    assert!(PROCFS_DYNAMIC.contains(PROCFS_DYNAMIC.at(0)));
    assert!(PROCFS_DYNAMIC.contains(PROCFS_DYNAMIC.at(PROCFS_DYNAMIC.len() - 1)));
    assert_eq!(PROCFS_DYNAMIC.at(PROCFS_DYNAMIC.len()), PROCFS_DYNAMIC.start());
    assert!(PROCFS_DYNAMIC.contains(PROCFS_DYNAMIC.at(u64::MAX)));
}

/// Per-pid numbers carry the file kind in the high half; every kind in use
/// lands inside the per-pid range.
#[test]
fn per_pid_numbers_sit_inside_the_per_pid_region() {
    for tag in [0x01u64, 0x07, 0x08, 0x09, 0x0C, 0x16, 0x1B, 0x20, 0x24, 0x28, 0x2a, 0x2d] {
        for id in [0u32, 1, 4096, u32::MAX] {
            let ino = pid_ino(tag, id);
            assert!(PROCFS_PID.contains(ino), "tag {tag:#x} id {id} → {ino:#x} outside procfs-pid");
        }
    }
}

#[test]
fn projid_map_and_personality_have_distinct_per_pid_identities() {
    for id in [0u32, 1, 4096, u32::MAX] {
        assert_ne!(
            pid_ino(PID_INO_TAG_PROJID_MAP, id),
            pid_ino(PID_INO_TAG_PERSONALITY, id),
            "projid_map and personality collide for pid {id}",
        );
    }
}
