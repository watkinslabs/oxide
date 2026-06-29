// `/proc/sys` ctl_table model (Linux `fs/proc/proc_sysctl.c` + `kernel/
// sysctl.c`). D22: replaces the ~70 scattered imperative
// `reg::register("/proc/sys/...", SysctlInode/StaticFileInode::new(...))`
// calls with a single declarative table — a `procname` + a `proc_handler`
// (here the inode kind: a writable byte slot vs a read-only constant) + the
// default value. `register_sysctl_table` walks it and installs each leaf into
// procfs's own `PROC_REG` kernfs subtree (chroot-independent, like Linux
// `proc_sys_lookup`). Entries that bind to live kernel state or need a runtime
// value (ip_forward, hostname, the random boot_id/uuid, binfmt_misc dir, the
// per-iface conf.* knobs) are registered by `register_dynamic` rather than the
// const table.
//
// NOT done (D22 remainder): a nested `ctl_table` *hierarchy* with per-leaf
// `data`/`extra1..2` bound to kernel variables and real `proc_dointvec`
// min/max validation — every writable knob here is still a free byte slot.
// The structural flat-vs-declarative antipattern is what this closes.

#![cfg(target_os = "oxide-kernel")]

use vfs::InodeRef;
use crate::StaticFileInode;
use crate::sysctl::{IpForwardInode, SysctlInode};

/// proc_handler class. `W` = `proc_dointvec`-style writable byte slot
/// (`SysctlInode`); `C` = read-only constant (`StaticFileInode`, Linux rejects
/// writes to these too — `mode 0444`).
#[derive(Copy, Clone)]
enum K { W, C }

/// One `ctl_table` leaf: `procname`, handler class, default value. # C: n/a
type Ctl = (&'static str, K, &'static [u8]);

/// The `/proc/sys` ctl_table (fixed-value leaves). Order is preserved at
/// registration: where a `procname` appears twice (the historical re-tunes of
/// `fs/file-max`, `kernel/threads-max`, `net/ipv4/tcp_syncookies`, …) the LATER
/// row wins, exactly as the prior in-order `register` calls behaved. # C: n/a
const SYSCTL_TABLE: &[Ctl] = &[
    // ---- first registration block ----
    ("/proc/sys/kernel/pid_max",                    K::W, b"32768\n"),
    ("/proc/sys/kernel/ngroups_max",                K::C, b"65536\n"),
    ("/proc/sys/kernel/cap_last_cap",               K::C, b"40\n"),
    ("/proc/sys/kernel/osrelease",                  K::C, b"5.15.0-oxide\n"),
    ("/proc/sys/kernel/ostype",                     K::C, b"Linux\n"),
    ("/proc/sys/kernel/version",                    K::C, b"#1 SMP PREEMPT oxide v0.1.0\n"),
    ("/proc/sys/kernel/domainname",                 K::C, b"(none)\n"),
    ("/proc/sys/kernel/threads-max",                K::C, b"32768\n"),
    ("/proc/sys/fs/file-max",                       K::W, b"65536\n"),
    ("/proc/sys/fs/file-nr",                        K::C, b"0\t0\t65536\n"),
    ("/proc/sys/fs/nr_open",                        K::W, b"1048576\n"),
    ("/proc/sys/fs/inotify/max_user_watches",       K::C, b"65536\n"),
    ("/proc/sys/fs/inotify/max_user_instances",     K::C, b"128\n"),
    ("/proc/sys/fs/inotify/max_queued_events",      K::C, b"16384\n"),
    ("/proc/sys/fs/pipe-max-size",                  K::W, b"4096\n"),
    ("/proc/sys/vm/overcommit_memory",              K::W, b"0\n"),
    ("/proc/sys/vm/swappiness",                     K::W, b"60\n"),
    ("/proc/sys/net/core/somaxconn",                K::W, b"4096\n"),
    ("/proc/sys/kernel/printk",                     K::W, b"4\t4\t1\t7\n"),
    ("/proc/sys/net/ipv4/tcp_syncookies",           K::W, b"1\n"),
    ("/proc/sys/vm/dirty_ratio",                    K::W, b"20\n"),
    ("/proc/sys/vm/max_map_count",                  K::W, b"65530\n"),
    // ---- second registration block (F158 + more) ----
    ("/proc/sys/net/ipv4/tcp_syncookies",           K::C, b"1\n"),
    ("/proc/sys/net/ipv4/tcp_tw_reuse",             K::C, b"2\n"),
    ("/proc/sys/net/ipv4/tcp_fin_timeout",          K::C, b"60\n"),
    ("/proc/sys/net/ipv4/tcp_keepalive_time",       K::C, b"7200\n"),
    ("/proc/sys/net/ipv4/ip_local_port_range",      K::C, b"32768\t60999\n"),
    ("/proc/sys/net/ipv4/icmp_echo_ignore_all",     K::W, b"0\n"),
    ("/proc/sys/fs/protected_regular",              K::W, b"2\n"),
    ("/proc/sys/fs/protected_fifos",                K::W, b"1\n"),
    ("/proc/sys/net/ipv6/conf/all/disable_ipv6",    K::C, b"0\n"),
    ("/proc/sys/net/ipv6/conf/default/disable_ipv6", K::C, b"0\n"),
    ("/proc/sys/net/core/rmem_default",             K::C, b"212992\n"),
    ("/proc/sys/net/core/rmem_max",                 K::C, b"212992\n"),
    ("/proc/sys/net/core/wmem_default",             K::C, b"212992\n"),
    ("/proc/sys/net/core/wmem_max",                 K::C, b"212992\n"),
    ("/proc/sys/net/core/netdev_max_backlog",       K::C, b"1000\n"),
    ("/proc/sys/vm/min_free_kbytes",                K::W, b"4096\n"),
    ("/proc/sys/vm/overcommit_ratio",               K::W, b"50\n"),
    ("/proc/sys/vm/dirty_ratio",                    K::W, b"20\n"),
    ("/proc/sys/vm/dirty_background_ratio",         K::W, b"10\n"),
    ("/proc/sys/vm/page-cluster",                   K::W, b"3\n"),
    ("/proc/sys/vm/max_map_count",                  K::W, b"65530\n"),
    ("/proc/sys/vm/nr_hugepages",                   K::W, b"0\n"),
    ("/proc/sys/vm/mmap_min_addr",                  K::W, b"65536\n"),
    ("/proc/sys/kernel/sched_rr_timeslice_ms",      K::W, b"100\n"),
    ("/proc/sys/kernel/randomize_va_space",         K::W, b"2\n"),
    ("/proc/sys/kernel/yama/ptrace_scope",          K::W, b"1\n"),
    ("/proc/sys/kernel/perf_event_paranoid",        K::W, b"2\n"),
    ("/proc/sys/kernel/dmesg_restrict",             K::W, b"0\n"),
    ("/proc/sys/kernel/kptr_restrict",              K::W, b"0\n"),
    ("/proc/sys/kernel/threads-max",                K::W, b"32768\n"),
    ("/proc/sys/kernel/io_uring_disabled",          K::W, b"0\n"),
    ("/proc/sys/fs/file-max",                       K::W, b"4096\n"),
    ("/proc/sys/fs/nr_open",                        K::W, b"1048576\n"),
    ("/proc/sys/fs/protected_hardlinks",            K::C, b"1\n"),
    ("/proc/sys/fs/protected_symlinks",             K::C, b"1\n"),
    ("/proc/sys/fs/suid_dumpable",                  K::W, b"0\n"),
];

/// The Linux `net/ipv4/conf/<dev>/*` per-interface knob set. Each `<dev>`
/// (all/default/eth0) gets the same writable leaves. # C: n/a
const IPV4_CONF_LEAVES: &[&str] =
    &["rp_filter", "arp_ignore", "arp_announce", "accept_redirects", "send_redirects", "forwarding"];

/// Build the leaf inode for a ctl_table handler class. # C: O(len default)
fn make_leaf(kind: K, default: &'static [u8]) -> InodeRef {
    match kind {
        K::W => SysctlInode::new(default) as InodeRef,
        K::C => StaticFileInode::new(default) as InodeRef,
    }
}

/// Register every `/proc/sys` leaf. `boot_id`/`random_uuid` are the per-boot
/// random lines (passed in — they have no fixed default), the rest come from
/// the const table + the dynamic/live-bound handlers.
/// # SAFETY: caller is the boot path; single-CPU pre-init.
/// # C: O(N leaves)
pub fn register_sysctl_table(boot_id: &'static [u8], random_uuid: &'static [u8]) {
    // Dynamic / live-bound / runtime-valued leaves (not const-table material).
    crate::reg::register("/proc/sys/kernel/random/boot_id", StaticFileInode::new(boot_id) as InodeRef);
    crate::reg::register("/proc/sys/kernel/random/uuid", StaticFileInode::new(random_uuid) as InodeRef);
    crate::reg::register("/proc/sys/kernel/hostname", crate::make_proc_hostname());
    crate::reg::register("/proc/sys/net/ipv4/ip_forward", IpForwardInode::new() as InodeRef);
    crate::reg::register(
        "/proc/sys/fs/binfmt_misc",
        kernfs::PseudoDir::new_root(
            kernfs::dir_ino("/proc/sys/fs/binfmt_misc"), crate::reg::PROCFS_FSID, false).as_inode(),
    );
    // Const-valued ctl_table leaves (in order — later same-path row wins).
    for (path, kind, default) in SYSCTL_TABLE.iter().copied() {
        crate::reg::register(path, make_leaf(kind, default));
    }
    // net/ipv4/conf/<dev>/* writable per-iface knobs (all/default/eth0).
    for dev in ["all", "default", "eth0"] {
        for leaf in IPV4_CONF_LEAVES.iter().copied() {
            let path = alloc::format!("/proc/sys/net/ipv4/conf/{dev}/{leaf}");
            let default: &[u8] = match leaf {
                "accept_redirects" | "send_redirects" => b"1\n",
                _ => b"0\n",
            };
            crate::reg::register(&path, SysctlInode::new(default) as InodeRef);
        }
    }
}
