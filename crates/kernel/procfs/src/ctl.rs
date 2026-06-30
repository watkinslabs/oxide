// `/proc/sys` ctl_table model (Linux `fs/proc/proc_sysctl.c` + `kernel/
// sysctl.c`). D22: a declarative, NESTED `ctl_table` tree whose every leaf
// binds — via a `proc_handler` (`proc_handler.rs`) — to a LIVE kernel variable.
// `register_sysctl_table` walks the tree, building each leaf's `/proc/sys/...`
// path and installing the bound inode into procfs's own `PROC_REG` kernfs
// subtree (chroot-independent, like Linux `proc_sys_lookup`).
//
// D22 binding (this revision):
//   * Integer leaves are `proc_dointvec` / `proc_dointvec_minmax` over a LIVE
//     `AtomicI64` cell (`Box::leak`ed at register time, seeded with the
//     default) — a read FORMATS the cell, a write PARSES + range-checks against
//     `extra1`/`extra2` (`Leaf::Int(default,(min,max))`) + UPDATES the cell.
//   * `fs.file-max` is `proc_doulongvec_minmax` over a LIVE `AtomicU64`.
//   * `kernel.hostname` is `proc_dostring` bound to the UTS hostname slot
//     (`hooks::hostname`/`set_hostname`) — the backing variable EXISTS in-tree.
//   * `net.ipv4.ip_forward` is `proc_dobool` bound to `net::forwarding` — also
//     a real in-tree backing variable.
//   * Genuine read-only constants (ostype/osrelease/version, cap_last_cap, …)
//     stay `StaticFileInode` (mode 0444 — Linux rejects writes to those too).
//   * Multi-field free slots (printk = 4 ints, file-nr = 3 fields) stay a
//     `proc_dointvec` free byte slot (`SysctlInode`, procfs-owned cell).
//
// Backing-variable policy: a leaf whose backing kernel variable EXISTS in-tree
// binds to it (hostname, ip_forward); a leaf whose backing does NOT exist gets
// a procfs-OWNED live cell (the `Box::leak`ed atomic) — a real read/write
// variable, NOT a fake constant (Linux-faithful: `data` always points at a
// live `int`/`long`/`bool`). Cross-lane subsystems (mm VM tunables, vfs fs
// limits, net buffer sizes) can later repoint these leaves at THEIR variable
// by swapping the handler, without changing the tree or the path set.

#![cfg(target_os = "oxide-kernel")]

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU64};
use vfs::InodeRef;
use crate::StaticFileInode;
use crate::sysctl::{bound_sysctl_inode, SysctlInode};
use crate::proc_handler::{
    BoolHook as HBoolHook, BoolVar, IntVar, StrHook as HStrHook, ULongVar,
};

/// `proc_dointvec_minmax` window upper bound for a 32-bit-int knob.
const INT_MAX: i64 = i32::MAX as i64;

/// One `ctl_table` leaf's `proc_handler` class + default value. # C: n/a
enum Leaf {
    /// `proc_dointvec` (bounds `None`) / `proc_dointvec_minmax` (bounds
    /// `Some((min,max))`) over a live `AtomicI64`.
    Int(i64, Option<(i64, i64)>),
    /// `proc_doulongvec_minmax` over a live `AtomicU64`.
    ULong(u64, Option<(u64, u64)>),
    /// `proc_dobool` over a live `AtomicBool`.
    Bool(bool),
    /// `proc_dobool` bound to a subsystem accessor pair.
    BoolHook(fn() -> bool, fn(bool)),
    /// `proc_dostring` bound to a subsystem accessor pair.
    StrHook(fn() -> alloc::vec::Vec<u8>, fn(&[u8])),
    /// `proc_dointvec` free byte slot (multi-field / not a single int).
    Bytes(&'static [u8]),
    /// Read-only constant (`StaticFileInode`, mode 0444).
    Const(&'static [u8]),
}

/// A `ctl_table` node: a subdirectory or a leaf file. # C: n/a
enum Node {
    Dir(&'static str, &'static [Node]),
    File(&'static str, Leaf),
}

use Leaf::*;
use Node::{Dir, File};

/// The nested `/proc/sys` ctl_table tree. Mirrors the Linux directory layout
/// (`kernel/`, `fs/`, `vm/`, `net/core`, `net/ipv4`, …) with the live binding
/// declared at every leaf. # C: n/a
const SYSCTL_TREE: &[Node] = &[
    Dir("kernel", &[
        File("pid_max",               Int(32768, Some((1, 4_194_304)))),
        File("ngroups_max",           Const(b"65536\n")),
        File("cap_last_cap",          Const(b"40\n")),
        File("osrelease",             Const(b"5.15.0-oxide\n")),
        File("ostype",                Const(b"Linux\n")),
        File("version",               Const(b"#1 SMP PREEMPT oxide v0.1.0\n")),
        File("domainname",            Const(b"(none)\n")),
        File("threads-max",           Int(32768, Some((20, INT_MAX)))),
        File("printk",                Bytes(b"4\t4\t1\t7\n")),
        File("sched_rr_timeslice_ms", Int(100, Some((1, INT_MAX)))),
        File("randomize_va_space",    Int(2, Some((0, 2)))),
        File("perf_event_paranoid",   Int(2, Some((-1, 4)))),
        File("dmesg_restrict",        Int(0, Some((0, 1)))),
        File("kptr_restrict",         Int(0, Some((0, 2)))),
        File("io_uring_disabled",     Int(0, Some((0, 2)))),
        File("hostname",              StrHook(crate::hooks::hostname, crate::hooks::set_hostname)),
        Dir("yama", &[
            File("ptrace_scope",      Int(1, Some((0, 3)))),
        ]),
    ]),
    Dir("fs", &[
        File("file-max",              ULong(4096, None)),
        File("file-nr",              Const(b"0\t0\t65536\n")),
        File("nr_open",               Int(1_048_576, Some((0, INT_MAX)))),
        File("pipe-max-size",         Int(4096, Some((0, INT_MAX)))),
        File("protected_regular",     Int(2, Some((0, 2)))),
        File("protected_fifos",       Int(1, Some((0, 2)))),
        File("protected_hardlinks",   Const(b"1\n")),
        File("protected_symlinks",    Const(b"1\n")),
        File("suid_dumpable",         Int(0, Some((0, 2)))),
        Dir("inotify", &[
            File("max_user_watches",  Const(b"65536\n")),
            File("max_user_instances", Const(b"128\n")),
            File("max_queued_events", Const(b"16384\n")),
        ]),
    ]),
    Dir("vm", &[
        File("overcommit_memory",       Int(0, Some((0, 2)))),
        File("overcommit_ratio",        Int(50, Some((0, 100)))),
        File("swappiness",              Int(60, Some((0, 200)))),
        File("dirty_ratio",             Int(20, Some((0, 100)))),
        File("dirty_background_ratio",  Int(10, Some((0, 100)))),
        File("max_map_count",           Int(65530, Some((0, INT_MAX)))),
        File("min_free_kbytes",         Int(4096, Some((0, INT_MAX)))),
        File("page-cluster",            Int(3, Some((0, INT_MAX)))),
        File("nr_hugepages",            Int(0, Some((0, INT_MAX)))),
        File("mmap_min_addr",           Int(65536, Some((0, INT_MAX)))),
    ]),
    Dir("net", &[
        Dir("core", &[
            File("somaxconn",          Int(4096, Some((0, INT_MAX)))),
            File("rmem_default",       Const(b"212992\n")),
            File("rmem_max",           Const(b"212992\n")),
            File("wmem_default",       Const(b"212992\n")),
            File("wmem_max",           Const(b"212992\n")),
            File("netdev_max_backlog", Const(b"1000\n")),
        ]),
        Dir("ipv4", &[
            File("ip_forward",         BoolHook(net::forwarding::ipv4_enabled, net::forwarding::set_ipv4_enabled)),
            File("tcp_syncookies",     Int(1, Some((0, 2)))),
            File("tcp_tw_reuse",       Int(2, Some((0, 2)))),
            File("tcp_fin_timeout",    Int(60, Some((0, INT_MAX)))),
            File("tcp_keepalive_time", Int(7200, Some((0, INT_MAX)))),
            File("ip_local_port_range", Const(b"32768\t60999\n")),
            File("icmp_echo_ignore_all", Int(0, Some((0, 1)))),
        ]),
        Dir("ipv6", &[
            Dir("conf", &[
                Dir("all",     &[ File("disable_ipv6", Int(0, Some((0, 1)))) ]),
                Dir("default", &[ File("disable_ipv6", Int(0, Some((0, 1)))) ]),
            ]),
        ]),
    ]),
];

/// The Linux `net/ipv4/conf/<dev>/*` per-interface knob set. Each `<dev>`
/// (all/default/eth0) gets the same writable leaves. # C: n/a
const IPV4_CONF_LEAVES: &[&str] =
    &["rp_filter", "arp_ignore", "arp_announce", "accept_redirects", "send_redirects", "forwarding"];

/// Build the leaf inode for a ctl_table handler class. Integer / long / bool
/// leaves get a freshly `Box::leak`ed live cell seeded with the default; the
/// hook leaves bind to a subsystem accessor pair; consts are read-only.
/// # SAFETY: register-time leak is boot-path, single-CPU pre-init.
/// # C: O(len default)
fn make_leaf(leaf: &Leaf) -> InodeRef {
    match *leaf {
        Int(def, bounds) => {
            let cell: &'static AtomicI64 = Box::leak(Box::new(AtomicI64::new(def)));
            bound_sysctl_inode(Arc::new(IntVar { cell, bounds }))
        }
        ULong(def, bounds) => {
            let cell: &'static AtomicU64 = Box::leak(Box::new(AtomicU64::new(def)));
            bound_sysctl_inode(Arc::new(ULongVar { cell, bounds }))
        }
        Bool(def) => {
            let cell: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(def)));
            bound_sysctl_inode(Arc::new(BoolVar { cell }))
        }
        Leaf::BoolHook(get, set) => bound_sysctl_inode(Arc::new(HBoolHook { get, set })),
        Leaf::StrHook(get, set) => bound_sysctl_inode(Arc::new(HStrHook { get, set })),
        Bytes(default) => SysctlInode::new(default),
        Const(default) => StaticFileInode::new(default),
    }
}

/// Walk one ctl_table subtree, building each leaf's `/proc/sys/...` path and
/// registering its bound inode. # C: O(N nodes)
fn register_tree(prefix: &str, nodes: &[Node]) {
    for n in nodes {
        match n {
            Dir(name, kids) => {
                let p = alloc::format!("{prefix}/{name}");
                register_tree(&p, kids);
            }
            File(name, leaf) => {
                let p = alloc::format!("{prefix}/{name}");
                crate::reg::register(&p, make_leaf(leaf));
            }
        }
    }
}

/// Register every `/proc/sys` leaf. `boot_id`/`random_uuid` are the per-boot
/// random lines (passed in — they have no fixed default), the binfmt_misc dir
/// is created here; the const/live tree + per-iface knobs come from the table.
/// # SAFETY: caller is the boot path; single-CPU pre-init.
/// # C: O(N leaves)
pub fn register_sysctl_table(boot_id: &'static [u8], random_uuid: &'static [u8]) {
    // Per-boot random-valued leaves (not const-table material).
    crate::reg::register("/proc/sys/kernel/random/boot_id", StaticFileInode::new(boot_id) as InodeRef);
    crate::reg::register("/proc/sys/kernel/random/uuid", StaticFileInode::new(random_uuid) as InodeRef);
    crate::reg::register(
        "/proc/sys/fs/binfmt_misc",
        kernfs::PseudoDir::new_root(
            kernfs::dir_ino("/proc/sys/fs/binfmt_misc"), crate::reg::PROCFS_FSID, false).as_inode(),
    );
    // The nested ctl_table tree (live-bound leaves).
    register_tree("/proc/sys", SYSCTL_TREE);
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
