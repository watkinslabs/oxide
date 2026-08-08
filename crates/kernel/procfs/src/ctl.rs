// `/proc/sys` ctl_table model, matching Linux's sysctl registration and
// proc_sysctl inode binding. D22: a declarative, NESTED `ctl_table` tree whose every leaf
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
//   * `net.ipv4.ip_forward` is an integer hook bound to `net::forwarding` —
//     also a real in-tree backing variable.
//   * `net.core.somaxconn` is bound to `net::sysctl`, shared by TCP + AF_UNIX.
//   * Genuine read-only constants (ostype/osrelease/version, cap_last_cap, …)
//     stay `StaticFileInode` (mode 0444 — Linux rejects writes to those too).
//   * Multi-field free slots (printk = 4 ints, file-nr = 3 fields) stay a
//     `proc_dointvec` free byte slot (`SysctlInode`, procfs-owned cell).
//
// Backing-variable policy: a leaf whose backing kernel variable EXISTS in-tree
// binds to it (hostname, ip_forward); a leaf whose backing does NOT exist gets
// a procfs-OWNED live cell (the `Box::leak`ed atomic) — a real read/write
// variable, NOT a fake constant (Linux-faithful: `data` always points at a
// live `int`/`long`). Cross-lane subsystems (mm VM tunables, vfs fs
// limits, net buffer sizes) can later repoint these leaves at THEIR variable
// by swapping the handler, without changing the tree or the path set.

#![cfg(target_os = "oxide-kernel")]

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicI64, AtomicU64};
use vfs::{InodeRef, KResult};
use crate::StaticFileInode;
use crate::sysctl::{bound_sysctl_inode, SysctlInode};
use crate::proc_handler::{
    CheckedIntHook as HCheckedIntHook, IntHook as HIntHook, IntVar, PermIntHook as HPermIntHook, NetGlobalIntHook as HNetGlobalIntHook,
    PerNetIntHook as HPerNetIntHook,
    PerPidIntHook as HPerPidIntHook,
    PerNetU16PairHook as HPerNetU16PairHook,
    PerNetBufWindowHook as HPerNetBufWindowHook,
    PerNetGroupRangeHook as HPerNetGroupRangeHook,
    StrHook as HStrHook, ULongVar,
};

/// `proc_dointvec_minmax` window upper bound for a 32-bit-int knob.
const INT_MAX: i64 = i32::MAX as i64;

/// `fs.mqueue.{msg_max,msg_default}` window.
const MQ_MSG_BOUNDS: (i64, i64) =
    (ipc::mqueue_policy::limits::MIN_MSGMAX, ipc::mqueue_policy::limits::HARD_MSGMAX);
/// `fs.mqueue.{msgsize_max,msgsize_default}` window (`msg_maxsize_limit_*`).
const MQ_MSGSIZE_BOUNDS: (i64, i64) =
    (ipc::mqueue_policy::limits::MIN_MSGSIZEMAX, ipc::mqueue_policy::limits::HARD_MSGSIZEMAX);

mod hooks;
use hooks::*;

// Subtree declarations, split out for the file-length cap. Named `*_dir`
// because a bare `mod net` here SHADOWS the `net` crate that this file's own
// leaves bind to — a collision that only fails on a kernel-target build.
mod kernel_dir;
mod net_dir;

/// One `ctl_table` leaf's `proc_handler` class + default value. # C: n/a
enum Leaf {
    /// `proc_dointvec` (bounds `None`) / `proc_dointvec_minmax` (bounds
    /// `Some((min,max))`) over a live `AtomicI64`.
    Int(i64, Option<(i64, i64)>),
    /// `proc_dointvec_minmax` bound to a subsystem accessor pair.
    NetInt(net::net_ns::NetSysctlKey, Option<(i64, i64)>),
    /// `proc_dointvec_minmax` bound to a subsystem-owned scalar.
    IntHook(fn() -> i64, fn(i64), Option<(i64, i64)>),
    /// `proc_dointvec_minmax` whose setter can REFUSE the write, for a value
    /// with a constraint the static bounds cannot express (a one-way ratchet).
    CheckedIntHook(fn() -> i64, fn(i64) -> Result<(), ()>, Option<(i64, i64)>),
    /// `proc_dointvec_minmax` whose setter answers EPERM rather than EINVAL
    /// when it refuses — a knob guarded by a capability or a one-way latch.
    PermIntHook(fn() -> i64, fn(i64) -> KResult<()>, Option<(i64, i64)>),
    /// A `net/core` leaf whose backing variable is one global, writable only
    /// from the initial network namespace.
    NetGlobalIntHook(fn() -> i64, fn(i64), Option<(i64, i64)>),
    /// Fallible hook for values constrained by another live field.
    PerNetIntHook(fn(&network_namespace::NetworkNamespaceRef, usize) -> Result<i64, ()>,
        fn(&network_namespace::NetworkNamespaceRef, usize, i64) -> Result<(), ()>,
        Option<(i64, i64)>),
    /// PID-namespace hook with a write-time namespace capability gate.
    PerPidIntHook(fn(&namespace_identity::NamespaceRef) -> Result<i64, ()>,
        fn(&namespace_identity::NamespaceRef) -> KResult<()>,
        fn(&namespace_identity::NamespaceRef, i64) -> KResult<()>,
        Option<(i64, i64)>),
    /// `proc_doulongvec_minmax` over a live `AtomicU64`.
    ULong(u64, Option<(u64, u64)>),
    /// `proc_dostring` bound to a subsystem accessor pair.
    StrHook(fn() -> alloc::vec::Vec<u8>, fn(&[u8])),
    /// `proc_dostring` over a per-namespace text value. The flag makes the
    /// file owner-only, for a value that is a secret.
    PerNetStrHook(fn(&network_namespace::NetworkNamespaceRef) -> alloc::vec::Vec<u8>,
        fn(&network_namespace::NetworkNamespaceRef, &[u8]) -> Result<(), ()>, bool),
    /// Two-u16 `proc_dointvec` bound to subsystem accessors.
    PerNetU16PairHook(fn(&network_namespace::NetworkNamespaceRef) -> Result<(u16, u16), ()>,
        fn(&network_namespace::NetworkNamespaceRef, u16, u16) -> Result<(), ()>),
    /// Three-value socket-buffer window (`tcp_wmem` / `tcp_rmem`).
    PerNetBufWindowHook(fn(&network_namespace::NetworkNamespaceRef) -> [i64; 3],
        fn(&network_namespace::NetworkNamespaceRef, [i64; 3]) -> Result<(), ()>,
        (i64, i64)),
    /// Two-value group window bound to subsystem accessors.
    PerNetGroupRangeHook(fn(&network_namespace::NetworkNamespaceRef) -> Result<(u32, u32), ()>,
        fn(&network_namespace::NetworkNamespaceRef, u32, u32) -> Result<(), ()>),
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
    Dir("kernel", kernel_dir::KERNEL_SYSCTLS),
    // `debug/` carries a single leaf: the reference registers `exception-trace`
    // there (not under `kernel/`), and `sysctl -w debug.exception-trace=0` is
    // how an operator silences the unhandled-fault report.
    Dir("debug", &[
        File("exception-trace",   IntHook(get_exception_trace, set_exception_trace, Some((0, 1)))),
    ]),
    Dir("fs", &[
        File("file-max",              ULong(4096, None)),
        File("file-nr",              Const(b"0\t0\t65536\n")),
        File("nr_open",               IntHook(get_nr_open, set_nr_open,
            Some((vfs::fdtable::NR_OPEN_MIN as i64, vfs::fdtable::NR_OPEN_MAX as i64)))),
        File("pipe-max-size",         IntHook(get_pipe_max_size, set_pipe_max_size, Some((1, INT_MAX)))),
        File("pipe-user-pages-hard",  IntHook(get_pipe_user_pages_hard, set_pipe_user_pages_hard, None)),
        File("pipe-user-pages-soft",  IntHook(get_pipe_user_pages_soft, set_pipe_user_pages_soft, None)),
        File("protected_regular",     Int(2, Some((0, 2)))),
        File("protected_fifos",       Int(1, Some((0, 2)))),
        // Writable, like their `protected_regular`/`protected_fifos` siblings
        // above: the reference registers all four mode 0644 over a [0,1] or
        // [0,2] window. Bound as read-only constants these answered the service
        // manager's boot-time sysctl apply with EROFS, and because the shipped
        // config does not prefix them with `-`, that one refusal failed the
        // whole unit.
        File("protected_hardlinks",   Int(1, Some((0, 1)))),
        File("protected_symlinks",    Int(1, Some((0, 1)))),
        File("suid_dumpable",         IntHook(get_suid_dumpable, set_suid_dumpable, Some((0, 2)))),
        Dir("mqueue", &[
            // `queues_max` is a plain `proc_dointvec`; the
            // four size knobs are `proc_dointvec_minmax` between the MIN_* an
            // admin may lower to and the HARD_* even CAP_SYS_RESOURCE cannot pass.
            File("queues_max",       IntHook(get_mq_queues_max, set_mq_queues_max, None)),
            File("msg_max",          IntHook(get_mq_msg_max, set_mq_msg_max, Some(MQ_MSG_BOUNDS))),
            File("msgsize_max",      IntHook(get_mq_msgsize_max, set_mq_msgsize_max, Some(MQ_MSGSIZE_BOUNDS))),
            File("msg_default",      IntHook(get_mq_msg_default, set_mq_msg_default, Some(MQ_MSG_BOUNDS))),
            File("msgsize_default",  IntHook(get_mq_msgsize_default, set_mq_msgsize_default, Some(MQ_MSGSIZE_BOUNDS))),
        ]),
        // Linux's inotify + fanotify subsystems register these against LIVE
        // variables — the two
        // `max_user_*` leaves are the user-namespace ucount ceilings the add
        // paths charge against (ENOSPC/EMFILE), the `max_queued_events` leaf is
        // the per-group queue depth snapshotted at group creation. Bound here,
        // not constants: a `Const` leaf let a watcher set a limit and observe
        // nothing enforce it.
        // `eventpoll_sysctls_init` registers this against the live ceiling
        // `epoll_ctl(EPOLL_CTL_ADD)` charges each interest against (ENOSPC).
        Dir("epoll", &[
            File("max_user_watches",   IntHook(get_ep_max_watches, set_ep_max_watches, Some((0, INT_MAX)))),
        ]),
        Dir("inotify", &[
            File("max_user_watches",   IntHook(get_in_max_watches, set_in_max_watches, Some((0, INT_MAX)))),
            File("max_user_instances", IntHook(get_in_max_instances, set_in_max_instances, Some((0, INT_MAX)))),
            File("max_queued_events",  IntHook(get_in_max_queued, set_in_max_queued, Some((0, INT_MAX)))),
        ]),
        Dir("fanotify", &[
            File("max_user_groups",   IntHook(get_fan_max_groups, set_fan_max_groups, Some((0, INT_MAX)))),
            File("max_user_marks",    IntHook(get_fan_max_marks, set_fan_max_marks, Some((0, INT_MAX)))),
            File("max_queued_events", IntHook(get_fan_max_queued, set_fan_max_queued, Some((0, INT_MAX)))),
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
        // `vm.memfd_noexec` belongs to the active PID namespace. A child
        // copies its parent's effective scope and cannot write below the
        // parent's current floor; writes require CAP_SYS_ADMIN in the PID
        // namespace's owning user namespace.
        File("memfd_noexec", PerPidIntHook(get_memfd_noexec,
            check_memfd_noexec_write, set_memfd_noexec,
            Some((namespace_identity::PID_MEMFD_NOEXEC_SCOPE_EXEC as i64,
                  namespace_identity::PID_MEMFD_NOEXEC_SCOPE_NOEXEC_ENFORCED as i64)))),
        // `vm.legacy_va_layout` — `sysctl_legacy_va_layout`, the system-wide
        // third input to `mmap_is_legacy` alongside
        // `personality(ADDR_COMPAT_LAYOUT)` and an unlimited RLIMIT_STACK.
        // Non-zero makes every subsequent exec allocate its mmap arena upward
        // from TASK_UNMAPPED_BASE instead of downward from mmap_base.
        File("legacy_va_layout",        IntHook(get_legacy_va_layout,
                                                set_legacy_va_layout, Some((0, 1)))),
        // `vm.mmap_rnd_bits` — the live entropy width `arch_mmap_rnd()` uses,
        // bounded by this arch's Kconfig pair. Linux has a
        // `mmap_rnd_compat_bits` sibling only under `CONFIG_COMPAT`; this
        // kernel has no 32-bit personality, so there is nothing to register.
        File("mmap_rnd_bits",           IntHook(get_mmap_rnd_bits, set_mmap_rnd_bits,
            Some((aslr::tunable::mmap_rnd_bits_min() as i64,
                  aslr::tunable::mmap_rnd_bits_max() as i64)))),
        // `vm.unprivileged_userfaultfd`:
        // `proc_dointvec_minmax` over `sysctl_unprivileged_userfaultfd`, window
        // [SYSCTL_ZERO, SYSCTL_ONE], zero-initialised. `userfaultfd(2)` reads it
        // to decide whether an unprivileged caller may create a context able to
        // intercept KERNEL-mode faults.
        File("unprivileged_userfaultfd", IntHook(get_unprivileged_userfaultfd,
            set_unprivileged_userfaultfd, Some(vmm::uffd::UNPRIVILEGED_USERFAULTFD_BOUNDS))),
    ]),
    Dir("net", net_dir::NET_SYSCTLS),
];

/// The Linux `net/ipv4/conf/<dev>/*` per-interface knob set (net/ipv4/
/// devinet.c `devinet_conf_ctl_table`). Each `<dev>` (all/default/lo/eth0)
/// gets the same writable leaves. # C: n/a
const IPV4_CONF_LEAVES: &[(&str, net::net_ns::Ipv4ConfKey)] = &[
    ("accept_local", net::net_ns::Ipv4ConfKey::AcceptLocal),
    ("accept_redirects", net::net_ns::Ipv4ConfKey::AcceptRedirects),
    ("accept_source_route", net::net_ns::Ipv4ConfKey::AcceptSourceRoute),
    ("arp_accept", net::net_ns::Ipv4ConfKey::ArpAccept),
    ("arp_announce", net::net_ns::Ipv4ConfKey::ArpAnnounce),
    ("arp_filter", net::net_ns::Ipv4ConfKey::ArpFilter),
    ("arp_ignore", net::net_ns::Ipv4ConfKey::ArpIgnore),
    ("arp_notify", net::net_ns::Ipv4ConfKey::ArpNotify),
    ("bootp_relay", net::net_ns::Ipv4ConfKey::BootpRelay),
    ("disable_policy", net::net_ns::Ipv4ConfKey::DisablePolicy),
    ("disable_xfrm", net::net_ns::Ipv4ConfKey::DisableXfrm),
    ("drop_gratuitous_arp", net::net_ns::Ipv4ConfKey::DropGratuitousArp),
    ("drop_unicast_in_l2_multicast", net::net_ns::Ipv4ConfKey::DropUnicastInL2Multicast),
    ("force_igmp_version", net::net_ns::Ipv4ConfKey::ForceIgmpVersion),
    ("forwarding", net::net_ns::Ipv4ConfKey::Forwarding),
    ("ignore_routes_with_linkdown", net::net_ns::Ipv4ConfKey::IgnoreRoutesWithLinkdown),
    ("log_martians", net::net_ns::Ipv4ConfKey::LogMartians),
    ("promote_secondaries", net::net_ns::Ipv4ConfKey::PromoteSecondaries),
    ("proxy_arp", net::net_ns::Ipv4ConfKey::ProxyArp),
    ("proxy_arp_pvlan", net::net_ns::Ipv4ConfKey::ProxyArpPvlan),
    ("route_localnet", net::net_ns::Ipv4ConfKey::RouteLocalnet),
    ("rp_filter", net::net_ns::Ipv4ConfKey::RpFilter),
    ("secure_redirects", net::net_ns::Ipv4ConfKey::SecureRedirects),
    ("send_redirects", net::net_ns::Ipv4ConfKey::SendRedirects),
    ("shared_media", net::net_ns::Ipv4ConfKey::SharedMedia),
    ("src_valid_mark", net::net_ns::Ipv4ConfKey::SrcValidMark),
];

/// Linux `ipv4_devconf` compiled defaults: the knobs seeded to `1`; every
/// other `net/ipv4/conf/<dev>/*` leaf defaults to `0`. # C: n/a
/// The interfaces that get a `net/ipv4/conf/<dev>` subtree at boot: the two
/// pseudo-devices Linux always exposes (`all`, `default`) plus the loopback
/// and the first ethernet device. # C: n/a
const IPV4_CONF_DEVS: &[(&str, net::net_ns::Ipv4ConfDev)] = &[
    ("all", net::net_ns::Ipv4ConfDev::All),
    ("default", net::net_ns::Ipv4ConfDev::Default),
    ("lo", net::net_ns::Ipv4ConfDev::Lo),
    ("eth0", net::net_ns::Ipv4ConfDev::Eth0),
];

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
        NetInt(key, bounds) => bound_sysctl_inode(Arc::new(HPerNetIntHook {
            current_ns: current_net_ns, key: key.as_usize(), get: net_int,
            set: set_net_int, bounds,
        })),
        Leaf::PerNetIntHook(get, set, bounds) => bound_sysctl_inode(Arc::new(HPerNetIntHook {
            current_ns: current_net_ns, key: 0, get, set, bounds,
        })),
        Leaf::PerPidIntHook(get, check_write, set, bounds) =>
            bound_sysctl_inode(Arc::new(HPerPidIntHook {
                current_ns: current_pid_ns, check_write, get, set, bounds,
            })),
        Leaf::IntHook(get, set, bounds) => bound_sysctl_inode(Arc::new(HIntHook { get, set, bounds })),
        Leaf::CheckedIntHook(get, set, bounds) =>
            bound_sysctl_inode(Arc::new(HCheckedIntHook { get, set, bounds })),
        Leaf::PermIntHook(get, set, bounds) =>
            bound_sysctl_inode(Arc::new(HPermIntHook { get, set, bounds })),
        Leaf::NetGlobalIntHook(get, set, bounds) => bound_sysctl_inode(Arc::new(
            HNetGlobalIntHook { current_ns: current_net_ns, get, set, bounds })),
        ULong(def, bounds) => {
            let cell: &'static AtomicU64 = Box::leak(Box::new(AtomicU64::new(def)));
            bound_sysctl_inode(Arc::new(ULongVar { cell, bounds }))
        }
        Leaf::StrHook(get, set) => bound_sysctl_inode(Arc::new(HStrHook { get, set })),
        Leaf::PerNetStrHook(get, set, owner_only) => bound_sysctl_inode(Arc::new(
            crate::proc_handler_netstr::PerNetStrHook {
                current_ns: current_net_ns, get, set, owner_only,
            })),
        Leaf::PerNetBufWindowHook(get, set, bounds) => bound_sysctl_inode(Arc::new(
            HPerNetBufWindowHook { current_ns: current_net_ns, get, set, bounds })),
        Leaf::PerNetGroupRangeHook(get, set) => bound_sysctl_inode(Arc::new(HPerNetGroupRangeHook {
            current_ns: current_net_ns, get, set,
        })),
        Leaf::PerNetU16PairHook(get, set) => bound_sysctl_inode(Arc::new(HPerNetU16PairHook {
            current_ns: current_net_ns, get, set,
        })),
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

/// Register every `/proc/sys` leaf. `boot_id` is the once-per-boot random line
/// (passed in — it has no fixed default), the binfmt_misc dir is created here;
/// the const/live tree + per-iface knobs come from the table.
/// # SAFETY: caller is the boot path; single-CPU pre-init.
/// # C: O(N leaves)
pub fn register_sysctl_table(boot_id: &'static [u8]) {
    net::net_ns::materialize_state(&network_namespace::initial());
    // The two `proc_do_uuid` leaves, matching Linux's random.c sysctl table.
    // `boot_id` has `.data = &sysctl_bootid`: generated once, then stable.
    // `uuid` has NO `.data`, so each read generates a fresh v4 UUID — a
    // generator inode, not a snapshot every reader on this boot would share.
    crate::reg::register("/proc/sys/kernel/random/boot_id",
        crate::random_uuid::make_boot_id_inode(boot_id));
    crate::reg::register("/proc/sys/kernel/random/uuid",
        crate::random_uuid::make_uuid_inode(crate::ids::RANDOM_UUID));
    crate::reg::register(
        "/proc/sys/fs/binfmt_misc",
        kernfs::PseudoDir::new_root(
            kernfs::dir_ino("/proc/sys/fs/binfmt_misc"), crate::reg::PROCFS_FSID).as_inode(),
    );
    // The nested ctl_table tree (live-bound leaves).
    register_tree("/proc/sys", SYSCTL_TREE);
    // net/ipv4/conf/<dev>/* writable per-iface knobs (all/default/lo/eth0).
    for (dev, dev_key) in IPV4_CONF_DEVS.iter().copied() {
        for (leaf, leaf_key) in IPV4_CONF_LEAVES.iter().copied() {
            let path = alloc::format!("/proc/sys/net/ipv4/conf/{dev}/{leaf}");
            let key = net::net_ns::NetSysctlKey::Ipv4Conf(dev_key, leaf_key);
            crate::reg::register(&path, make_leaf(&NetInt(key, Some((0, INT_MAX)))));
        }
    }
}
