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
use vfs::{InodeRef, KResult, VfsError};
use crate::StaticFileInode;
use crate::sysctl::{bound_sysctl_inode, SysctlInode};
use crate::proc_handler::{
    CheckedIntHook as HCheckedIntHook, IntHook as HIntHook, IntVar, NetGlobalIntHook as HNetGlobalIntHook,
    PerNetIntHook as HPerNetIntHook,
    PerPidIntHook as HPerPidIntHook,
    PerNetU16PairHook as HPerNetU16PairHook,
    PerNetGroupRangeHook as HPerNetGroupRangeHook,
    StrHook as HStrHook, ULongVar,
};

/// `proc_dointvec_minmax` window upper bound for a 32-bit-int knob.
const INT_MAX: i64 = i32::MAX as i64;

/// `fs.mqueue.{msg_max,msg_default}` window (`ipc/mq_sysctl.c` `msg_max_limit_*`).
const MQ_MSG_BOUNDS: (i64, i64) =
    (ipc::mqueue_policy::limits::MIN_MSGMAX, ipc::mqueue_policy::limits::HARD_MSGMAX);
/// `fs.mqueue.{msgsize_max,msgsize_default}` window (`msg_maxsize_limit_*`).
const MQ_MSGSIZE_BOUNDS: (i64, i64) =
    (ipc::mqueue_policy::limits::MIN_MSGSIZEMAX, ipc::mqueue_policy::limits::HARD_MSGSIZEMAX);

fn current_net_ns() -> network_namespace::NetworkNamespaceRef {
    net::net_ns::current_namespace()
}
fn current_pid_ns() -> namespace_identity::NamespaceRef {
    sched::current()
        .and_then(|task| task.namespace_owner(namespace_identity::NamespaceKind::Pid))
        .unwrap_or_else(|| namespace_identity::initial(namespace_identity::NamespaceKind::Pid))
}
fn get_memfd_noexec(namespace: &namespace_identity::NamespaceRef) -> Result<i64, ()> {
    namespace.pid_memfd_noexec_scope().map(i64::from).map_err(|_| ())
}
fn check_memfd_noexec_write(namespace: &namespace_identity::NamespaceRef) -> KResult<()> {
    let current = sched::current().ok_or(VfsError::Esrch)?;
    if nscg::proc_ns::has_cap_for(current, &namespace.owner_user_namespace(),
        sched::cap::SYS_ADMIN)
    {
        Ok(())
    } else {
        Err(VfsError::Eperm)
    }
}
fn set_memfd_noexec(namespace: &namespace_identity::NamespaceRef, value: i64) -> KResult<()> {
    namespace.set_pid_memfd_noexec_scope(value as u8).map_err(|_| VfsError::Einval)
}
/// `fs.suid_dumpable` lives with the credential code that consumes it
/// (`sched::cred`, Linux `fs/exec.c int suid_dumpable`); this leaf binds to
/// that variable rather than keeping a procfs-owned copy.
fn get_suid_dumpable() -> i64 { sched::cred::suid_dumpable() as i64 }
fn get_perf_paranoid() -> i64 { sched::perf_sw::paranoid() as i64 }
fn set_perf_paranoid(v: i64) { sched::perf_sw::set_paranoid(v as i32); }
fn get_perf_sample_rate() -> i64 { sched::perf_sw::sample_rate() as i64 }
fn set_perf_sample_rate(v: i64) { sched::perf_sw::set_sample_rate(v as i32); }
fn get_dmesg_restrict() -> i64 { klog::syslog::dmesg_restrict() as i64 }
/// `kernel.randomize_va_space` + `vm.mmap_rnd_bits` bind to `aslr`, the single
/// owner of the randomisation policy every `execve` consults.
fn get_randomize_va_space() -> i64 { aslr::randomize_va_space() as i64 }
fn set_randomize_va_space(v: i64) { aslr::set_randomize_va_space(v as i32); }
/// `vm.unprivileged_userfaultfd` binds to the mm-owned tunable
/// `userfaultfd_syscall_allowed` consults; there is no procfs-side copy that
/// could disagree with the gate.
fn get_unprivileged_userfaultfd() -> i64 { vmm::uffd::unprivileged_userfaultfd() }
fn set_unprivileged_userfaultfd(v: i64) { vmm::uffd::set_unprivileged_userfaultfd(v); }
fn get_legacy_va_layout() -> i64 { aslr::tunable::legacy_va_layout() as i64 }
fn set_legacy_va_layout(v: i64) { aslr::tunable::set_legacy_va_layout(v != 0); }

fn get_mmap_rnd_bits() -> i64 { aslr::tunable::mmap_rnd_bits() as i64 }
fn set_mmap_rnd_bits(v: i64) { aslr::tunable::set_mmap_rnd_bits(v.max(0) as u32); }
/// `fs.nr_open` binds to Linux's own owner of `sysctl_nr_open` (`fs/file.c` →
/// `vfs::fdtable`), so `setrlimit(RLIMIT_NOFILE)`'s EPERM ceiling and this file
/// can never disagree.
fn get_nr_open() -> i64 { vfs::fdtable::nr_open() as i64 }
fn set_nr_open(value: i64) { let _ = vfs::fdtable::set_nr_open(value as u32); }
fn set_dmesg_restrict(value: i64) { klog::syslog::set_dmesg_restrict(value != 0); }
/// `fs.mqueue.*` binds to the per-IPC-namespace values `mq_open` measures a
/// `struct mq_attr` against (`ipc/mq_sysctl.c`), so raising a ceiling here and
/// the EINVAL the syscall reports can never disagree. Every leaf is
/// namespace-scoped: Linux's `set_lookup` resolves `current`'s `ipc_ns`.
fn get_ep_max_watches() -> i64 { vfs::epoll_limits::max_user_watches() }
fn set_ep_max_watches(v: i64) { vfs::epoll_limits::set_max_user_watches(v) }
fn get_in_max_watches() -> i64 { vfs::fsnotify::max_user_watches() }
fn set_in_max_watches(v: i64) { vfs::fsnotify::set_max_user_watches(v) }
fn get_in_max_instances() -> i64 { vfs::fsnotify::max_user_instances() }
fn set_in_max_instances(v: i64) { vfs::fsnotify::set_max_user_instances(v) }
fn get_in_max_queued() -> i64 { vfs::fsnotify::max_queued_events() }
fn set_in_max_queued(v: i64) { vfs::fsnotify::set_max_queued_events(v) }
fn get_fan_max_groups() -> i64 { vfs::fsnotify::fanotify_max_user_groups() }
fn set_fan_max_groups(v: i64) { vfs::fsnotify::set_fanotify_max_user_groups(v) }
fn get_fan_max_marks() -> i64 { vfs::fsnotify::fanotify_max_user_marks() }
fn set_fan_max_marks(v: i64) { vfs::fsnotify::set_fanotify_max_user_marks(v) }
fn get_fan_max_queued() -> i64 { vfs::fsnotify::fanotify_max_queued_events() }
fn set_fan_max_queued(v: i64) { vfs::fsnotify::set_fanotify_max_queued_events(v) }

fn get_mq_queues_max() -> i64 { ipc::live::posix_mq::sysctl::queues_max() }
fn set_mq_queues_max(v: i64) { ipc::live::posix_mq::sysctl::set_queues_max(v) }
fn get_mq_msg_max() -> i64 { ipc::live::posix_mq::sysctl::msg_max() }
fn set_mq_msg_max(v: i64) { ipc::live::posix_mq::sysctl::set_msg_max(v) }
fn get_mq_msgsize_max() -> i64 { ipc::live::posix_mq::sysctl::msgsize_max() }
fn set_mq_msgsize_max(v: i64) { ipc::live::posix_mq::sysctl::set_msgsize_max(v) }
fn get_mq_msg_default() -> i64 { ipc::live::posix_mq::sysctl::msg_default() }
fn set_mq_msg_default(v: i64) { ipc::live::posix_mq::sysctl::set_msg_default(v) }
fn get_mq_msgsize_default() -> i64 { ipc::live::posix_mq::sysctl::msgsize_default() }
fn set_mq_msgsize_default(v: i64) { ipc::live::posix_mq::sysctl::set_msgsize_default(v) }
/// `kernel.modules_disabled` binds to the variable `init_module`/`finit_module`/
/// `delete_module` actually read (`modules::admission`), so the file and the
/// syscall admission can never disagree. Linux registers the leaf with
/// `extra1 = extra2 = SYSCTL_ONE`: only the 0→1 transition is in range, which
/// is what makes the latch one-way.
fn get_modules_disabled() -> i64 { modules::admission::modules_disabled() as i64 }
fn set_modules_disabled(value: i64) { let _ = modules::admission::set_modules_disabled(value); }
fn set_suid_dumpable(value: i64) { sched::cred::set_suid_dumpable(value as u8); }
fn get_ptrace_scope() -> i64 { sched::yama::scope() as i64 }
/// A REFUSED write must report EINVAL, not silently succeed: a hardening
/// script that lowers `ptrace_scope` and reads back a success it did not get
/// would believe it had relaxed a restriction that is still in force.
fn set_ptrace_scope(value: i64) -> Result<(), ()> {
    if sched::yama::set_scope(value) { Ok(()) } else { Err(()) }
}
/// `net.core.rmem_max` / `net.core.wmem_max` bind to the ONE pair of ceilings
/// `SO_RCVBUF` / `SO_SNDBUF` clamp against, so the leaf and the option can
/// never disagree.
fn get_rmem_max() -> i64 { net::sysctl::rmem_max() as i64 }
fn set_rmem_max(value: i64) { net::sysctl::set_rmem_max(value) }
fn get_wmem_max() -> i64 { net::sysctl::wmem_max() as i64 }
fn set_wmem_max(value: i64) { net::sysctl::set_wmem_max(value) }
fn net_int(namespace: &network_namespace::NetworkNamespaceRef, key: usize) -> Result<i64, ()> {
    let key = net::net_ns::NetSysctlKey::from_usize(key).ok_or(())?;
    net::sysctl::value(namespace, key).ok_or(())
}
fn set_net_int(namespace: &network_namespace::NetworkNamespaceRef,
    key: usize, value: i64) -> Result<(), ()>
{
    let key = net::net_ns::NetSysctlKey::from_usize(key).ok_or(())?;
    net::sysctl::set_value(namespace, key, value)
}
fn local_port_range(namespace: &network_namespace::NetworkNamespaceRef) -> Result<(u16, u16), ()> {
    let range = net::ephemeral::range_for(namespace).ok_or(())?;
    Ok((range.start, range.end))
}
fn set_local_port_range(namespace: &network_namespace::NetworkNamespaceRef,
    start: u16, end: u16) -> Result<(), ()>
{
    net::ephemeral::set_range_for(namespace, start, end)
}
fn ping_group_range(namespace: &network_namespace::NetworkNamespaceRef)
    -> Result<(u32, u32), ()>
{
    net::ping::group_range_for(namespace).ok_or(())
}
fn set_ping_group_range(namespace: &network_namespace::NetworkNamespaceRef,
    low: u32, high: u32) -> Result<(), ()>
{
    net::ping::set_group_range_for(namespace, low, high)
}
fn unprivileged_port_start(namespace: &network_namespace::NetworkNamespaceRef,
    _key: usize) -> Result<i64, ()>
{
    net::ephemeral::unprivileged_start_for(namespace).map(i64::from).ok_or(())
}
fn set_unprivileged_port_start(namespace: &network_namespace::NetworkNamespaceRef,
    _key: usize, value: i64) -> Result<(), ()>
{
    net::ephemeral::set_unprivileged_start_for(namespace, value as u16)
}

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
    /// Two-u16 `proc_dointvec` bound to subsystem accessors.
    PerNetU16PairHook(fn(&network_namespace::NetworkNamespaceRef) -> Result<(u16, u16), ()>,
        fn(&network_namespace::NetworkNamespaceRef, u16, u16) -> Result<(), ()>),
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

// Subtree declarations, split out for the file-length cap. Named `*_dir`
// because a bare `mod net` here SHADOWS the `net` crate every leaf in this file
// binds to.
mod kernel_dir;
mod net_dir;

/// The nested `/proc/sys` ctl_table tree. Mirrors the Linux directory layout
/// (`kernel/`, `fs/`, `vm/`, `net/core`, `net/ipv4`, …) with the live binding
/// declared at every leaf. # C: n/a
const SYSCTL_TREE: &[Node] = &[
    Dir("kernel", kernel_dir::KERNEL_SYSCTLS),
    Dir("fs", &[
        File("file-max",              ULong(4096, None)),
        File("file-nr",              Const(b"0\t0\t65536\n")),
        File("nr_open",               IntHook(get_nr_open, set_nr_open,
            Some((vfs::fdtable::NR_OPEN_MIN as i64, vfs::fdtable::NR_OPEN_MAX as i64)))),
        File("pipe-max-size",         Int(4096, Some((0, INT_MAX)))),
        File("protected_regular",     Int(2, Some((0, 2)))),
        File("protected_fifos",       Int(1, Some((0, 2)))),
        File("protected_hardlinks",   Const(b"1\n")),
        File("protected_symlinks",    Const(b"1\n")),
        File("suid_dumpable",         IntHook(get_suid_dumpable, set_suid_dumpable, Some((0, 2)))),
        Dir("mqueue", &[
            // `ipc/mq_sysctl.c`: `queues_max` is a plain `proc_dointvec`; the
            // four size knobs are `proc_dointvec_minmax` between the MIN_* an
            // admin may lower to and the HARD_* even CAP_SYS_RESOURCE cannot pass.
            File("queues_max",       IntHook(get_mq_queues_max, set_mq_queues_max, None)),
            File("msg_max",          IntHook(get_mq_msg_max, set_mq_msg_max, Some(MQ_MSG_BOUNDS))),
            File("msgsize_max",      IntHook(get_mq_msgsize_max, set_mq_msgsize_max, Some(MQ_MSGSIZE_BOUNDS))),
            File("msg_default",      IntHook(get_mq_msg_default, set_mq_msg_default, Some(MQ_MSG_BOUNDS))),
            File("msgsize_default",  IntHook(get_mq_msgsize_default, set_mq_msgsize_default, Some(MQ_MSGSIZE_BOUNDS))),
        ]),
        // `fs/notify/inotify/inotify_user.c` + `fs/notify/fanotify/
        // fanotify_user.c` register these against LIVE variables — the two
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
        // namespace's owning user namespace (`kernel/pid_sysctl.h`).
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
        // bounded by this arch's Kconfig pair (`mm/mmap.c:66-75`). Linux has a
        // `mmap_rnd_compat_bits` sibling only under `CONFIG_COMPAT`; this
        // kernel has no 32-bit personality, so there is nothing to register.
        File("mmap_rnd_bits",           IntHook(get_mmap_rnd_bits, set_mmap_rnd_bits,
            Some((aslr::tunable::mmap_rnd_bits_min() as i64,
                  aslr::tunable::mmap_rnd_bits_max() as i64)))),
        // `vm.unprivileged_userfaultfd` (`mm/userfaultfd.c` `vm_userfaultfd_table`):
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
        Leaf::NetGlobalIntHook(get, set, bounds) => bound_sysctl_inode(Arc::new(
            HNetGlobalIntHook { current_ns: current_net_ns, get, set, bounds })),
        ULong(def, bounds) => {
            let cell: &'static AtomicU64 = Box::leak(Box::new(AtomicU64::new(def)));
            bound_sysctl_inode(Arc::new(ULongVar { cell, bounds }))
        }
        Leaf::StrHook(get, set) => bound_sysctl_inode(Arc::new(HStrHook { get, set })),
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
    // The two `proc_do_uuid` leaves (`drivers/char/random.c` `random_table`).
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
