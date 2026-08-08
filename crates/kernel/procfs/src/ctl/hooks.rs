// The accessor pairs each `/proc/sys` leaf binds to. Every one of these reads
// or writes the LIVE variable its subsystem already owns, so a leaf and the
// syscall that consults the same value can never disagree.

use vfs::{KResult, VfsError};

pub(super) fn current_net_ns() -> network_namespace::NetworkNamespaceRef {
    net::net_ns::current_namespace()
}
pub(super) fn current_pid_ns() -> namespace_identity::NamespaceRef {
    sched::current()
        .and_then(|task| task.namespace_owner(namespace_identity::NamespaceKind::Pid))
        .unwrap_or_else(|| namespace_identity::initial(namespace_identity::NamespaceKind::Pid))
}
pub(super) fn get_memfd_noexec(namespace: &namespace_identity::NamespaceRef) -> Result<i64, ()> {
    namespace.pid_memfd_noexec_scope().map(i64::from).map_err(|_| ())
}
pub(super) fn check_memfd_noexec_write(namespace: &namespace_identity::NamespaceRef) -> KResult<()> {
    let current = sched::current().ok_or(VfsError::Esrch)?;
    if nscg::proc_ns::has_cap_for(current, &namespace.owner_user_namespace(),
        sched::cap::SYS_ADMIN)
    {
        Ok(())
    } else {
        Err(VfsError::Eperm)
    }
}
pub(super) fn set_memfd_noexec(namespace: &namespace_identity::NamespaceRef, value: i64) -> KResult<()> {
    namespace.set_pid_memfd_noexec_scope(value as u8).map_err(|_| VfsError::Einval)
}
/// `fs.suid_dumpable` lives with the credential code that consumes it
/// (`sched::cred`); this leaf binds to
/// that variable rather than keeping a procfs-owned copy.
pub(super) fn get_suid_dumpable() -> i64 { sched::cred::suid_dumpable() as i64 }
pub(super) fn get_perf_paranoid() -> i64 { sched::perf_sw::paranoid() as i64 }
pub(super) fn set_perf_paranoid(v: i64) { sched::perf_sw::set_paranoid(v as i32); }
pub(super) fn get_perf_sample_rate() -> i64 { sched::perf_sw::sample_rate() as i64 }
pub(super) fn set_perf_sample_rate(v: i64) { sched::perf_sw::set_sample_rate(v as i32); }
pub(super) fn get_dmesg_restrict() -> i64 { klog::syslog::dmesg_restrict() as i64 }

/// `kernel.unprivileged_bpf_disabled`, bound to the cell `bpf(2)` reads.
/// # C: O(1)
pub(super) fn get_unpriv_bpf_disabled() -> i64 {
    security::bpf::attr::unpriv_bpf_disabled_value() as i64
}
/// # C: O(1)
pub(super) fn set_unpriv_bpf_disabled(value: i64) -> vfs::KResult<()> {
    security::bpf::attr::write_unpriv_bpf_disabled(value)
        .map_err(|e| if e == syscall::errno::Errno::Eperm { vfs::VfsError::Eperm }
                     else { vfs::VfsError::Einval })
}
/// `kernel.io_uring_disabled` / `kernel.io_uring_group` bind to the live cells
/// the ring-creation admission check reads. A procfs-local copy would let an
/// administrator disable io_uring here while ring creation kept succeeding.
pub(super) fn get_io_uring_disabled() -> i64 { syscall::io_uring_ctl::disabled() as i64 }
pub(super) fn set_io_uring_disabled(v: i64) { syscall::io_uring_ctl::set_disabled(v as i32); }
pub(super) fn get_io_uring_group() -> i64 { syscall::io_uring_ctl::group() as i64 }
pub(super) fn set_io_uring_group(v: i64) { syscall::io_uring_ctl::set_group(v as i32); }
/// `debug.exception-trace` binds to the live `show_unhandled_signals` cell the
/// fault path reads, so silencing the report here really does silence it.
pub(super) fn get_exception_trace() -> i64 { sched::signal_report::show_unhandled_signals() as i64 }
pub(super) fn set_exception_trace(v: i64) { sched::signal_report::set_show_unhandled_signals(v != 0); }
/// `kernel.randomize_va_space` + `vm.mmap_rnd_bits` bind to `aslr`, the single
/// owner of the randomisation policy every `execve` consults.
pub(super) fn get_randomize_va_space() -> i64 { aslr::randomize_va_space() as i64 }
pub(super) fn set_randomize_va_space(v: i64) { aslr::set_randomize_va_space(v as i32); }
/// `vm.unprivileged_userfaultfd` binds to the mm-owned tunable
/// `userfaultfd_syscall_allowed` consults; there is no procfs-side copy that
/// could disagree with the gate.
pub(super) fn get_unprivileged_userfaultfd() -> i64 { vmm::uffd::unprivileged_userfaultfd() }
pub(super) fn set_unprivileged_userfaultfd(v: i64) { vmm::uffd::set_unprivileged_userfaultfd(v); }
pub(super) fn get_legacy_va_layout() -> i64 { aslr::tunable::legacy_va_layout() as i64 }
pub(super) fn set_legacy_va_layout(v: i64) { aslr::tunable::set_legacy_va_layout(v != 0); }

pub(super) fn get_mmap_rnd_bits() -> i64 { aslr::tunable::mmap_rnd_bits() as i64 }
pub(super) fn set_mmap_rnd_bits(v: i64) { aslr::tunable::set_mmap_rnd_bits(v.max(0) as u32); }
/// `fs.nr_open` binds to Linux's own owner of `sysctl_nr_open`
/// (`vfs::fdtable`), so `setrlimit(RLIMIT_NOFILE)`'s EPERM ceiling and this file
/// can never disagree.
pub(super) fn get_nr_open() -> i64 { vfs::fdtable::nr_open() as i64 }
pub(super) fn set_nr_open(value: i64) { let _ = vfs::fdtable::set_nr_open(value as u32); }
pub(super) fn set_dmesg_restrict(value: i64) { klog::syslog::set_dmesg_restrict(value != 0); }
/// `fs.mqueue.*` binds to the per-IPC-namespace values `mq_open` measures a
/// `struct mq_attr` against, so raising a ceiling here and
/// the EINVAL the syscall reports can never disagree. Every leaf is
/// namespace-scoped: Linux's `set_lookup` resolves `current`'s `ipc_ns`.
pub(super) fn get_ep_max_watches() -> i64 { vfs::epoll_limits::max_user_watches() }
pub(super) fn set_ep_max_watches(v: i64) { vfs::epoll_limits::set_max_user_watches(v) }
pub(super) fn get_in_max_watches() -> i64 { vfs::fsnotify::max_user_watches() }
pub(super) fn set_in_max_watches(v: i64) { vfs::fsnotify::set_max_user_watches(v) }
pub(super) fn get_in_max_instances() -> i64 { vfs::fsnotify::max_user_instances() }
pub(super) fn set_in_max_instances(v: i64) { vfs::fsnotify::set_max_user_instances(v) }
pub(super) fn get_in_max_queued() -> i64 { vfs::fsnotify::max_queued_events() }
pub(super) fn set_in_max_queued(v: i64) { vfs::fsnotify::set_max_queued_events(v) }
pub(super) fn get_fan_max_groups() -> i64 { vfs::fsnotify::fanotify_max_user_groups() }
pub(super) fn set_fan_max_groups(v: i64) { vfs::fsnotify::set_fanotify_max_user_groups(v) }
pub(super) fn get_fan_max_marks() -> i64 { vfs::fsnotify::fanotify_max_user_marks() }
pub(super) fn set_fan_max_marks(v: i64) { vfs::fsnotify::set_fanotify_max_user_marks(v) }
pub(super) fn get_fan_max_queued() -> i64 { vfs::fsnotify::fanotify_max_queued_events() }
pub(super) fn set_fan_max_queued(v: i64) { vfs::fsnotify::set_fanotify_max_queued_events(v) }

/// `kernel.shm_rmid_forced` binds to the SysV shm registry's own per-IPC-namespace
/// flag — the value `shm_may_destroy` reads on every detach and creator exit.
/// The write side is Linux's `proc_ipc_dointvec_minmax_orphans`: setting it also
/// sweeps the namespace's already orphaned segments, so the knob reclaims
/// segments created before the write.
pub(super) fn get_shm_rmid_forced() -> i64 { ipc::sysv_shm::shm_rmid_forced() }
pub(super) fn set_shm_rmid_forced(v: i64) { ipc::sysv_shm::set_shm_rmid_forced(v) }
pub(super) fn get_mq_queues_max() -> i64 { ipc::live::posix_mq::sysctl::queues_max() }
pub(super) fn set_mq_queues_max(v: i64) { ipc::live::posix_mq::sysctl::set_queues_max(v) }
pub(super) fn get_mq_msg_max() -> i64 { ipc::live::posix_mq::sysctl::msg_max() }
pub(super) fn set_mq_msg_max(v: i64) { ipc::live::posix_mq::sysctl::set_msg_max(v) }
pub(super) fn get_mq_msgsize_max() -> i64 { ipc::live::posix_mq::sysctl::msgsize_max() }
pub(super) fn set_mq_msgsize_max(v: i64) { ipc::live::posix_mq::sysctl::set_msgsize_max(v) }
pub(super) fn get_mq_msg_default() -> i64 { ipc::live::posix_mq::sysctl::msg_default() }
pub(super) fn set_mq_msg_default(v: i64) { ipc::live::posix_mq::sysctl::set_msg_default(v) }
pub(super) fn get_mq_msgsize_default() -> i64 { ipc::live::posix_mq::sysctl::msgsize_default() }
pub(super) fn set_mq_msgsize_default(v: i64) { ipc::live::posix_mq::sysctl::set_msgsize_default(v) }
/// `kernel.modules_disabled` binds to the variable `init_module`/`finit_module`/
/// `delete_module` actually read (`modules::admission`), so the file and the
/// syscall admission can never disagree. Linux registers the leaf with
/// `extra1 = extra2 = SYSCTL_ONE`: only the 0→1 transition is in range, which
/// is what makes the latch one-way.
pub(super) fn get_modules_disabled() -> i64 { modules::admission::modules_disabled() as i64 }
pub(super) fn set_modules_disabled(value: i64) { let _ = modules::admission::set_modules_disabled(value); }
pub(super) fn set_suid_dumpable(value: i64) { sched::cred::set_suid_dumpable(value as u8); }
pub(super) fn get_ptrace_scope() -> i64 { sched::yama::scope() as i64 }
/// A REFUSED write must report EINVAL, not silently succeed: a hardening
/// script that lowers `ptrace_scope` and reads back a success it did not get
/// would believe it had relaxed a restriction that is still in force.
pub(super) fn set_ptrace_scope(value: i64) -> Result<(), ()> {
    if sched::yama::set_scope(value) { Ok(()) } else { Err(()) }
}
/// `net.core.rmem_max` / `net.core.wmem_max` bind to the ONE pair of ceilings
/// `SO_RCVBUF` / `SO_SNDBUF` clamp against, so the leaf and the option can
/// never disagree.
/// `net.core.{r,w}mem_default` bind to the ONE pair of buffer sizes every new
/// socket is seeded from, so the leaf can never disagree with what a socket
/// reports through `SO_RCVBUF` / `SO_SNDBUF` right after creation.
pub(super) fn get_rmem_default() -> i64 { net::sysctl::rmem_default() as i64 }
pub(super) fn set_rmem_default(value: i64) { net::sysctl::set_rmem_default(value) }
pub(super) fn get_wmem_default() -> i64 { net::sysctl::wmem_default() as i64 }
pub(super) fn set_wmem_default(value: i64) { net::sysctl::set_wmem_default(value) }
/// `net.ipv4.tcp_{w,r}mem` bind to the per-namespace window a new TCP socket
/// takes its buffers from.
pub(super) fn tcp_wmem(ns: &network_namespace::NetworkNamespaceRef) -> [i64; 3] {
    net::sysctl::tcp_buf_window(ns, false)
}
pub(super) fn set_tcp_wmem(ns: &network_namespace::NetworkNamespaceRef, w: [i64; 3]) -> Result<(), ()> {
    net::sysctl::set_tcp_buf_window(ns, false, w)
}
pub(super) fn tcp_rmem(ns: &network_namespace::NetworkNamespaceRef) -> [i64; 3] {
    net::sysctl::tcp_buf_window(ns, true)
}
pub(super) fn set_tcp_rmem(ns: &network_namespace::NetworkNamespaceRef, w: [i64; 3]) -> Result<(), ()> {
    net::sysctl::set_tcp_buf_window(ns, true, w)
}
pub(super) fn get_rmem_max() -> i64 { net::sysctl::rmem_max() as i64 }
pub(super) fn set_rmem_max(value: i64) { net::sysctl::set_rmem_max(value) }
pub(super) fn get_mld_max_msf() -> i64 { net::sysctl::mld_max_msf() }
pub(super) fn set_mld_max_msf(value: i64) { net::sysctl::set_mld_max_msf(value) }
pub(super) fn get_wmem_max() -> i64 { net::sysctl::wmem_max() as i64 }
pub(super) fn set_wmem_max(value: i64) { net::sysctl::set_wmem_max(value) }
pub(super) fn net_int(namespace: &network_namespace::NetworkNamespaceRef, key: usize) -> Result<i64, ()> {
    let key = net::net_ns::NetSysctlKey::from_usize(key).ok_or(())?;
    net::sysctl::value(namespace, key).ok_or(())
}
pub(super) fn set_net_int(namespace: &network_namespace::NetworkNamespaceRef,
    key: usize, value: i64) -> Result<(), ()>
{
    let key = net::net_ns::NetSysctlKey::from_usize(key).ok_or(())?;
    net::sysctl::set_value(namespace, key, value)
}
pub(super) fn local_port_range(namespace: &network_namespace::NetworkNamespaceRef) -> Result<(u16, u16), ()> {
    let range = net::ephemeral::range_for(namespace).ok_or(())?;
    Ok((range.start, range.end))
}
pub(super) fn set_local_port_range(namespace: &network_namespace::NetworkNamespaceRef,
    start: u16, end: u16) -> Result<(), ()>
{
    net::ephemeral::set_range_for(namespace, start, end)
}
pub(super) fn ping_group_range(namespace: &network_namespace::NetworkNamespaceRef)
    -> Result<(u32, u32), ()>
{
    net::ping::group_range_for(namespace).ok_or(())
}
pub(super) fn set_ping_group_range(namespace: &network_namespace::NetworkNamespaceRef,
    low: u32, high: u32) -> Result<(), ()>
{
    net::ping::set_group_range_for(namespace, low, high)
}
pub(super) fn unprivileged_port_start(namespace: &network_namespace::NetworkNamespaceRef,
    _key: usize) -> Result<i64, ()>
{
    net::ephemeral::unprivileged_start_for(namespace).map(i64::from).ok_or(())
}
pub(super) fn set_unprivileged_port_start(namespace: &network_namespace::NetworkNamespaceRef,
    _key: usize, value: i64) -> Result<(), ()>
{
    net::ephemeral::set_unprivileged_start_for(namespace, value as u16)
}


/// `net.ipv4.tcp_fastopen_key` binds to the namespace's own keys. A namespace
/// that has drawn none still reads as one all-zero key, so the file always
/// names the shape of the value.
pub(super) fn tcp_fastopen_key(ns: &network_namespace::NetworkNamespaceRef) -> alloc::vec::Vec<u8> {
    net::tcp_fastopen::format_hex(net::tcp_fastopen::ns_keys(ns).as_ref())
}
pub(super) fn set_tcp_fastopen_key(ns: &network_namespace::NetworkNamespaceRef,
    src: &[u8]) -> Result<(), ()>
{
    let ctx = net::tcp_fastopen::parse_hex(src).ok_or(())?;
    net::tcp_fastopen::set_ns_keys(ns, ctx);
    Ok(())
}
