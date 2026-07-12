// SIOCGSKNS — "get the network namespace of this socket" (linux/sockios.h).
// Split out of the ioctl dispatcher (docs/53 §0): the socket-netns fd install
// is its own concern, not a tty/block/evdev ioctl.
#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;
use alloc::string::String;

/// `SIOCGSKNS` (linux/sockios.h). Issued on ANY socket fd; Linux `sock_ioctl`
/// routes it to `open_related_ns(sock_net(sk), get_net_ns)`, returning an nsfs
/// fd (`O_RDONLY|O_CLOEXEC`) referring to the socket's network namespace.
pub const SIOCGSKNS: u64 = 0x894C;

/// Answer `ioctl(sock_fd, SIOCGSKNS)`: install a new fd referring to the network
/// namespace the socket belongs to.
///
/// systemd's `sd-device-monitor` (`src/libsystemd/sd-device/device-monitor.c`,
/// under `DEBUG_LOGGING`) does exactly this on its `NETLINK_KOBJECT_UEVENT`
/// socket, then `fstat`s the returned fd and compares `(st_dev,st_ino)` against
/// `/proc/1/ns/net` to warn if the uevent monitor is not in the host netns.
/// oxide returned `ENOTTY` for the ioctl, so udev logged "Unable to get network
/// namespace of udev netlink socket, unable to determine if we are in host
/// netns, ignoring: Inappropriate ioctl for device" on every udev worker.
///
/// oxide is single-netns per host, so the socket's netns is the caller's net
/// namespace. Build the same `/proc/<pid>/ns/net` NsInode `iget`/`ns_inode_for`
/// produces (identity is keyed only on `NsKind::Net` → stable `st_ino`
/// `0x7200_0006`; SB-less → `st_dev` 0), and install an fd to it with the
/// `O_CLOEXEC` slot flag Linux's `open_related_ns` sets. `fstat` on the fd
/// therefore succeeds (so udev does not abort monitor setup on the `goto fail`
/// path), and the reported identity equals what `/proc/1/ns/net` resolves to —
/// so once nsfs symlink-follow lands the udev host-netns compare is exact and
/// the diagnostic goes fully silent.
/// # C: O(1)
pub fn handle_siocgskns() -> i64 {
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let ns_inode = nscg::proc_ns::ns_inode_for(cur, nscg::proc_ns::NsKind::Net);
    // Detached dentry named "net" (Linux nsfs anon dentry): the fd is a pure
    // ns reference, never path-walked further.
    let dentry = vfs::Dentry::new(None, String::from("net"), ns_inode.clone());
    // O_RDONLY description; `mnt_id` 0 marks the anonymous (SB-less) nsfs inode.
    let file = vfs::File::new_at(
        ns_inode, dentry, vfs::OpenFlags::empty(), 0, crate::pathresolve::current_cred(),
    );
    // RLIMIT_NOFILE soft limit caps fd allocation (Linux `__alloc_fd`); over → EMFILE.
    // SAFETY: rlimits slot single-mutator per `13§5`; cur is the running task on this CPU.
    let nofile = unsafe { (*cur.rlimits.get())[sched::rlimit::rlim::NOFILE].0 } as usize;
    match fdt.alloc_limit(file, nofile) {
        Ok(n) => {
            // open_related_ns() returns the fd with O_CLOEXEC set.
            if let Err(e) = fdt.set_cloexec(n, true) { return -(e as i64); }
            n as i64
        }
        Err(e) => -(e as i64),
    }
}
