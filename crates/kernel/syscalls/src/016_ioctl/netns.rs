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
/// The input owner was cloned from the resolved socket, so the nsfs inode and
/// returned fd retain that namespace even when caller membership differs.
/// # C: O(1)
pub fn handle_siocgskns(namespace: network_namespace::NetworkNamespaceRef) -> i64 {
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let ns_inode = nscg::net_ns_inode(namespace);
    // Detached dentry named "net" (Linux nsfs anon dentry): the fd is a pure
    // ns reference, never path-walked further.
    let dentry = vfs::Dentry::new(None, String::from("net"), ns_inode.clone());
    // O_RDONLY description; `mnt_id` 0 marks the anonymous (SB-less) nsfs inode.
    let file_cred = match crate::pathresolve::file_cred_for(&cur) {
        Some(cred) => cred, None => return -(Errno::Esrch.as_i32() as i64),
    };
    let file = vfs::File::new_at(ns_inode, dentry, vfs::OpenFlags::empty(), 0, file_cred);
    // RLIMIT_NOFILE soft limit caps fd allocation (Linux `__alloc_fd`); over → EMFILE.
    let nofile = cur.rlimit(sched::rlimit::rlim::NOFILE).0 as usize;
    match super::netns_fd::install(&fdt, file, nofile) {
        Ok(n) => n as i64,
        Err(e) => -(e as i64),
    }
}
