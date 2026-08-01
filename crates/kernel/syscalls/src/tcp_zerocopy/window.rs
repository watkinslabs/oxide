// The receive window `mmap(2)` on a TCP socket fd establishes, and the pages
// `TCP_ZEROCOPY_RECEIVE` publishes through it.
//
// Frame lifetime (the rule that makes this safe): every page installed here is
// a REFCOUNTED RAM frame from `alloc_object_frame`, and it reaches userspace
// through the fault path's `direct_frame` arm, which `inc_ref`s the frame per
// PTE — `munmap` and address-space teardown `dec_ref` it back. The window
// holds exactly one object reference per installed page and releases it when
// the page is displaced or the window drops. So a frame is freed only once BOTH
// the window has let it go AND every user mapping of it is gone.
//
// Never `PhysRange` / `remap_pfn_range`: that arm installs a PTE with no
// refcount and no mapcount, which is correct only for UNREFCOUNTED device MMIO.
// Backing refcounted RAM with it makes the mapping invisible to the frame's
// lifetime accounting, so the owner dropping its reference frees the page while
// userspace still maps it — a free-while-mapped UAF (CLAUDE.md Lessons §9).

use alloc::sync::Arc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use sync::{Spinlock, Socket as SockLockClass};
use syscall::errno::Errno;

/// One mapped receive window. Sparse: only the offsets a completed
/// `TCP_ZEROCOPY_RECEIVE` published carry a page, and every other offset faults
/// (Linux: a window page that no insert covered raises `SIGBUS`).
pub struct TcpZcWindow {
    /// The open socket file, pinned for the mapping's whole lifetime so the
    /// window cannot outlive the socket it belongs to.
    file: Arc<vfs::File>,
    /// Byte length the mapping was created with.
    len: u64,
    /// Page-aligned window offset -> owned frame.
    pages: Spinlock<BTreeMap<u64, u64>, SockLockClass>,
}

impl TcpZcWindow {
    /// # C: O(1)
    pub fn new(file: Arc<vfs::File>, len: u64) -> Arc<Self> {
        Arc::new(Self { file, len, pages: Spinlock::new(BTreeMap::new()) })
    }

    /// # C: O(1)
    pub fn len(&self) -> u64 { self.len }

    /// The frame published at page-aligned window offset `off`. # C: O(log N)
    pub fn frame(&self, off: u64) -> Option<u64> {
        if off >= self.len { return None; }
        self.pages.lock().get(&off).copied()
    }

    /// Publish `pa` at page-aligned window offset `off`, taking over the one
    /// object reference the caller allocated. Any frame already there is
    /// displaced and its object reference released — the displaced frame stays
    /// alive as long as a user PTE still holds its own reference.
    /// # C: O(log N)
    pub fn install(&self, off: u64, pa: u64) {
        let displaced = self.pages.lock().insert(off, pa);
        if let Some(old) = displaced { release_frame(old); }
    }

    /// Offsets currently carrying a page, lowest first. # C: O(N)
    pub fn published(&self) -> Vec<u64> { self.pages.lock().keys().copied().collect() }
}

impl Drop for TcpZcWindow {
    /// Release this window's object reference on every page it still holds.
    /// # C: O(N pages)
    fn drop(&mut self) {
        let pages: Vec<u64> = self.pages.lock().values().copied().collect();
        for pa in pages { release_frame(pa); }
    }
}

/// Drop one object reference on a window page. # C: O(1)
fn release_frame(pa: u64) {
    // SAFETY: `pa` was allocated by `alloc_object_frame` for this window and the window owns exactly that one object reference; user PTE references are counted separately and keep the frame alive past this drop.
    unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
}

impl vmm::FileBacking for TcpZcWindow {
    /// A window offset that no completed receive published carries no bytes,
    /// so there is nothing to read a page from — the fault becomes a fatal
    /// access rather than a zero page. # C: O(1)
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, vmm::FileBackingError> {
        Err(vmm::FileBackingError::Io)
    }

    fn size_hint(&self) -> u64 { self.len }

    fn ino(&self) -> u64 { self.file.inode().ino() }

    /// Both mapping types install the published frame directly; the fault path
    /// `inc_ref`s it, which is what ties the frame's lifetime to the PTE.
    /// # C: O(log N)
    fn direct_frame(&self, off: u64) -> Option<u64> { self.frame(off) }

    /// # C: O(log N)
    fn shared_frame(&self, off: u64) -> Result<Option<vmm::SharedFrame>, vmm::FileBackingError> {
        Ok(self.frame(off).map(|pa| vmm::SharedFrame { pa, map_ref_held: false }))
    }

    /// Lets the option recognise one of its own windows by identity, the way
    /// Linux recognises the mapping by its operations table. # C: O(1)
    fn as_object(&self) -> Option<&(dyn core::any::Any + 'static)> { Some(self) }
}

/// `mmap(2)` on a socket fd.
///
/// `None` = not a socket, so the ordinary file path owns the call. A TCP socket
/// gets a receive window; every other socket has no mapping operation at all,
/// which is a device-level refusal rather than an argument error. A window is
/// read-only and never executable: the pages published into it are the kernel's
/// own receive buffers, and a writable mapping of them would let a reader edit
/// the stream every other mapper sees.
/// # C: O(1)
pub fn mmap_backing(file: &Arc<vfs::File>, prot: u64, len: u64)
    -> Option<Result<Arc<dyn vmm::FileBacking>, i64>>
{
    use pmm::mmap_flags::{PROT_EXEC, PROT_WRITE};
    if file.inode().file_type() != vfs::FileType::Socket { return None; }
    let tcp = net::sock::inet_arc_from_inode(file.inode()).is_some_and(|s| matches!(*s.kind.lock(),
        net::sock::SockKind::TcpInit | net::sock::SockKind::TcpConn(_)
            | net::sock::SockKind::TcpListener(_)));
    if !tcp { return Some(Err(-(Errno::Enodev.as_i32() as i64))); }
    if prot & (PROT_WRITE | PROT_EXEC) != 0 { return Some(Err(-(Errno::Eperm.as_i32() as i64))); }
    Some(Ok(TcpZcWindow::new(file.clone(), len)))
}

/// The window covering `addr`, and the window offset `addr` sits at, for a
/// mapping whose backing is a receive window. # C: O(1)
pub fn window_of(backing: &Arc<dyn vmm::FileBacking>) -> Option<&TcpZcWindow> {
    backing.as_object()?.downcast_ref::<TcpZcWindow>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pmm::mmap_flags::{PROT_EXEC, PROT_READ, PROT_WRITE};
    use vmm::FileBacking;

    fn socket_file(sock: Arc<net::sock::InetSocket>) -> Arc<vfs::File> {
        let inode = net::sock::make_inet_socket_inode(sock);
        let dentry = vfs::Dentry::new(None, alloc::string::String::from("sock"), inode.clone());
        vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR)
    }

    fn tcp_file() -> Arc<vfs::File> {
        socket_file(Arc::new(net::sock::InetSocket::new_tcp()))
    }

    #[test]
    fn a_window_offset_with_no_published_page_has_no_frame_to_install() {
        let w = TcpZcWindow::new(tcp_file(), 4 * 4096);
        assert_eq!(w.frame(0), None);
        assert_eq!(w.direct_frame(0), None);
        assert_eq!(w.shared_frame(0), Ok(None));
        // No page means no bytes: the fault is fatal, never a zero page.
        assert_eq!(w.read_at(0, &mut [0u8; 8]), Err(vmm::FileBackingError::Io));
        assert!(w.published().is_empty());
    }

    #[test]
    fn an_offset_past_the_window_never_resolves() {
        let w = TcpZcWindow::new(tcp_file(), 4096);
        assert_eq!(w.frame(4096), None);
        assert_eq!(w.frame(u64::MAX), None);
        assert_eq!(w.size_hint(), 4096);
    }

    #[test]
    fn a_window_is_recognised_by_identity_not_by_address() {
        let w: Arc<dyn vmm::FileBacking> = TcpZcWindow::new(tcp_file(), 4096);
        assert!(window_of(&w).is_some());
        // An unrelated backing publishes no window identity.
        struct Other;
        impl vmm::FileBacking for Other {
            fn read_at(&self, _o: u64, _d: &mut [u8]) -> Result<usize, vmm::FileBackingError> { Ok(0) }
            fn size_hint(&self) -> u64 { 0 }
        }
        let other: Arc<dyn vmm::FileBacking> = Arc::new(Other);
        assert!(other.as_object().is_none());
        assert!(window_of(&other).is_none());
    }

    #[test]
    fn a_window_pins_its_socket_until_the_last_mapping_drops() {
        let sock = Arc::new(net::sock::InetSocket::new_tcp());
        let weak = Arc::downgrade(&sock);
        let file = socket_file(sock.clone());
        let w = TcpZcWindow::new(file.clone(), 4096);
        let forked = w.clone();
        drop(file); drop(sock); drop(w);
        assert!(weak.upgrade().is_some(), "a live window retains the open socket");
        drop(forked);
        assert!(weak.upgrade().is_none(), "the final window drop releases it");
    }

    #[test]
    fn a_window_is_read_only_and_never_executable() {
        let file = tcp_file();
        assert!(mmap_backing(&file, PROT_READ, 4096).unwrap().is_ok());
        assert_eq!(mmap_backing(&file, PROT_READ | PROT_WRITE, 4096).unwrap().err(),
                   Some(-(Errno::Eperm.as_i32() as i64)));
        assert_eq!(mmap_backing(&file, PROT_READ | PROT_EXEC, 4096).unwrap().err(),
                   Some(-(Errno::Eperm.as_i32() as i64)));
    }

    #[test]
    fn only_a_tcp_socket_has_a_mapping_operation() {
        let udp = socket_file(Arc::new(net::sock::InetSocket::new_udp()));
        assert_eq!(mmap_backing(&udp, PROT_READ, 4096).unwrap().err(),
                   Some(-(Errno::Enodev.as_i32() as i64)));
    }
}
