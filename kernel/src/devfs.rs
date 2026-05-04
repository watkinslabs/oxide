// Minimal devfs registry per docs/16 + docs/19. v1 stand-in
// for the full VFS / mount-tree work: a flat `&str → InodeRef`
// table holding the kernel's char devices. `sys_open` looks up
// here. Real VFS (path resolution, dentry cache, multi-mount,
// ext-style filesystems) lands as docs/16 fully wires.
//
// Registered at boot:
//   /dev/console   — kernel console, aliases the foreground VT
//   /dev/tty       — controlling terminal (per-process); v1 routes
//                    to the same ConsoleInode
//   /dev/tty0      — foreground VT alias (real Linux: dynamic; v1: tty1)
//   /dev/tty1..tty6 — distinct VT slots (v1: all share ConsoleInode)
//   /dev/ttyS0     — first serial line (v1: ConsoleInode)
//
// Once distinct VT instances + foreground tracking land, tty0
// resolves dynamically and tty1..6 each carry their own buffer.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Spinlock, TaskList as TaskListClass};
use vfs::{Inode, InodeRef};

/// Flat path → inode map. v1 single-CPU UP with `TaskList` lock
/// class (matching the rank used elsewhere for boot-time
/// kernel-state registries).
static REGISTRY: Spinlock<Vec<(&'static str, InodeRef)>, TaskListClass>
    = Spinlock::new(Vec::new());

/// Register a path → inode mapping. Idempotent: re-registering
/// the same path replaces the prior entry (last writer wins).
/// # SAFETY: caller is the boot path; single-CPU pre-init.
/// # C: O(N)
pub fn register(path: &'static str, inode: InodeRef) {
    let mut g = REGISTRY.lock();
    if let Some(slot) = g.iter_mut().find(|(p, _)| *p == path) {
        slot.1 = inode;
    } else {
        g.push((path, inode));
    }
}

/// Look up a path. Returns `Some(inode)` on hit.
/// # C: O(N)
pub fn lookup(path: &str) -> Option<InodeRef> {
    let g = REGISTRY.lock();
    g.iter().find(|(p, _)| *p == path).map(|(_, i)| Arc::clone(i))
}

/// Boot-time devfs population per docs/19. Registers the v1
/// console + tty char devices. Re-runnable: subsequent calls are
/// no-ops because re-registration is idempotent.
///
/// All v1 entries share one `ConsoleInode` instance — the
/// foreground-VT alias semantics + per-VT buffer separation land
/// once a real char-device dispatch table exists.
/// # SAFETY: caller is the boot path; single-CPU pre-init.
/// # C: O(1)
pub fn init() {
    let console: InodeRef = Arc::new(crate::dev_console::ConsoleInode);
    register("/dev/console", Arc::clone(&console));
    register("/dev/tty",     Arc::clone(&console));
    register("/dev/tty0",    Arc::clone(&console));
    register("/dev/tty1",    Arc::clone(&console));
    register("/dev/tty2",    Arc::clone(&console));
    register("/dev/tty3",    Arc::clone(&console));
    register("/dev/tty4",    Arc::clone(&console));
    register("/dev/tty5",    Arc::clone(&console));
    register("/dev/tty6",    Arc::clone(&console));
    register("/dev/ttyS0",   console);

    // P3-04 misc char devices.
    register("/dev/null",    Arc::new(crate::dev_misc::NullInode)   as InodeRef);
    register("/dev/zero",    Arc::new(crate::dev_misc::ZeroInode)   as InodeRef);
    register("/dev/full",    Arc::new(crate::dev_misc::FullInode)   as InodeRef);
    let rand: InodeRef = Arc::new(crate::dev_misc::RandomInode);
    register("/dev/random",  Arc::clone(&rand));
    register("/dev/urandom", rand);
}

/// Read a NUL-terminated string from user memory at `ptr`,
/// bounded at `max` bytes. Returns the slice (trimmed of NUL)
/// borrowed against the user page. Caller asserts the user page
/// is mapped + CR3 is the calling task's AS.
/// # SAFETY: ptr in user range; user page mapped; CPL=0 reads
/// pass through user mappings.
/// # C: O(strlen)
pub unsafe fn read_user_cstr<'a>(ptr: u64, max: usize) -> Option<&'a [u8]> {
    if ptr == 0 || ptr >= hal::USER_VA_END { return None; }
    let mut len = 0;
    while len < max {
        // SAFETY: ptr+len < ptr+max ≤ USER_VA_END (caller's responsibility for mapped page); 1-byte read.
        let b = unsafe { core::ptr::read_volatile((ptr + len as u64) as *const u8) };
        if b == 0 { break; }
        len += 1;
    }
    if len == 0 { return Some(&[]); }
    // SAFETY: same range; we've just probed every byte.
    Some(unsafe { core::slice::from_raw_parts(ptr as *const u8, len) })
}
