//! `get_next_ino` (Linux `fs/inode.c`) — the anon-inode number allocator for
//! the pseudo families with no range of their own (pidfd, POSIX message
//! queues, the io_uring low half). Before it existed there was no central
//! allocator at all, so pseudo inodes could collide on `(s_dev, i_ino)` or hand
//! out `0` (which `getdents` treats as "no entry"). It then counted up from 1,
//! which walked straight through the console tty band and on through every
//! other low-space region — so a long-lived system eventually handed a pidfd a
//! number `/dev/tty1` already owned. It now draws from the range
//! `vfs::pseudo_ino` reserves for it. Global state ⇒ SERIAL-guarded.

use std::sync::{Mutex, MutexGuard};

use vfs::inode::get_next_ino;
use vfs::pseudo_ino::{CONSOLE_TTY, VFS_ANON};

static SERIAL: Mutex<()> = Mutex::new(());
fn guard() -> MutexGuard<'static, ()> { SERIAL.lock().unwrap_or_else(|e| e.into_inner()) }

/// Consecutive calls are strictly increasing and never `0` (`0` = reserved
/// "no inode").
#[test]
fn allocations_increase_and_skip_zero() {
    let _g = guard();
    let a = get_next_ino();
    let b = get_next_ino();
    let c = get_next_ino();
    assert_ne!(a, 0);
    assert_ne!(b, 0);
    assert_ne!(c, 0);
    assert!(b > a, "second allocation advances past the first");
    assert!(c > b, "third allocation advances past the second");
    assert_eq!(b, a + 1, "monotone step of one");
    assert_eq!(c, b + 1);
}

/// A burst of allocations are all distinct (no two pseudo inodes share a no.).
#[test]
fn burst_is_unique() {
    let _g = guard();
    let mut seen = std::collections::HashSet::new();
    for _ in 0..256 {
        let ino = get_next_ino();
        assert_ne!(ino, 0);
        assert!(seen.insert(ino), "duplicate ino {ino} handed out");
    }
}

/// Every number comes out of the anon range, so it can never be a number some
/// other owner minted — the counter used to start at 1 and walk through them.
#[test]
fn allocations_stay_inside_the_anon_region() {
    let _g = guard();
    for _ in 0..4096 {
        let ino = get_next_ino() as u64;
        assert!(VFS_ANON.contains(ino), "{ino:#x} left the vfs-anon region");
        assert!(!CONSOLE_TTY.contains(ino), "{ino:#x} is a console tty number");
    }
}

/// Driving the allocator past the range's length wraps inside it rather than
/// running into the owner declared above.
#[test]
fn the_counter_wraps_inside_its_region() {
    assert_eq!(VFS_ANON.at(VFS_ANON.len()), VFS_ANON.start());
    assert!(VFS_ANON.contains(VFS_ANON.at(VFS_ANON.len() - 1)));
    assert!(VFS_ANON.contains(VFS_ANON.at(u64::MAX)));
    // The whole range fits in the `u32` the allocator returns, so the wrap is
    // the region's, not the integer's.
    assert!(VFS_ANON.end() <= u32::MAX as u64);
}
