//! `get_next_ino` (Linux `fs/inode.c`) — the global anonymous-inode number
//! allocator for pseudo inodes (pipes/sockets/eventfd/anon_inode). Before this
//! there was no central allocator (grep get_next_ino = nothing), so pseudo
//! inodes could collide on `(s_dev, i_ino)` or hand out `0` (which `getdents`
//! treats as "no entry"). This proves: consecutive allocations are strictly
//! increasing and never `0`. Global state ⇒ SERIAL-guarded.

use std::sync::{Mutex, MutexGuard};

use vfs::inode::get_next_ino;

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
