// Superblock pins: kernel-side users that hold a file OPEN on a filesystem and
// must be told to let go before that filesystem can be unmounted or resealed
// read-only.
//
// Without this a subsystem holding such a file wedges the mount: the reference
// keeps the superblock alive, so `umount` either fails or leaves a filesystem
// nobody can take down, and a read-only remount silently leaves a writer
// behind. The owner registers a pin naming the superblock and a callback; the
// two teardown paths fire every pin on that superblock and the owner closes
// its file. That is why the callback must never fail — it is a release, not a
// request.
//
// The registry lives here rather than in the owning subsystem because both
// firing sites are inside the VFS, which cannot call up into its dependents.
// Callbacks run with NO registry lock held, so an owner is free to take its own
// state lock (and to deregister itself) from inside one.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{MountTable as PinClass, Spinlock};

use crate::superblock::SuperBlock;

/// One registered pin. `cookie` is opaque to the VFS — the owner's own handle
/// for whatever it must close (for process accounting, the pid-namespace id).
struct Pin {
    sb_key: usize,
    kill:   fn(u64),
    cookie: u64,
}

static PINS: Spinlock<Vec<Pin>, PinClass> = Spinlock::new(Vec::new());

/// Identity of a superblock for pin purposes. Address of the allocation, which
/// is stable for the superblock's whole life and unique among live ones.
/// # C: O(1)
pub fn sb_key(sb: &Arc<SuperBlock>) -> usize { Arc::as_ptr(sb) as usize }

/// Identity of a superblock reached by reference rather than by `Arc`.
/// # C: O(1)
pub fn sb_key_ref(sb: &SuperBlock) -> usize { sb as *const SuperBlock as usize }

/// Register a pin on `sb_key`. A second registration with the same `cookie`
/// replaces the first, so an owner re-pointing its file at another filesystem
/// cannot leave a stale pin on the old one. # C: O(N_pins)
pub fn pin_insert(sb_key: usize, cookie: u64, kill: fn(u64)) {
    let mut g = PINS.lock();
    g.retain(|p| p.cookie != cookie);
    g.push(Pin { sb_key, kill, cookie });
}

/// Drop the pin registered under `cookie`, if any. Called by the owner once its
/// file is closed — including from inside its own kill callback. # C: O(N_pins)
pub fn pin_remove(cookie: u64) { PINS.lock().retain(|p| p.cookie != cookie); }

/// Fire every pin registered on `sb_key` and return how many ran. Each
/// callback is invoked with the registry lock DROPPED, so a callback may take
/// its owner's lock and deregister itself. # C: O(N_pins)
pub fn kill_sb_pins(sb_key: usize) -> usize {
    let doomed: Vec<(fn(u64), u64)> = {
        let g = PINS.lock();
        g.iter().filter(|p| p.sb_key == sb_key).map(|p| (p.kill, p.cookie)).collect()
    };
    for (kill, cookie) in &doomed { kill(*cookie); }
    doomed.len()
}

/// Whether any pin is registered on `sb_key`. # C: O(N_pins)
pub fn sb_has_pins(sb_key: usize) -> bool { PINS.lock().iter().any(|p| p.sb_key == sb_key) }

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU64, Ordering};

    static FIRED: AtomicU64 = AtomicU64::new(0);
    fn record(cookie: u64) { FIRED.fetch_add(cookie, Ordering::Relaxed); pin_remove(cookie); }

    /// A pin fires for its own superblock only, and deregisters itself from
    /// inside the callback — the shape every owner uses.
    #[test]
    fn a_pin_fires_once_for_its_own_superblock() {
        PINS.lock().clear();
        FIRED.store(0, Ordering::Relaxed);
        pin_insert(0x1000, 7, record);
        pin_insert(0x2000, 9, record);
        assert_eq!(kill_sb_pins(0x3000), 0, "an unrelated superblock fires nothing");
        assert_eq!(kill_sb_pins(0x1000), 1);
        assert_eq!(FIRED.load(Ordering::Relaxed), 7);
        assert!(!sb_has_pins(0x1000), "the callback deregistered itself");
        assert!(sb_has_pins(0x2000));
        // Firing the same superblock again is a no-op, so a double umount
        // cannot double-close the owner's file.
        assert_eq!(kill_sb_pins(0x1000), 0);
        assert_eq!(FIRED.load(Ordering::Relaxed), 7);
        PINS.lock().clear();
    }

    /// Re-registering a cookie MOVES the pin: the old superblock no longer
    /// holds it, so unmounting the file's previous filesystem does not close
    /// the file that has since moved elsewhere.
    #[test]
    fn re_registering_a_cookie_moves_the_pin() {
        PINS.lock().clear();
        FIRED.store(0, Ordering::Relaxed);
        pin_insert(0x1000, 5, record);
        pin_insert(0x2000, 5, record);
        assert_eq!(kill_sb_pins(0x1000), 0);
        assert_eq!(kill_sb_pins(0x2000), 1);
        assert_eq!(FIRED.load(Ordering::Relaxed), 5);
        PINS.lock().clear();
    }
}
