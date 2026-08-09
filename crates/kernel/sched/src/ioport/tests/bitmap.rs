use crate::ioport::bitmap::{IoBitmap, IO_BITMAP_BITS, IO_BITMAP_BYTES, IO_BITMAP_LONGS};

/// A fresh map denies everything, and its byte image is the all-ones the TSS
/// window expects. A zeroed map would permit every port the moment it was
/// installed — the whole point of the deny-all start.
#[test]
fn a_fresh_map_denies_every_port() {
    let m = IoBitmap::denied_all();
    assert_eq!(m.bytes().len(), IO_BITMAP_BYTES);
    assert!(m.bytes().iter().all(|b| *b == 0xff));
    for p in [0u64, 1, 0x3f8, IO_BITMAP_BITS - 1] { assert!(!m.permits(p), "port {p}"); }
    assert_eq!(m.recompute_max(), None, "nothing permitted ⇒ no map worth keeping");
}

/// `turn_on` clears exactly the requested ports and nothing on either side of
/// the range. The neighbours are the assertion that matters: an off-by-one
/// here silently hands out a port nobody asked for.
#[test]
fn set_range_permits_exactly_the_requested_ports() {
    let mut m = IoBitmap::denied_all();
    m.set_range(0x3f8, 8, true);
    assert!(!m.permits(0x3f7), "the port below the range must stay denied");
    for p in 0x3f8..0x400 { assert!(m.permits(p), "port {p:#x} was granted"); }
    assert!(!m.permits(0x400), "the port above the range must stay denied");

    // And withdrawing puts them back.
    m.set_range(0x3f8, 8, false);
    for p in 0x3f8..0x400 { assert!(!m.permits(p), "port {p:#x} was withdrawn"); }
}

/// Ranges that straddle word boundaries are where a word-at-a-time edit goes
/// wrong. Grant one port on each side of every boundary the range crosses.
#[test]
fn set_range_crosses_word_boundaries() {
    let mut m = IoBitmap::denied_all();
    m.set_range(63, 130, true);
    assert!(!m.permits(62));
    for p in 63..193 { assert!(m.permits(p), "port {p}"); }
    assert!(!m.permits(193));
}

/// The max-byte window is what the TSS copy is sized by. It must cover the
/// LAST permitted port: a window that stops short leaves the tail of the
/// grant unpublished, so a legitimately granted high port faults.
#[test]
fn max_covers_the_highest_permitted_port() {
    let mut m = IoBitmap::denied_all();
    m.set_range(0, 1, true);
    assert_eq!(m.recompute_max(), Some(8), "one word carries a permit ⇒ 8 bytes");

    let mut m = IoBitmap::denied_all();
    m.set_range(IO_BITMAP_BITS - 1, 1, true);
    assert_eq!(m.recompute_max(), Some((IO_BITMAP_LONGS * 8) as u32),
               "a permit in the top word needs the whole map published");

    let mut m = IoBitmap::denied_all();
    m.set_range(64, 1, true); // first bit of word 1
    assert_eq!(m.recompute_max(), Some(16));
}

/// Withdrawing the last permitted port takes the map back to "nothing
/// permitted", which is the signal to drop it entirely rather than carry an
/// all-denied 8 KiB image through every context switch.
#[test]
fn withdrawing_everything_reports_no_remaining_window() {
    let mut m = IoBitmap::denied_all();
    m.set_range(0x60, 2, true);
    assert!(m.recompute_max().is_some());
    m.set_range(0x60, 2, false);
    assert_eq!(m.recompute_max(), None);
}

/// Ports outside the 16-bit space are never permitted, whatever was asked
/// for, and asking cannot walk off the allocation.
#[test]
fn ports_past_the_space_are_never_permitted() {
    let mut m = IoBitmap::denied_all();
    m.set_range(IO_BITMAP_BITS - 4, 64, true); // clamped
    assert!(m.permits(IO_BITMAP_BITS - 1));
    assert!(!m.permits(IO_BITMAP_BITS));
    assert!(!m.permits(u64::MAX));
}

/// Every edit gets a NEW revision, or a CPU holding the previous one would
/// skip the copy and keep enforcing the stale grant.
#[test]
fn restamp_moves_the_revision_forward() {
    let mut m = IoBitmap::denied_all();
    let a = m.sequence;
    m.restamp();
    assert_ne!(m.sequence, a);
    assert_ne!(m.sequence, 0, "zero is the never-copied sentinel and must never be issued");
}

/// A clone is an independent map: editing the copy must not move the
/// original's bits. This is what makes the fork copy-on-write safe.
#[test]
fn a_clone_is_independent() {
    let mut a = IoBitmap::denied_all();
    a.set_range(0x60, 1, true);
    let mut b = a.clone();
    b.set_range(0x64, 1, true);
    assert!(a.permits(0x60) && !a.permits(0x64), "the original must not gain the copy's port");
    assert!(b.permits(0x60) && b.permits(0x64));
}
