// The sequential-write rule, which is the whole reason a caller asks for a
// zone map. Each case is a placement a drive would accept or refuse, and a
// wrong answer here is data written where the drive will not take it.

use super::*;

fn seq(start: u64, len: u64, cap: u64, wp: Option<u64>, cond: ZoneCond) -> Zone {
    Zone { start_block: start, len_blocks: len, capacity_blocks: cap,
           kind: ZoneType::SeqWriteRequired, wp_block: wp, cond }
}

fn conv(start: u64, len: u64) -> Zone {
    Zone { start_block: start, len_blocks: len, capacity_blocks: len,
           kind: ZoneType::Conventional, wp_block: None, cond: ZoneCond::NotWp }
}

/// A sequential zone takes a write at its write pointer and nowhere else.
/// Both neighbours of the pointer are refusals, not near-misses.
#[test]
fn a_sequential_zone_takes_a_write_only_at_its_pointer() {
    let z = seq(1000, 128, 128, Some(1040), ZoneCond::ImplicitOpen);
    assert!(z.accepts_write(1040, 8));
    assert!(!z.accepts_write(1039, 8), "one block behind the pointer");
    assert!(!z.accepts_write(1041, 8), "one block ahead of it");
    assert!(!z.accepts_write(1000, 8), "the start of a partly written zone");
}

/// A conventional zone takes a write anywhere inside itself, and nothing
/// outside it — the bound is the zone, not the pointer it does not have.
#[test]
fn a_conventional_zone_takes_a_write_anywhere_inside_itself() {
    let z = conv(0, 128);
    assert!(z.accepts_write(0, 128));
    assert!(z.accepts_write(64, 8));
    assert!(!z.accepts_write(120, 16), "past the end of the zone");
    assert!(!z.accepts_write(128, 1), "the next zone");
}

/// Capacity, not length, bounds a write. A short-capacity zone has a tail of
/// addresses that exist and can never be written, and a caller that used the
/// length would place data there.
#[test]
fn capacity_bounds_the_write_not_length() {
    let z = seq(0, 128, 125, Some(120), ZoneCond::ImplicitOpen);
    assert!(z.accepts_write(120, 5), "up to the capacity");
    assert!(!z.accepts_write(120, 6), "one block into the unwritable tail");
    let c = Zone { capacity_blocks: 125, ..conv(0, 128) };
    assert!(!c.accepts_write(124, 2), "the same tail on a conventional zone");
}

/// A full zone accepts nothing further, and its pointer sits at the end of
/// what was written — so the capacity bound is what refuses the write, and it
/// must not be reachable by naming that pointer.
#[test]
fn a_full_zone_accepts_nothing_further() {
    let z = seq(0, 128, 128, Some(128), ZoneCond::Full);
    assert!(!z.accepts_write(128, 1));
    assert!(!z.accepts_write(0, 1), "not at the start either");
    assert!(!z.accepts_write(127, 1), "nor at the last written block");
}

/// Neither can be written, whatever their pointer field once said.
#[test]
fn read_only_and_offline_zones_accept_nothing() {
    for cond in [ZoneCond::ReadOnly, ZoneCond::Offline] {
        let z = seq(0, 128, 128, Some(0), ZoneCond::Empty);
        let z = Zone { cond, ..z };
        assert!(!z.accepts_write(0, 8), "{cond:?}");
        let c = Zone { cond, ..conv(0, 128) };
        assert!(!c.accepts_write(0, 8), "conventional, {cond:?}");
    }
}

/// A sequential zone the drive gave no pointer for has nowhere a write could
/// legally go, and must not fall through to "anywhere".
#[test]
fn a_sequential_zone_with_no_pointer_accepts_nothing() {
    let z = seq(0, 128, 128, None, ZoneCond::Empty);
    assert!(!z.accepts_write(0, 8));
}

/// A sequentially-preferred zone is still sequential: the drive accepts an
/// out-of-order write by RELOCATING it, which silently moves data a caller
/// believed it had placed.
#[test]
fn a_preferred_zone_is_treated_as_sequential() {
    assert!(ZoneType::SeqWritePreferred.sequential());
    let z = Zone { kind: ZoneType::SeqWritePreferred, ..seq(0, 128, 128, Some(16), ZoneCond::Closed) };
    assert!(z.accepts_write(16, 8));
    assert!(!z.accepts_write(0, 8));
}

/// A length that overflows the address space is a refusal, never a wrap into
/// an apparently legal range.
#[test]
fn an_overflowing_length_is_refused() {
    let z = seq(0, 128, 128, Some(0), ZoneCond::Empty);
    assert!(!z.accepts_write(u64::MAX, 2));
    let c = conv(0, u64::MAX);
    assert!(!c.accepts_write(u64::MAX - 1, 4));
}
