// The backend driven over a `Vec` standing in for the reserved region. The
// reboot is modelled by dropping every kernel structure and attaching a new
// backend to the same bytes — which is exactly what a warm reboot does.

use super::*;
use crate::hdr::parse_kmsg_hdr;
use alloc::vec;

const REGION: usize = 64 * 1024;
const RECORD: usize = 8 * 1024;
const CONSOLE: usize = 4096;

/// A region that outlives the backends attached to it, like real reserved
/// memory outlives the kernel that reserved it.
struct Ram(Vec<u8>);

impl Ram {
    fn new() -> Ram { Ram(vec![0u8; REGION]) }
    /// # SAFETY: the caller drops the returned backend before touching the
    /// backing vector again, so the region is never aliased.
    fn attach(&mut self, record: usize, console: usize) -> (Arc<RamBackend>, Vec<Record>) {
        let base = self.0.as_mut_ptr() as usize;
        let len = self.0.len();
        // SAFETY: `self` is borrowed mutably for the call, the span is a live
        // heap allocation of exactly `len` bytes, and the backend is the only
        // holder until it is dropped.
        let region = unsafe { RamRegion::new(base, len) };
        RamBackend::attach(region, record, console)
    }
}

#[test]
fn a_fresh_region_yields_no_records() {
    let mut ram = Ram::new();
    let (b, found) = ram.attach(RECORD, CONSOLE);
    assert!(found.is_empty());
    assert!(b.records().is_empty());
}

#[test]
fn a_dmesg_record_survives_a_reboot() {
    let mut ram = Ram::new();
    {
        let (b, _) = ram.attach(RECORD, CONSOLE);
        b.write_dmesg(1700, 250_000_000, b"Panic#1 Part1\nthe kernel log");
    }
    // The reboot: everything above is gone; only the bytes remain.
    let (_b, found) = ram.attach(RECORD, CONSOLE);
    assert_eq!(found.len(), 1);
    let r = &found[0];
    assert_eq!(r.id, RecordId { ty: RecordType::Dmesg, index: 0 });
    assert_eq!(r.sec, 1700);
    assert_eq!(r.nsec, 250_000_000);
    assert_eq!(r.body, b"Panic#1 Part1\nthe kernel log".to_vec());
}

#[test]
fn console_output_survives_a_reboot_with_no_crash_at_all() {
    let mut ram = Ram::new();
    {
        let (b, _) = ram.attach(RECORD, CONSOLE);
        b.write_console(b"[0.000] booting\n");
        b.write_console(b"[1.000] running\n");
    }
    let (_b, found) = ram.attach(RECORD, CONSOLE);
    let c = found.iter().find(|r| r.id.ty == RecordType::Console).expect("console record");
    assert_eq!(c.body, b"[0.000] booting\n[1.000] running\n".to_vec());
}

#[test]
fn successive_crashes_land_in_successive_zones() {
    let mut ram = Ram::new();
    {
        let (b, _) = ram.attach(RECORD, CONSOLE);
        b.write_dmesg(1, 0, b"first");
        b.write_dmesg(2, 0, b"second");
    }
    let (_b, mut found) = ram.attach(RECORD, CONSOLE);
    found.retain(|r| r.id.ty == RecordType::Dmesg);
    found.sort_by_key(|r| r.id);
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].body, b"first".to_vec());
    assert_eq!(found[1].body, b"second".to_vec());
    assert_eq!(found[1].id.index, 1);
}

#[test]
fn a_new_crash_after_a_reboot_does_not_overwrite_the_old_record() {
    let mut ram = Ram::new();
    {
        let (b, _) = ram.attach(RECORD, CONSOLE);
        b.write_dmesg(1, 0, b"from the first boot");
    }
    {
        let (b, found) = ram.attach(RECORD, CONSOLE);
        assert_eq!(found.len(), 1);
        b.write_dmesg(2, 0, b"from the second boot");
    }
    let (_b, mut found) = ram.attach(RECORD, CONSOLE);
    found.retain(|r| r.id.ty == RecordType::Dmesg);
    found.sort_by_key(|r| r.id);
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].body, b"from the first boot".to_vec());
    assert_eq!(found[1].body, b"from the second boot".to_vec());
}

#[test]
fn a_rewritten_zone_holds_only_the_newest_crash() {
    let mut ram = Ram::new();
    {
        let (b, _) = ram.attach(RECORD, CONSOLE);
        b.write_dmesg(1, 0, b"stale");
    }
    {
        // One dump zone only: the second crash must REPLACE the first, not
        // be appended after it, or the record would not begin with a header.
        let (b, _) = ram.attach(REGION - CONSOLE, CONSOLE);
        b.write_dmesg(2, 0, b"current");
    }
    let (_b, found) = ram.attach(REGION - CONSOLE, CONSOLE);
    let d: Vec<_> = found.iter().filter(|r| r.id.ty == RecordType::Dmesg).collect();
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].body, b"current".to_vec());
}

#[test]
fn erasing_a_record_frees_its_zone() {
    let mut ram = Ram::new();
    {
        let (b, _) = ram.attach(RECORD, CONSOLE);
        b.write_dmesg(1, 0, b"to be erased");
    }
    {
        let (b, found) = ram.attach(RECORD, CONSOLE);
        assert_eq!(found.len(), 1);
        b.erase(found[0].id).unwrap();
        assert!(b.records().is_empty());
    }
    // Gone across the reboot too, not merely hidden from this boot's view.
    let (_b, found) = ram.attach(RECORD, CONSOLE);
    assert!(found.is_empty());
}

#[test]
fn erasing_the_console_record_empties_the_console_zone() {
    let mut ram = Ram::new();
    let (b, _) = ram.attach(RECORD, CONSOLE);
    b.write_console(b"noise");
    let id = RecordId { ty: RecordType::Console, index: 0 };
    b.erase(id).unwrap();
    assert!(b.records().is_empty());
}

#[test]
fn erasing_a_zone_that_does_not_exist_is_refused() {
    let mut ram = Ram::new();
    let (b, _) = ram.attach(RECORD, CONSOLE);
    assert_eq!(b.erase(RecordId { ty: RecordType::Dmesg, index: 9999 }),
        Err(vfs::VfsError::Einval));
    assert_eq!(b.erase(RecordId { ty: RecordType::Ftrace, index: 0 }),
        Err(vfs::VfsError::Einval));
}

#[test]
fn a_zone_holding_bytes_this_kernel_did_not_write_is_discarded() {
    let mut ram = Ram::new();
    // Plausible-looking garbage where a record would be.
    for (i, b) in ram.0.iter_mut().enumerate() { *b = (i % 251) as u8; }
    let (b, found) = ram.attach(RECORD, CONSOLE);
    assert!(found.is_empty(), "garbage must not be published as a crash report");
    assert!(b.records().is_empty());
}

#[test]
fn a_record_whose_body_was_corrupted_is_not_published() {
    let mut ram = Ram::new();
    {
        let (b, _) = ram.attach(RECORD, CONSOLE);
        b.write_dmesg(1, 0, b"a report nobody should trust");
    }
    // A bit flips somewhere in the first zone's data.
    ram.0[crate::limits::ZONE_HDR_LEN + 40] ^= 0x20;
    let (_b, found) = ram.attach(RECORD, CONSOLE);
    assert!(found.iter().all(|r| r.id.ty != RecordType::Dmesg));
}

#[test]
fn a_record_longer_than_its_zone_still_begins_with_its_header() {
    let mut ram = Ram::new();
    {
        let (b, _) = ram.attach(RECORD, CONSOLE);
        let huge = vec![b'x'; RECORD * 2];
        b.write_dmesg(5, 0, &huge);
    }
    let (_b, found) = ram.attach(RECORD, CONSOLE);
    let d = found.iter().find(|r| r.id.ty == RecordType::Dmesg);
    // Either the record is readable with its header intact, or it is
    // discarded — never published headerless with a wrong timestamp.
    if let Some(r) = d { assert_eq!(r.sec, 5); }
}

#[test]
fn the_room_a_record_has_is_the_zone_minus_its_overhead() {
    let mut ram = Ram::new();
    let (b, _) = ram.attach(RECORD, CONSOLE);
    let room = b.dump_room();
    // Less than the zone, because the zone header and the record's own
    // timestamp line come out of it first.
    let zone = (REGION - CONSOLE) / ((REGION - CONSOLE) / RECORD);
    assert!(room > 0 && room < zone, "room {room} zone {zone}");
}

#[test]
fn a_region_with_no_dump_zone_records_nothing_and_does_not_fault() {
    let mut ram = Ram::new();
    let (b, _) = ram.attach(REGION * 4, 0);
    assert_eq!(b.dump_room(), 0);
    b.write_dmesg(1, 0, b"nowhere to put this");
    assert!(b.records().is_empty());
}

#[test]
fn a_written_record_carries_a_parseable_timestamp_line() {
    let mut ram = Ram::new();
    let (b, _) = ram.attach(RECORD, CONSOLE);
    b.write_dmesg(42, 7_000, b"body");
    // The on-media form is what a later boot parses, so assert on it.
    let raw = crate::zone::read_all(&ram.0[..RECORD]);
    let h = parse_kmsg_hdr(&raw).expect("a timestamp line");
    assert_eq!(h.sec, 42);
    assert_eq!(&raw[h.len..], b"body");
}

#[test]
fn the_console_record_is_the_previous_boots_log_not_this_ones() {
    // The console zone is appended to by THIS boot's own output and is small
    // enough to wrap within seconds, so a record read live would carry the
    // current boot's log under a name promising the previous one's.
    let mut ram = Ram::new();
    {
        let (b, _) = ram.attach(RECORD, CONSOLE);
        b.write_console(b"FIRST BOOT LOG\n");
    }
    let (b, found) = ram.attach(RECORD, CONSOLE);
    assert_eq!(found.iter().find(|r| r.id.ty == RecordType::Console).unwrap().body,
        b"FIRST BOOT LOG\n".to_vec());
    // This boot now prints enough to wrap the zone several times over.
    for _ in 0..8 { b.write_console(&vec![b'Z'; CONSOLE]); }
    let c = b.records().into_iter().find(|r| r.id.ty == RecordType::Console).unwrap();
    assert_eq!(c.body, b"FIRST BOOT LOG\n".to_vec(),
        "the mount must publish what was found at attach");
}

#[test]
fn erasing_the_console_record_drops_the_snapshot_too() {
    let mut ram = Ram::new();
    {
        let (b, _) = ram.attach(RECORD, CONSOLE);
        b.write_console(b"gone");
    }
    let (b, found) = ram.attach(RECORD, CONSOLE);
    assert_eq!(found.len(), 1);
    b.erase(RecordId { ty: RecordType::Console, index: 0 }).unwrap();
    assert!(b.records().is_empty(), "the file must not survive its own erase");
}
