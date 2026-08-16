//! The records a name becomes, under both naming rules.


use syscall::errno::Errno;

use crate::dirent::{checksum, Record, ATTR_ARCH, ATTR_DIR, ATTR_EXT, ATTR_HIDDEN,
                    LAST_LONG_ENTRY};
use crate::namei::build_group;
use crate::opts::Options;
use crate::time::FatTime;

/// A reading with all three fields distinct, so a field written from the wrong
/// one is visible.
fn when() -> FatTime { FatTime { time: 0x4a3c, date: 0x5123, cs: 137 } }

fn nothing_exists(_: &[u8; 11]) -> bool { false }

/// An 8.3-legal uppercase name needs no long-name slots at all: it IS the
/// name, and the entry costs one record.
#[test]
fn an_uppercase_short_name_needs_one_record() {
    let o = Options::vfat();
    let g = build_group("HELLO.TXT", false, 0, when(), &o, 1, &mut nothing_exists).unwrap();
    assert_eq!(g.slots(), 1);
    assert_eq!(&g.raw_name, b"HELLO   TXT");
}

/// A name that does not spell itself in 8.3 gets slots, and every slot carries
/// the checksum of the eleven bytes the short entry ended up with. A slot with
/// the wrong checksum is discarded by every reader, so the name would come
/// back as its alias.
#[test]
fn a_long_name_gets_slots_tied_by_the_checksum() {
    let o = Options::vfat();
    let g = build_group("A Long File Name.txt", false, 0, when(), &o, 1, &mut nothing_exists)
        .unwrap();
    assert!(g.slots() > 1);
    let sum = checksum(&g.raw_name);
    for slot in &g.records[..g.slots() - 1] {
        assert_eq!(slot[11], ATTR_EXT);
        assert_eq!(slot[13], sum);
    }
}

/// The slots are stored in reverse, so the FIRST record on disk is the one
/// marked last and carrying the highest ordinal, and the ordinals count down
/// to one immediately before the short entry.
#[test]
fn the_slots_are_written_in_reverse_with_the_marker_first() {
    let o = Options::vfat();
    let g = build_group("A Long File Name Needing Three Slots.txt", false, 0, when(), &o, 1,
                        &mut nothing_exists).unwrap();
    let longs = g.slots() - 1;
    assert!(longs >= 3);
    assert_eq!(g.records[0][0], longs as u8 | LAST_LONG_ENTRY);
    for (i, slot) in g.records[..longs].iter().enumerate() {
        assert_eq!(slot[0] & !LAST_LONG_ENTRY, (longs - i) as u8);
    }
}

/// The short entry is LAST. Written first, it would publish the file under its
/// alias with a run of slots after it belonging to nothing.
#[test]
fn the_short_entry_is_the_last_record() {
    let o = Options::vfat();
    let g = build_group("Another Long Name.txt", false, 0, when(), &o, 1, &mut nothing_exists)
        .unwrap();
    let short = Record::parse(g.short_record()).expect("a short entry");
    assert_eq!(short.short.raw_name, g.raw_name);
    assert_eq!(short.short.attr, ATTR_ARCH);
}

/// All three readings come from ONE instant, at the granularity each field
/// has: creation keeps its centiseconds, modification does not, and access is
/// a date with no time.
#[test]
fn one_reading_stamps_all_three_fields() {
    let o = Options::vfat();
    let g = build_group("STAMP.TXT", false, 0, when(), &o, 1, &mut nothing_exists).unwrap();
    let r = Record::parse(g.short_record()).unwrap();
    assert_eq!(r.times.create, when());
    assert_eq!(r.times.modify, FatTime { time: when().time, date: when().date, cs: 0 });
    assert_eq!(r.times.access_date, when().date);
}

/// The 8.3-only type writes NONE of the extra fields. They belong to the
/// long-name format, and a reader of the older one may use those bytes for
/// something else.
#[test]
fn the_short_only_type_writes_no_creation_or_access_field() {
    let o = Options::msdos();
    let g = build_group("STAMP.TXT", false, 0, when(), &o, 1, &mut nothing_exists).unwrap();
    let r = Record::parse(g.short_record()).unwrap();
    assert_eq!(g.slots(), 1);
    assert_eq!(r.times.create, FatTime::default());
    assert_eq!(r.times.access_date, 0);
    assert_eq!(r.times.modify, FatTime { time: when().time, date: when().date, cs: 0 });
}

/// A directory's record carries the directory attribute and the cluster its
/// contents begin at, and a size of zero whatever those contents hold.
#[test]
fn a_directorys_record_names_its_cluster_and_reports_no_size() {
    let o = Options::vfat();
    let g = build_group("SUB", true, 77, when(), &o, 1, &mut nothing_exists).unwrap();
    let r = Record::parse(g.short_record()).unwrap();
    assert_eq!(r.short.attr, ATTR_DIR);
    assert_eq!(r.short.cluster, 77);
    assert_eq!(r.short.size, 0);
}

/// On the 8.3-only type a leading dot is not a character: it becomes the
/// hidden attribute, and only when the dot actually disappeared.
#[test]
fn a_leading_dot_becomes_the_hidden_attribute() {
    let mut o = Options::msdos();
    o.dots_ok = true;
    let g = build_group(".profile", false, 0, when(), &o, 1, &mut nothing_exists).unwrap();
    let r = Record::parse(g.short_record()).unwrap();
    assert_eq!(r.short.attr & ATTR_HIDDEN, ATTR_HIDDEN);
    assert_eq!(&g.raw_name, b"PROFILE    ");
    // A mount that refuses leading dots produces no hidden entry at all.
    let strict = Options::msdos();
    assert_eq!(build_group(".profile", false, 0, when(), &strict, 1, &mut nothing_exists)
                   .err(), Some(Errno::Einval));
}

/// A name already taken in its 8.3 form gets a numeric tail rather than
/// colliding, and the alias is what the slots are checksummed against.
#[test]
fn a_taken_alias_gets_a_numeric_tail() {
    let o = Options::vfat();
    let taken: [u8; 11] = *b"ALONGN~1TXT";
    let mut exists = |c: &[u8; 11]| *c == taken;
    let g = build_group("a long name.txt", false, 0, when(), &o, 1, &mut exists).unwrap();
    assert_ne!(g.raw_name, taken);
    assert_eq!(&g.raw_name[..8], b"ALONGN~2");
}

/// Trailing dots are not part of a name, and a name that is nothing but dots
/// is no name at all.
#[test]
fn trailing_dots_are_stripped_and_a_name_of_dots_is_refused() {
    let o = Options::vfat();
    let g = build_group("HELLO.TXT...", false, 0, when(), &o, 1, &mut nothing_exists).unwrap();
    assert_eq!(&g.raw_name, b"HELLO   TXT");
    assert_eq!(build_group("...", false, 0, when(), &o, 1, &mut nothing_exists).err(),
               Some(Errno::Enoent));
}

/// A name longer than the slots can address cannot be stored OR found again.
#[test]
fn a_name_past_the_slot_limit_is_refused() {
    let o = Options::vfat();
    let name: ::alloc::string::String = core::iter::repeat('a').take(256).collect();
    assert_eq!(build_group(&name, false, 0, when(), &o, 1, &mut nothing_exists).err(),
               Some(Errno::Enametoolong));
}
