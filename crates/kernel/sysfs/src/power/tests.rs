use super::*;
use alloc::vec::Vec;

/// Every `power::Error` variant, exhaustively — a match arm added in
/// `map_err` for a variant that does not exist here would be dead code, and
/// one dropped from `map_err` for a variant still listed here fails to build.
const ALL_ERRORS: [power::Error; 11] = [
    power::Error::Inval, power::Error::Perm, power::Error::Io, power::Error::Busy,
    power::Error::Nosys, power::Error::Opnotsupp, power::Error::Again,
    power::Error::Intr, power::Error::Nomem, power::Error::Nodata,
    power::Error::Nospc,
];

/// `map_err` is total and injective: every input has a distinct `VfsError`
/// outputs. A collision here would mean two power-crate errors surface as
/// the same errno to userspace.
#[test]
fn error_mapping_is_total_and_distinct() {
    let mapped: Vec<VfsError> = ALL_ERRORS.iter().map(|e| map_err(*e)).collect();
    for i in 0..mapped.len() {
        for j in (i + 1)..mapped.len() {
            assert_ne!(mapped[i], mapped[j], "{:?} and {:?} map to the same VfsError",
                ALL_ERRORS[i], ALL_ERRORS[j]);
        }
    }
}

/// Every `ATTRS`/`STATS_ATTRS` index gets one distinct ino, and the two
/// blocks never overlap. Counted with a multiset (sort + adjacent-equal
/// scan), not a set, so a genuine duplicate cannot be silently deduped away.
#[test]
fn every_registered_ino_is_distinct() {
    let mut inos: Vec<u64> = Vec::new();
    for i in 0..sysfs_api::ATTRS.len() { inos.push(POWER_ATTR_BASE + i as u64); }
    for i in 0..sysfs_api::STATS_ATTRS.len() { inos.push(POWER_STATS_ATTR_BASE + i as u64); }
    let expected = sysfs_api::ATTRS.len() + sysfs_api::STATS_ATTRS.len();
    assert_eq!(inos.len(), expected, "one ino must be pushed per attribute");
    inos.sort_unstable();
    for w in inos.windows(2) {
        assert_ne!(w[0], w[1], "duplicate ino {:#x} across /sys/power attributes", w[0]);
    }
}

/// Power attributes share the sysfs superblock with device classes.  Their
/// inode blocks must therefore be globally unique: `iget` keys solely on
/// `i_ino`, and an alias can turn a regular power attribute into a cached
/// class directory depending on lookup order.
#[test]
fn power_inode_blocks_do_not_alias_device_classes() {
    const BLOCK_MASK: u64 = 0xffff_0000;
    let power_blocks = [POWER_ATTR_BASE, POWER_STATS_ATTR_BASE];
    let device_class_blocks = [
        crate::ids::POWER_SUPPLY_CLASS,
        crate::ids::BACKLIGHT_CLASS,
        crate::ids::THERMAL_CLASS,
    ];
    for power in power_blocks {
        for class in device_class_blocks {
            assert_ne!(power & BLOCK_MASK, class & BLOCK_MASK,
                "power inode block {:#x} aliases device-class block {:#x}",
                power & BLOCK_MASK, class & BLOCK_MASK);
        }
    }
}

/// Every name in `ATTRS` reads back non-empty bytes through the same
/// `SysfsOps` wrapper `init()` registers.
#[test]
fn every_power_attr_reads_nonempty() {
    let ops = PowerOps;
    for a in sysfs_api::ATTRS.iter() {
        let body = ops.show(a.name).unwrap_or_else(|e| panic!("show {} failed: {:?}", a.name, e));
        assert!(!body.is_empty(), "{} rendered empty body", a.name);
    }
}

/// Every name in `STATS_ATTRS` reads back non-empty bytes through the same
/// `SysfsOps` wrapper `init()` registers, and stats stay read-only.
#[test]
fn every_stats_attr_reads_nonempty_and_is_read_only() {
    let ops = StatsOps;
    for name in sysfs_api::STATS_ATTRS.iter() {
        let body = ops.show(name).unwrap_or_else(|e| panic!("show {} failed: {:?}", name, e));
        assert!(!body.is_empty(), "{} rendered empty body", name);
    }
    assert_eq!(ops.store("success", b"0"), Err(VfsError::Erofs));
}

/// A name absent from both `ATTRS` and `STATS_ATTRS` is `Nodata`/`Enodata`
/// through both wrappers, never a silent empty success.
#[test]
fn unknown_attr_name_is_enodata() {
    assert_eq!(PowerOps.show("no_such_attr"), Err(VfsError::Enodata));
    assert_eq!(StatsOps.show("no_such_attr"), Err(VfsError::Enodata));
}
