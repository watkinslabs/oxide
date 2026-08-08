// cgroup2 mount options and the hierarchy-root flag bits they set.
//
// Unlike devpts or procfs, these are NOT per-mount: cgroup v2 has one default
// root, every mount of it shows the same flags, and a mount (or remount) that
// names one turns it on hierarchy-wide. A singleton is the reference shape
// here, not a defect.
//
// The values are bare flags — `mount -t cgroup2 -o nsdelegate` — and systemd
// passes `nsdelegate,memory_recursiveprot` on every boot of a modern distro.

extern crate alloc;
use alloc::string::String;

/// One cgroup2 hierarchy-root flag. The bit values are Linux's `CGRP_ROOT_*`
/// so a value read out of this word means the same thing it does there.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootFlag {
    /// `CGRP_ROOT_NS_DELEGATE` (1 << 3): cgroup-namespace boundaries are
    /// delegation boundaries. ENFORCED — see `crate::membership`.
    NsDelegate = 1 << 3,
    /// `CGRP_ROOT_FAVOR_DYNMODS` (1 << 4): trade fork/exit cost for cheaper
    /// migration. A locking-strategy choice with no user-visible semantics.
    FavorDynmods = 1 << 4,
    /// `CGRP_ROOT_MEMORY_LOCAL_EVENTS` (1 << 17): `memory.events` reports this
    /// cgroup's own counts rather than the subtree's. ENFORCED.
    MemoryLocalEvents = 1 << 17,
    /// `CGRP_ROOT_MEMORY_RECURSIVE_PROT` (1 << 18): distribute `memory.min`/
    /// `memory.low` protection recursively.
    MemoryRecursiveProt = 1 << 18,
    /// `CGRP_ROOT_MEMORY_HUGETLB_ACCOUNTING` (1 << 19): charge hugetlb pages to
    /// the memory controller.
    MemoryHugetlbAccounting = 1 << 19,
    /// `CGRP_ROOT_PIDS_LOCAL_EVENTS` (1 << 20): `pids.events` reports this
    /// cgroup's own counts rather than the subtree's.
    PidsLocalEvents = 1 << 20,
}

/// Every flag, in the order `cgroup_show_options` prints them — which is the
/// order they are declared in `cgroup2_fs_parameters`, so the rendered line
/// matches the reference byte for byte.
pub const ALL_FLAGS: &[(&str, RootFlag)] = &[
    ("nsdelegate",                RootFlag::NsDelegate),
    ("favordynmods",              RootFlag::FavorDynmods),
    ("memory_localevents",        RootFlag::MemoryLocalEvents),
    ("memory_recursiveprot",      RootFlag::MemoryRecursiveProt),
    ("memory_hugetlb_accounting", RootFlag::MemoryHugetlbAccounting),
    ("pids_localevents",          RootFlag::PidsLocalEvents),
];

/// The hierarchy root's flag word (Linux `cgrp_dfl_root.flags`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RootFlags(u64);

impl RootFlags {
    /// # C: O(1)
    pub const fn empty() -> Self { RootFlags(0) }
    /// # C: O(1)
    pub fn has(&self, f: RootFlag) -> bool { self.0 & (f as u64) != 0 }
    /// # C: O(1)
    pub fn set(&mut self, f: RootFlag) { self.0 |= f as u64; }
    /// # C: O(1)
    pub fn bits(&self) -> u64 { self.0 }
    /// # C: O(1)
    pub const fn from_bits(bits: u64) -> Self { RootFlags(bits) }

    /// Parse one option name into a flag. All six are BARE flags, so a value
    /// (`-o nsdelegate=1`) is as wrong as an unknown name — the reference's
    /// `fsparam_flag` refuses it before any value is examined. # C: O(1)
    pub fn apply(&mut self, key: &str, value: Option<&str>) -> Result<(), ()> {
        if value.is_some() { return Err(()); }
        match ALL_FLAGS.iter().find(|(n, _)| *n == key) {
            Some((_, f)) => { self.set(*f); Ok(()) }
            None => Err(()),
        }
    }

    /// Render for `/proc/mounts` (Linux `cgroup_show_options`): each set flag,
    /// in declaration order. # C: O(1)
    pub fn show_options(&self) -> String {
        let mut s = String::new();
        for (name, f) in ALL_FLAGS {
            if self.has(*f) { s.push(','); s.push_str(name); }
        }
        s
    }
}

/// Build a flag word from a `mount(2)` option BLOB.
///
/// The blob is where `mount(2)` puts the options; a constructor's parameter
/// slice carries only values that are pinned open files, which cgroup2 has
/// none of. # C: O(len data)
pub fn flags_for_mount(data: &str, pinned: &[vfs::fs::FsParameter])
    -> Result<RootFlags, vfs::VfsError>
{
    if !pinned.is_empty() { return Err(vfs::VfsError::Einval); }
    let mut flags = RootFlags::empty();
    for p in vfs::fs::split_monolithic(data) {
        let value = match &p.value {
            vfs::fs::FsValue::Flag => None,
            vfs::fs::FsValue::String(s) => Some(s.as_str()),
            _ => return Err(vfs::VfsError::Einval),
        };
        flags.apply(p.key.as_str(), value).map_err(|_| vfs::VfsError::Einval)?;
    }
    Ok(flags)
}

/// `cgroup2_fs_parameters`. Every name the reference accepts is here, because a
/// name omitted from the table fails a mount the reference allows — and a
/// container runtime that passes `memory_recursiveprot` would then not mount at
/// all. Which of them this kernel can act on is a separate question, recorded
/// per flag in the ledger and in `RootFlag`'s own documentation above.
pub static CGROUP2_PARAMS: &[vfs::fs::FsParamSpec] = &[
    vfs::fs::FsParamSpec::flag("nsdelegate"),
    vfs::fs::FsParamSpec::flag("favordynmods"),
    vfs::fs::FsParamSpec::flag("memory_localevents"),
    vfs::fs::FsParamSpec::flag("memory_recursiveprot"),
    vfs::fs::FsParamSpec::flag("memory_hugetlb_accounting"),
    vfs::fs::FsParamSpec::flag("pids_localevents"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_option_line_a_modern_distro_passes_sets_both_flags() {
        let f = flags_for_mount("nsdelegate,memory_recursiveprot", &[]).expect("systemd's line");
        assert!(f.has(RootFlag::NsDelegate));
        assert!(f.has(RootFlag::MemoryRecursiveProt));
        assert!(!f.has(RootFlag::MemoryLocalEvents));
    }

    /// The bit values are the reference's, so a flag word means the same thing
    /// here as the `CGRP_ROOT_*` word it mirrors.
    #[test]
    fn the_bit_values_are_the_references() {
        let mut f = RootFlags::empty();
        f.set(RootFlag::NsDelegate);
        assert_eq!(f.bits(), 1 << 3);
        f.set(RootFlag::PidsLocalEvents);
        assert_eq!(f.bits(), (1 << 3) | (1 << 20));
    }

    #[test]
    fn an_option_less_mount_sets_nothing() {
        let f = flags_for_mount("", &[]).expect("no options");
        assert_eq!(f, RootFlags::empty());
        assert_eq!(f.show_options(), "");
        for (_, flag) in ALL_FLAGS { assert!(!f.has(*flag)); }
    }

    /// They are bare flags: a value is refused, as `fsparam_flag` refuses it.
    #[test]
    fn a_flag_given_a_value_is_refused() {
        assert!(flags_for_mount("nsdelegate=1", &[]).is_err());
        assert!(flags_for_mount("memory_recursiveprot=yes", &[]).is_err());
    }

    #[test]
    fn an_unknown_option_is_refused() {
        for bad in ["nodev", "nsdelegat", "NSDELEGATE", "all"] {
            assert!(flags_for_mount(bad, &[]).is_err(), "{bad} must not mount");
        }
    }

    /// Every name the reference declares must mount — omitting one would fail a
    /// mount Linux accepts, which is worse than accepting a flag we cannot yet
    /// act on.
    #[test]
    fn every_name_the_reference_accepts_mounts_here() {
        for spec in CGROUP2_PARAMS {
            assert!(flags_for_mount(spec.name, &[]).is_ok(), "{} must mount", spec.name);
        }
        assert_eq!(CGROUP2_PARAMS.len(), ALL_FLAGS.len());
        for (name, _) in ALL_FLAGS {
            assert!(CGROUP2_PARAMS.iter().any(|s| s.name == *name),
                "{name} is parsed but not declared, so admission would refuse it");
        }
    }

    /// `cgroup_show_options` prints in declaration order, and what it prints
    /// parses back.
    #[test]
    fn the_shown_options_are_in_declaration_order_and_round_trip() {
        let f = flags_for_mount("pids_localevents,nsdelegate,memory_localevents", &[]).expect("parse");
        assert_eq!(f.show_options(), ",nsdelegate,memory_localevents,pids_localevents");
        assert_eq!(flags_for_mount(f.show_options().trim_start_matches(','), &[]), Ok(f));

        let all = flags_for_mount(
            "nsdelegate,favordynmods,memory_localevents,memory_recursiveprot,memory_hugetlb_accounting,pids_localevents",
            &[]).expect("all six");
        assert_eq!(all.show_options(),
            ",nsdelegate,favordynmods,memory_localevents,memory_recursiveprot,memory_hugetlb_accounting,pids_localevents");
    }

    /// The pinned slice is not an option source — the same trap that made the
    /// procfs options silently do nothing.
    #[test]
    fn options_come_from_the_blob_and_never_from_the_pinned_slice() {
        assert!(flags_for_mount("", &[vfs::fs::FsParameter::flag("nsdelegate")]).is_err());
    }
}
