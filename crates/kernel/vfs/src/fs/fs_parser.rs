// Filesystem parameter descriptions and the key lookup every mount option goes
// through, on both entry points: `fsconfig(2)`'s one-parameter-at-a-time path
// and `mount(2)`'s monolithic comma-separated data string.
//
// A filesystem publishes the parameters it accepts as a `&'static
// [FsParamSpec]`. A key absent from that table is not silently swallowed: the
// lookup declines it, the caller falls through to `source`, and the parameter
// is reported as unknown. That rejection is what makes a userspace
// option-support query truthful — a probe that sets an option and reads success
// as "supported" gets a real answer only if an unsupported option fails.
//
// Ungated: pure decision logic over `&str`, so it is covered by hosted tests.

use super::fs_context::{FsParameter, FsValue};

/// Value shape a parameter accepts. `Flag` is the reference's "no type"
/// spec — the parameter is a bare word and carries no value.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FsParamType {
    /// Bare word, no value: `noswap`, `nsdelegate`, `usrquota`.
    Flag,
    /// Free-form string: `errors=remount-ro`, `hidepid=invisible`.
    String,
    /// Unsigned decimal (or `0x`-prefixed) integer: `uid=`, `nr_inodes=`.
    U32,
    /// Unsigned integer read in octal: `mode=`, `rootmode=`.
    U32Oct,
    /// Byte count with a `k`/`m`/`g` suffix or a trailing `%`: `size=`.
    Size,
    /// Pathname: `usrjquota=`.
    Path,
    /// Descriptor number, from `FSCONFIG_SET_FD` or a decimal string: `fd=`.
    Fd,
}

impl FsParamType {
    /// A spec with no value is the reference's `is_flag`. # C: O(1)
    pub fn is_flag(self) -> bool { matches!(self, FsParamType::Flag) }
}

/// One accepted parameter.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct FsParamSpec {
    pub name: &'static str,
    pub ty:   FsParamType,
    /// `fs_param_neg_with_no`: the flag may also be written `no<name>`, which
    /// selects it negated.
    pub neg_with_no: bool,
}

impl FsParamSpec {
    /// # C: O(1)
    pub const fn flag(name: &'static str) -> Self {
        Self { name, ty: FsParamType::Flag, neg_with_no: false }
    }
    /// A flag that also accepts the `no`-prefixed spelling. # C: O(1)
    pub const fn flag_no(name: &'static str) -> Self {
        Self { name, ty: FsParamType::Flag, neg_with_no: true }
    }
    /// # C: O(1)
    pub const fn value(name: &'static str, ty: FsParamType) -> Self {
        Self { name, ty, neg_with_no: false }
    }
}

/// A matched parameter: which spec, and whether the `no` spelling selected it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct FsParamMatch {
    pub spec:    FsParamSpec,
    pub negated: bool,
}

/// `fs_lookup_key`: find `key` in `specs`.
///
/// A name may appear twice, once as a flag and once with a value (the
/// reference's `hidepid`, which takes either). The entry whose flag-ness agrees
/// with what the caller supplied wins; a disagreeing entry is remembered and
/// returned only if no agreeing one exists, so the caller reports "unexpected
/// value" rather than "unknown parameter" — the two are different errors even
/// though both end as EINVAL.
///
/// The `no<name>` spelling is only considered for a bare word, and only for a
/// spec that opted into it. # C: O(N_specs * len key)
pub fn lookup_key(specs: &[FsParamSpec], key: &str, want_flag: bool) -> Option<FsParamMatch> {
    let mut other: Option<FsParamSpec> = None;
    for spec in specs {
        if spec.name != key { continue; }
        if spec.ty.is_flag() == want_flag {
            return Some(FsParamMatch { spec: *spec, negated: false });
        }
        other = Some(*spec);
    }
    if want_flag {
        if let Some(stripped) = key.strip_prefix("no") {
            if !stripped.is_empty() {
                for spec in specs {
                    if spec.name == stripped && spec.neg_with_no {
                        return Some(FsParamMatch { spec: *spec, negated: true });
                    }
                }
            }
        }
    }
    other.map(|spec| FsParamMatch { spec, negated: false })
}

/// Outcome of admitting one parameter against a filesystem's table.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FsParamVerdict {
    /// The table describes this key and the supplied value shape fits.
    Accept(FsParamMatch),
    /// The table does not describe this key — the reference's `-ENOPARAM`. The
    /// caller falls through to `source` and then reports it unknown.
    Unknown,
    /// The key is described but was given the wrong value shape: a value on a
    /// flag, or a bare word where a value is required.
    WrongValueShape(FsParamSpec),
}

/// Admit one parameter against a table, checking only the value SHAPE. Range and
/// syntax checking of the value itself belongs to the filesystem, which is the
/// only party that knows what its numbers mean. # C: O(N_specs * len key)
pub fn admit(specs: &[FsParamSpec], param: &FsParameter) -> FsParamVerdict {
    let want_flag = matches!(param.value, FsValue::Flag);
    match lookup_key(specs, &param.key, want_flag) {
        None => FsParamVerdict::Unknown,
        Some(m) => {
            if m.spec.ty.is_flag() != want_flag {
                return FsParamVerdict::WrongValueShape(m.spec);
            }
            FsParamVerdict::Accept(m)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;

    const SPECS: &[FsParamSpec] = &[
        FsParamSpec::value("size", FsParamType::Size),
        FsParamSpec::value("mode", FsParamType::U32Oct),
        FsParamSpec::flag_no("swap"),
        FsParamSpec::flag("nsdelegate"),
        FsParamSpec::value("errors", FsParamType::String),
    ];

    #[test]
    fn a_key_outside_the_table_is_unknown_not_an_error() {
        // The distinction matters: Unknown falls through to `source`, which is
        // how a filesystem that takes no parameters still accepts a device.
        assert_eq!(admit(SPECS, &FsParameter::string("nosuchoption", "1")),
            FsParamVerdict::Unknown);
        assert_eq!(admit(SPECS, &FsParameter::flag("nosuchoption")),
            FsParamVerdict::Unknown);
        // A near-miss is still a miss.
        assert_eq!(admit(SPECS, &FsParameter::string("siz", "1")), FsParamVerdict::Unknown);
        assert_eq!(admit(SPECS, &FsParameter::string("sizes", "1")), FsParamVerdict::Unknown);
    }

    #[test]
    fn a_described_key_with_the_right_shape_is_accepted() {
        match admit(SPECS, &FsParameter::string("size", "64m")) {
            FsParamVerdict::Accept(m) => {
                assert_eq!(m.spec.ty, FsParamType::Size);
                assert!(!m.negated);
            }
            other => panic!("expected Accept, got {other:?}"),
        }
        match admit(SPECS, &FsParameter::flag("nsdelegate")) {
            FsParamVerdict::Accept(m) => assert!(m.spec.ty.is_flag()),
            other => panic!("expected Accept, got {other:?}"),
        }
    }

    // A value handed to a flag, or a bare word where a value belongs, is a
    // DIFFERENT failure from an unknown key — it must not fall through to
    // `source`, or `mount -o nsdelegate=1` would be read as a device name.
    #[test]
    fn the_wrong_value_shape_is_distinguished_from_an_unknown_key() {
        assert_eq!(admit(SPECS, &FsParameter::string("nsdelegate", "1")),
            FsParamVerdict::WrongValueShape(FsParamSpec::flag("nsdelegate")));
        assert_eq!(admit(SPECS, &FsParameter::flag("size")),
            FsParamVerdict::WrongValueShape(
                FsParamSpec::value("size", FsParamType::Size)));
    }

    #[test]
    fn the_no_spelling_selects_an_opted_in_flag_negated() {
        match admit(SPECS, &FsParameter::flag("noswap")) {
            FsParamVerdict::Accept(m) => {
                assert_eq!(m.spec.name, "swap");
                assert!(m.negated);
            }
            other => panic!("expected negated Accept, got {other:?}"),
        }
        match admit(SPECS, &FsParameter::flag("swap")) {
            FsParamVerdict::Accept(m) => assert!(!m.negated),
            other => panic!("expected Accept, got {other:?}"),
        }
        // A flag that did not opt in gets no `no` spelling.
        assert_eq!(admit(SPECS, &FsParameter::flag("nonsdelegate")), FsParamVerdict::Unknown);
        // `no` alone is not a negation of anything.
        assert_eq!(admit(SPECS, &FsParameter::flag("no")), FsParamVerdict::Unknown);
        // The `no` form is a bare-word spelling only.
        assert_eq!(admit(SPECS, &FsParameter::string("noswap", "1")), FsParamVerdict::Unknown);
    }

    // A name carried twice, once as a flag and once with a value, resolves to
    // whichever entry matches what the caller supplied.
    #[test]
    fn a_name_described_both_ways_resolves_by_what_the_caller_supplied() {
        const BOTH: &[FsParamSpec] = &[
            FsParamSpec::flag("hidepid"),
            FsParamSpec::value("hidepid", FsParamType::String),
        ];
        match admit(BOTH, &FsParameter::string("hidepid", "invisible")) {
            FsParamVerdict::Accept(m) => assert_eq!(m.spec.ty, FsParamType::String),
            other => panic!("expected string Accept, got {other:?}"),
        }
        match admit(BOTH, &FsParameter::flag("hidepid")) {
            FsParamVerdict::Accept(m) => assert!(m.spec.ty.is_flag()),
            other => panic!("expected flag Accept, got {other:?}"),
        }
    }

    // `FSCONFIG_SET_FD` and `FSCONFIG_SET_PATH` are not bare words, so they take
    // the value branch of the lookup and reach a value-typed spec.
    #[test]
    fn non_string_value_kinds_take_the_value_branch() {
        const FD: &[FsParamSpec] = &[FsParamSpec::value("fd", FsParamType::Fd)];
        let file = FsParameter::path("fd", "/dev/fuse");
        assert!(matches!(admit(FD, &file), FsParamVerdict::Accept(_)));
        assert_eq!(admit(FD, &FsParameter::flag("fd")),
            FsParamVerdict::WrongValueShape(FsParamSpec::value("fd", FsParamType::Fd)));
        let _ = Arc::new(());
    }

    #[test]
    fn an_empty_table_describes_nothing() {
        assert_eq!(admit(&[], &FsParameter::flag("anything")), FsParamVerdict::Unknown);
        assert_eq!(admit(&[], &FsParameter::string("anything", "1")), FsParamVerdict::Unknown);
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use crate::fs::fs_context::{vfs_parse_fs_param, FsContext};
    use crate::fs::{FsFlags, FsType};
    use crate::types::VfsError;

    fn ty(params: Option<&'static [FsParamSpec]>) -> Arc<dyn crate::FileSystemType> {
        FsType::with_parameters("paramtest", 0x5a5a, FsFlags::empty(),
            Box::new(|_, _, _, _, _| Err(VfsError::Einval)), params)
    }

    // A filesystem that declares no table is the legacy backend: it cannot
    // reject anything, which is the behaviour every filesystem had before a
    // table existed.
    #[test]
    fn a_filesystem_without_a_table_still_swallows_every_key() {
        let mut fc = FsContext::for_mount(ty(None), 0);
        assert_eq!(vfs_parse_fs_param(&mut fc, &FsParameter::string("nosuchoption", "1")), Ok(()));
        assert_eq!(vfs_parse_fs_param(&mut fc, &FsParameter::flag("alsononsense")), Ok(()));
    }

    // An EMPTY table is a real declaration — "this filesystem takes no options"
    // — and is what makes an option-support query answer truthfully instead of
    // claiming support for everything.
    #[test]
    fn an_empty_table_rejects_every_option_with_einval() {
        let mut fc = FsContext::for_mount(ty(Some(&[])), 0);
        assert_eq!(vfs_parse_fs_param(&mut fc, &FsParameter::string("hidepid", "invisible")),
            Err(VfsError::Einval));
        assert_eq!(vfs_parse_fs_param(&mut fc, &FsParameter::string("subset", "pid")),
            Err(VfsError::Einval));
        assert_eq!(vfs_parse_fs_param(&mut fc, &FsParameter::flag("anything")),
            Err(VfsError::Einval));
    }

    // Rejecting unknown keys must not cost the two things every filesystem
    // still has to accept: the superblock flags the VFS handles itself, and
    // `source`.
    #[test]
    fn a_declared_table_still_admits_sb_flags_and_source() {
        let mut fc = FsContext::for_mount(ty(Some(&[])), 0);
        assert_eq!(vfs_parse_fs_param(&mut fc, &FsParameter::flag("ro")), Ok(()));
        assert_eq!(vfs_parse_fs_param(&mut fc, &FsParameter::flag("nosuid")), Err(VfsError::Einval));
        assert_eq!(vfs_parse_fs_param(&mut fc, &FsParameter::string("source", "/dev/vda")), Ok(()));
    }

    #[test]
    fn a_declared_key_is_accepted_and_an_undeclared_neighbour_is_not() {
        const SPECS: &[FsParamSpec] = &[FsParamSpec::value("size", FsParamType::Size)];
        let mut fc = FsContext::for_mount(ty(Some(SPECS)), 0);
        assert_eq!(vfs_parse_fs_param(&mut fc, &FsParameter::string("size", "64m")), Ok(()));
        assert_eq!(vfs_parse_fs_param(&mut fc, &FsParameter::string("nr_blocks", "10")),
            Err(VfsError::Einval));
        // A value-typed key given as a bare word is the wrong shape, not an
        // unknown key, and must not be read as a device name.
        assert_eq!(vfs_parse_fs_param(&mut fc, &FsParameter::flag("size")), Err(VfsError::Einval));
        assert!(fc.source().is_none());
    }
}
