//! Parsing an option string, and rendering it back.
//!
//! The round trip is the contract that matters: a remount reads back what was
//! shown, so an option rendered in a form the parser refuses turns a working
//! mount into one that cannot be remounted.

use super::*;

use syscall::errno::Errno;

use crate::name::flags::{SFN_CREATE_WINNT, SFN_DISPLAY_WINNT};

fn vfat(data: &str) -> Options { parse(Options::vfat(), data).expect("accepted") }

/// The three masks are OCTAL. Read as decimal, `umask=0077` masks off bits
/// nobody asked about and leaves the ones they did.
#[test]
fn the_masks_are_octal() {
    let o = vfat("umask=0077");
    assert_eq!(o.fmask, 0o077);
    assert_eq!(o.dmask, 0o077);
    // The two halves override the combined one, whichever order they arrive in.
    let o = vfat("umask=0077,dmask=0022");
    assert_eq!(o.fmask, 0o077);
    assert_eq!(o.dmask, 0o022);
}

/// `codepage=` is decimal, and a page this build has no table for is refused
/// rather than silently falling back — a name would then come back as
/// different characters than the medium holds.
#[test]
fn the_code_page_must_be_one_this_build_has() {
    assert_eq!(vfat("codepage=437").codepage.number, 437);
    assert_eq!(vfat("codepage=850").codepage.number, 850);
    assert_eq!(parse(Options::vfat(), "codepage=852").err(), Some(Errno::Einval));
}

#[test]
fn iocharset_is_stored_separately_from_the_disk_code_page() {
    let o = vfat("codepage=437,iocharset=utf8");
    assert_eq!(o.codepage.number, 437);
    assert_eq!(o.iocharset, crate::name::compare::IoCharset::Utf8);
    assert_eq!(vfat("iocharset=iso8859-1").iocharset,
               crate::name::compare::IoCharset::Iso88591);
    assert_eq!(parse(Options::vfat(), "iocharset=cp1252").err(), Some(Errno::Einval));
}

/// The four `shortname=` words each name a display and a creation rule.
#[test]
fn shortname_names_a_display_and_a_creation_rule() {
    assert_eq!(vfat("shortname=winnt").shortname, SFN_DISPLAY_WINNT | SFN_CREATE_WINNT);
    assert_eq!(parse(Options::vfat(), "shortname=nonsense").err(), Some(Errno::Einval));
}

/// `tz=UTC` and `time_offset=` are the same field, and an offset no zone could
/// have is refused.
#[test]
fn the_time_offset_is_bounded() {
    assert_eq!(vfat("tz=UTC").time, crate::time::TimeConfig::with_offset(0));
    assert_eq!(vfat("time_offset=-330").time, crate::time::TimeConfig::with_offset(-330));
    assert_eq!(parse(Options::vfat(), "time_offset=2000").err(), Some(Errno::Einval));
    // A mount that named nothing is not the same as one that named zero.
    assert!(!Options::vfat().time.set);
    assert!(vfat("tz=UTC").time.set);
}

/// `nonumtail` is spelled as its own negation, so an explicit truth value
/// inverts it. Reading it straight turns the option on when it was turned off.
#[test]
fn nonumtail_is_a_negated_option() {
    assert!(Options::vfat().numtail);
    assert!(!vfat("nonumtail").numtail);
    assert!(!vfat("nonumtail=1").numtail);
    assert!(vfat("nonumtail=0").numtail);
}

/// A flag with a value, and a value-bearing key with none, are both the
/// caller having meant something this filesystem cannot do.
#[test]
fn the_wrong_shape_is_refused() {
    assert_eq!(parse(Options::vfat(), "usefree=1").err(), Some(Errno::Einval));
    assert_eq!(parse(Options::vfat(), "codepage").err(), Some(Errno::Einval));
    assert_eq!(parse(Options::vfat(), "check=nonsense").err(), Some(Errno::Einval));
}

/// A key outside the filesystem's parameter table must fail rather than turn a
/// typo into a mount with different semantics than the caller requested.
#[test]
fn an_unknown_key_is_refused() {
    assert_eq!(parse(Options::vfat(), "nosuchoption=1").err(), Some(Errno::Einval));
}

/// The VFS-facing tables separate the two type-specific option sets before
/// the shared parser receives the admitted string.
#[test]
fn parameter_tables_admit_only_the_named_fat_type_surface() {
    use vfs::fs::{admit_fs_param, FsParamVerdict, FsParameter};

    assert!(matches!(admit_fs_param(VFAT_PARAMS,
        &FsParameter::string("shortname", "winnt")), FsParamVerdict::Accept(_)));
    assert_eq!(admit_fs_param(MSDOS_PARAMS,
        &FsParameter::string("shortname", "winnt")), FsParamVerdict::Unknown);
    assert!(matches!(admit_fs_param(MSDOS_PARAMS,
        &FsParameter::flag("nodots")), FsParamVerdict::Accept(_)));
    assert_eq!(admit_fs_param(VFAT_PARAMS,
        &FsParameter::flag("nodots")), FsParamVerdict::Unknown);
    assert_eq!(admit_fs_param(VFAT_PARAMS,
        &FsParameter::string("nosuchoption", "1")), FsParamVerdict::Unknown);
}

/// Generic mount flags are consumed before the FAT table, while a typo reaches
/// the same unknown-parameter refusal used by the real mount path.
#[test]
fn vfs_admission_consumes_ro_and_rejects_an_unknown_fat_key() {
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use vfs::FileSystemType;
    use vfs::fs::{vfs_parse_fs_param, FsContext, FsFlags, FsParameter, FsType};

    let ty: Arc<dyn FileSystemType> = FsType::with_parameters("vfat-test", 0,
        FsFlags::FS_REQUIRES_DEV, Box::new(|_, _, _, _, _, _| Err(vfs::VfsError::Einval)),
        Some(VFAT_PARAMS));
    let mut fc = FsContext::for_mount(ty, 0);
    assert_eq!(vfs_parse_fs_param(&mut fc, &FsParameter::flag("ro")), Ok(()));
    assert_eq!(vfs_parse_fs_param(&mut fc,
        &FsParameter::string("nosuchoption", "1")), Err(vfs::VfsError::Einval));
}

/// `allow_utime` defaults from `dmask` rather than from a constant: a mount
/// that masked the group and other write bits off its directories must not
/// then let a non-owner set timestamps through the bits it just removed.
#[test]
fn allow_utime_is_derived_from_the_directory_mask() {
    assert_eq!(vfat("dmask=0022").allow_utime, Some(0o000));
    assert_eq!(vfat("dmask=0000").allow_utime, Some(0o022));
    // Named explicitly, only the two write bits survive.
    assert_eq!(vfat("allow_utime=0777").allow_utime, Some(0o022));
}

/// What is shown parses back to the same thing.
#[test]
fn what_is_shown_parses_back() {
    for data in ["", "uid=1000,gid=1000,umask=0077,shortname=winnt,utf8",
                 "codepage=437,check=s,flush,tz=UTC,errors=continue",
                 "time_offset=-330,nonumtail,discard,nfs=nostale_ro"] {
        let first = parse(Options::vfat(), data).expect("accepted");
        let rendered = show(&first);
        let again = parse(Options::vfat(), &rendered).expect("its own output is accepted");
        assert_eq!(show(&again), rendered, "round trip of {data:?} via {rendered:?}");
    }
}

/// The two types render differently, and each renders only what applies to it:
/// no `shortname=` on a mount with no long names, no `dotsOK` on one that has.
#[test]
fn each_type_shows_only_its_own_options() {
    let mut msdos = Options::msdos();
    msdos.dots_ok = true;
    msdos.settle();
    let line = show(&msdos);
    assert!(line.contains(",dotsOK=yes"), "{line}");
    assert!(!line.contains("shortname="), "{line}");
    let mut vfat = Options::vfat();
    vfat.settle();
    let line = show(&vfat);
    assert!(line.contains(",shortname=mixed"), "{line}");
    assert!(!line.contains("dotsOK"), "{line}");
}

/// Every option carries its own leading comma, which is what the generic
/// per-mount flags in front of it expect.
#[test]
fn every_option_is_comma_prefixed() {
    let mut o = Options::vfat();
    o.settle();
    let line = show(&o);
    assert!(line.starts_with(','), "{line}");
    assert!(!line.contains(",,"), "{line}");
}

/// The two types report different longest components, because they accept
/// different names.
#[test]
fn the_two_types_accept_different_name_lengths() {
    assert_eq!(Options::vfat().name_max(), VFAT_NAME_MAX);
    assert_eq!(Options::msdos().name_max(), MSDOS_NAME_MAX);
}
