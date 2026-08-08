//! Casefolded filesystem support: the per-superblock encoding, the generic
//! case-insensitive `d_hash`/`d_compare` pair, and strict-mode name validation.
//!
//! Driven against a real SuperBlock and a real dcache so the hooks are reached
//! the way a lookup reaches them — through `d_add`/`d_lookup`, not by calling
//! them directly. Casefolding is per DIRECTORY (`S_CASEFOLD`) on an instance
//! that declared an encoding, so both halves are exercised on one superblock.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::dcache::{d_add, d_lookup, d_make_root_ops};
use vfs::dentry::casefold::{generic_ci_validate_strict_name, sb_enable_casefold};
use vfs::inode::S_CASEFOLD;
use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{Dentry, FileType, InodeRef, KResult, VfsError};

// The dcache hash table is process-global; serialize.
static SERIAL: Mutex<()> = Mutex::new(());
fn guard() -> MutexGuard<'static, ()> { SERIAL.lock().unwrap_or_else(|e| e.into_inner()) }

struct CiFsType;
impl FileSystemType for CiFsType {
    fn name(&self) -> &str { "cifs-test" }
    fn mount(&self, _s: Option<&str>, _o: &str) -> KResult<Arc<SuperBlock>> { Ok(mount(0x71)) }
}
struct CiFsOps;
impl SuperOps for CiFsOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs { f_bsize: 4096, ..Default::default() }) }
}

fn mount(s_dev: u64) -> Arc<SuperBlock> {
    SuperBlock::new(Arc::new(CiFsType), Arc::new(CiFsOps), 0x0102_0304, s_dev, 4096, "cifs-test".into(), Arc::new(()))
}

fn dir(sb: &Arc<SuperBlock>, ino: u64, casefold: bool) -> InodeRef {
    let i = vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Directory, 0o755),
                                   vfs::default_inode_ops(), vfs::default_file_ops())
        .sb(Arc::downgrade(sb)).build();
    if casefold { i.set_i_flags(i.i_flags() | S_CASEFOLD); }
    i
}

fn file(sb: &Arc<SuperBlock>, ino: u64) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Regular, 0o644),
                           vfs::default_inode_ops(), vfs::default_file_ops())
        .sb(Arc::downgrade(sb)).build()
}

/// A mounted casefolding instance whose root directory folds case.
fn casefolded_root(s_dev: u64, charset: &str, strict: bool) -> (Arc<SuperBlock>, Arc<Dentry>) {
    let sb = mount(s_dev);
    let ops = sb_enable_casefold(&sb, charset, strict).expect("encoding loads");
    let root = d_make_root_ops(dir(&sb, 1, true), &sb, Some(ops));
    (sb, root)
}

#[test]
fn declaring_an_encoding_records_it_on_the_superblock() {
    let _g = guard();
    let (sb, _root) = casefolded_root(0x71, "utf8-12.1.0", false);
    let enc = sb.s_encoding().expect("encoding recorded");
    assert_eq!((enc.version().major(), enc.version().minor(), enc.version().revision()), (12, 1, 0));
    assert!(!sb.has_strict_encoding());

    let (strict_sb, _r) = casefolded_root(0x72, "utf8", true);
    assert!(strict_sb.has_strict_encoding());
    assert!(strict_sb.s_encoding().is_some());

    // A plain instance declares nothing and stays byte-exact.
    assert!(mount(0x73).s_encoding().is_none());
}

#[test]
fn an_encoding_this_kernel_cannot_serve_is_refused() {
    let _g = guard();
    let sb = mount(0x74);
    assert_eq!(sb_enable_casefold(&sb, "latin1", false).err(), Some(VfsError::Einval));
    assert_eq!(sb_enable_casefold(&sb, "utf8-99.0.0", false).err(), Some(VfsError::Einval));
    assert_eq!(sb_enable_casefold(&sb, "", false).err(), Some(VfsError::Einval));
    // A refused charset leaves the instance case-sensitive.
    assert!(sb.s_encoding().is_none());
}

#[test]
fn a_casefolded_directory_finds_a_name_by_any_spelling() {
    let _g = guard();
    let (sb, root) = casefolded_root(0x75, "utf8", false);
    d_add(&root, "École", file(&sb, 10));
    for spelling in ["École", "école", "ÉCOLE", "e\u{301}cole", "E\u{301}COLE"] {
        let hit = d_lookup(&root, spelling).unwrap_or_else(|| panic!("{spelling} should hit"));
        assert_eq!(hit.name(), "École");
    }
    assert!(d_lookup(&root, "ecole").is_none(), "a different name must not hit");
}

#[test]
fn full_folding_and_hangul_reach_the_dcache() {
    let _g = guard();
    let (sb, root) = casefolded_root(0x76, "utf8", false);
    d_add(&root, "Straße", file(&sb, 11));
    d_add(&root, "한국", file(&sb, 12));
    assert!(d_lookup(&root, "STRASSE").is_some());
    assert!(d_lookup(&root, "strasse").is_some());
    assert!(d_lookup(&root, "\u{1112}\u{1161}\u{11ab}\u{1100}\u{116e}\u{11a8}").is_some());
    assert!(d_lookup(&root, "Strafe").is_none());
}

#[test]
fn a_directory_without_the_flag_stays_case_sensitive() {
    let _g = guard();
    let sb = mount(0x77);
    let ops = sb_enable_casefold(&sb, "utf8", false).unwrap();
    // The instance declared an encoding, but THIS directory did not opt in.
    let root = d_make_root_ops(dir(&sb, 2, false), &sb, Some(ops));
    d_add(&root, "École", file(&sb, 13));
    assert!(d_lookup(&root, "École").is_some(), "exact name still resolves");
    assert!(d_lookup(&root, "école").is_none(), "no folding without S_CASEFOLD");
    assert!(d_lookup(&root, "e\u{301}cole").is_none());
}

#[test]
fn strict_mode_refuses_a_name_that_is_not_well_formed() {
    let _g = guard();
    let (sb, _root) = casefolded_root(0x78, "utf8", true);
    let folded = dir(&sb, 3, true);
    let plain = dir(&sb, 4, false);

    assert!(generic_ci_validate_strict_name(&folded, "école".as_bytes()));
    assert!(!generic_ci_validate_strict_name(&folded, &[0xff, 0xfe]));
    assert!(!generic_ci_validate_strict_name(&folded, &[0xed, 0xa0, 0x80]));
    // Not casefolded: any bytes are a legal name even on a strict instance.
    assert!(generic_ci_validate_strict_name(&plain, &[0xff, 0xfe]));
    assert_eq!(sb.strict_name_ok(&[0xff, 0xfe]), Err(VfsError::Einval));
    assert_eq!(sb.strict_name_ok("école".as_bytes()), Ok(()));
}

#[test]
fn without_strict_mode_a_malformed_name_is_opaque_bytes() {
    let _g = guard();
    let (sb, _root) = casefolded_root(0x79, "utf8", false);
    let folded = dir(&sb, 5, true);
    assert!(generic_ci_validate_strict_name(&folded, &[0xff, 0xfe]));
    assert_eq!(sb.strict_name_ok(&[0xff, 0xfe]), Ok(()));
}
