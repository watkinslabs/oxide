//! The value-carrying half of the mount API: `FSCONFIG_SET_FD`,
//! `FSCONFIG_SET_PATH`, `FSCONFIG_SET_PATH_EMPTY`, `FSCONFIG_SET_BINARY`.
//!
//! FAILS-BEFORE: every one of these could only ever be REJECTED. The descriptor
//! was pinned, the pathname captured and the blob copied correctly, and then the
//! parameter was refused on its value TYPE before the filesystem's own table was
//! ever consulted — so no filesystem could accept a descriptor no matter what it
//! declared, and the fd-passing half of the mount API was unreachable.
//!
//! What these pin:
//!   * the table is consulted FIRST, and it decides the value type;
//!   * an admitted descriptor reaches the backend BOTH ways — its number in the
//!     option string (what `mount -o fd=N` would have produced) and the PINNED
//!     open file, which is the only one of the two that survives the caller
//!     closing the descriptor;
//!   * a filesystem publishing no table still refuses a value it cannot render;
//!   * a blob is refused by every declared type, because none consumes one.
//!
//! SERIAL: registers filesystem types on the global registry.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::{
    put_fs_context, vfs_get_tree, vfs_parse_fs_param, FileSystem, FsContext, FsFlags, FsParamSpec,
    FsParamType, FsParameter, FsType,
};
use vfs::{
    default_file_ops, default_inode_ops, mk_mode, File, FileType, InodeBuilder, InodeRef,
    OpenFlags, VfsError,
};

static SERIAL: Mutex<()> = Mutex::new(());
/// What the constructor was handed: `(option string, pinned fd numbers)`.
static SEEN: Mutex<Option<(String, Vec<i32>)>> = Mutex::new(None);

const MAGIC: u64 = 0x1703_0001;

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    *SEEN.lock().unwrap_or_else(|e| e.into_inner()) = None;
    g
}

fn seen() -> (String, Vec<i32>) {
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clone().expect("constructor ran")
}

struct Leaf;
impl FileSystem for Leaf {
    fn name(&self) -> &str { "valfs" }
    fn magic(&self) -> u64 { MAGIC }
    fn root(&self) -> Option<InodeRef> {
        Some(InodeBuilder::new(1, mk_mode(FileType::Directory, 0o755),
            default_inode_ops(), default_file_ops()).build())
    }
}

/// A table with one descriptor key, one pathname key and one plain string key —
/// the three value shapes a real filesystem distinguishes.
const SPECS: &[FsParamSpec] = &[
    FsParamSpec::value("fd", FsParamType::Fd),
    FsParamSpec::value("journal_path", FsParamType::Path),
    FsParamSpec::value("subtype", FsParamType::String),
];

fn register(name: &'static str, params: Option<&'static [FsParamSpec]>) -> Arc<FsType> {
    let ty = FsType::with_parameters(name, MAGIC, FsFlags::empty(),
        Box::new(move |ty, _s, t, d, sb_flags, pinned: &[FsParameter]| {
            *SEEN.lock().unwrap_or_else(|e| e.into_inner()) = Some((
                d.to_string(),
                pinned.iter().filter_map(|p| p.as_fd()).collect(),
            ));
            let fs: Arc<dyn FileSystem> = Arc::new(Leaf);
            vfs::fs::superblock_from_filesystem(ty, fs, None, t.into(), sb_flags)
        }), params);
    let _ = vfs::fs::register_fs(ty.clone());
    ty
}

/// An open file description standing in for the daemon's `/dev/fuse` channel.
fn pinned_file() -> Arc<File> {
    let inode = InodeBuilder::new(9, mk_mode(FileType::CharDev, 0o600),
        default_inode_ops(), default_file_ops()).build();
    let dentry = vfs::dentry::Dentry::new_root(inode.clone());
    File::new(inode, dentry, OpenFlags::O_RDWR)
}

fn ctx(ty: Arc<FsType>) -> FsContext {
    FsContext::for_mount(ty as Arc<dyn vfs::FileSystemType>, 0)
}

// ---- the descriptor half ----------------------------------------------------

// The headline defect. FAILS-BEFORE: EINVAL, always, for every filesystem.
#[test]
fn a_declared_descriptor_parameter_accepts_a_pinned_file() {
    let _g = guard();
    let ty = register("valfs_fd", Some(SPECS));
    let mut fc = ctx(ty);
    let f = pinned_file();

    vfs_parse_fs_param(&mut fc, &FsParameter::fd("fd", 17, f.clone()))
        .expect("a descriptor-typed parameter admits a pinned file");
    vfs_get_tree(&mut fc).expect("the tree realizes");

    let (opts, fds) = seen();
    // BOTH views reach the backend. The number is what `mount -o fd=17` would
    // have written, so a backend that parses its option string is unchanged…
    assert_eq!(opts, "fd=17", "the descriptor renders its NUMBER into the option string");
    // …and the pinned description travels beside it, because the number alone
    // is stale the moment the caller closes the fd.
    assert_eq!(fds, vec![17], "the pinned open file reaches the constructor");
    put_fs_context(fc);
}

// The pinned description must be the SAME file the caller passed — carrying the
// number only would force a second descriptor-table lookup that can race a
// close, which is the whole reason the reference pins it.
#[test]
fn the_pinned_description_is_the_callers_own_file() {
    let _g = guard();
    let ty = register("valfs_pin", Some(SPECS));
    let mut fc = ctx(ty);
    let f = pinned_file();

    vfs_parse_fs_param(&mut fc, &FsParameter::fd("fd", 3, f.clone())).expect("admitted");
    let got = fc.pinned_params();
    assert_eq!(got.len(), 1);
    assert!(Arc::ptr_eq(got[0].as_file().expect("a file value"), &f),
        "the description handed to the backend is the one the caller pinned");
    put_fs_context(fc);
}

// ---- the pathname half ------------------------------------------------------

#[test]
fn a_declared_pathname_parameter_accepts_a_path_and_renders_it() {
    let _g = guard();
    let ty = register("valfs_path", Some(SPECS));
    let mut fc = ctx(ty);

    vfs_parse_fs_param(&mut fc, &FsParameter::path("journal_path", "/dev/vdb"))
        .expect("a pathname-typed parameter admits a pathname");
    vfs_get_tree(&mut fc).expect("realizes");
    let (opts, fds) = seen();
    assert_eq!(opts, "journal_path=/dev/vdb");
    assert!(fds.is_empty(), "a pathname is not a pinned descriptor");
    put_fs_context(fc);
}

// `SET_PATH_EMPTY` differs from `SET_PATH` only in permitting an empty
// pathname; both are the same value type to the table.
#[test]
fn an_empty_pathname_is_still_a_pathname_to_the_table() {
    let _g = guard();
    let ty = register("valfs_pathe", Some(SPECS));
    let mut fc = ctx(ty);
    vfs_parse_fs_param(&mut fc, &FsParameter::path_empty("journal_path", ""))
        .expect("admitted");
    put_fs_context(fc);
}

// ---- the refusals that must SURVIVE ----------------------------------------

// A key the table does not describe is still unknown, whatever its value type —
// the admission fix must not become "anything goes".
#[test]
fn an_undeclared_key_is_still_refused_with_a_file_value() {
    let _g = guard();
    let ty = register("valfs_unk", Some(SPECS));
    let mut fc = ctx(ty);
    assert_eq!(vfs_parse_fs_param(&mut fc, &FsParameter::fd("nosuchopt", 5, pinned_file()))
        .unwrap_err(), VfsError::Einval);
    put_fs_context(fc);
}

// A descriptor handed to a parameter that asked for a string is a wrong VALUE,
// not an unknown key — it must not be silently turned into text.
#[test]
fn a_descriptor_given_to_a_string_parameter_is_refused() {
    let _g = guard();
    let ty = register("valfs_mism", Some(SPECS));
    let mut fc = ctx(ty);
    assert_eq!(vfs_parse_fs_param(&mut fc, &FsParameter::fd("subtype", 5, pinned_file()))
        .unwrap_err(), VfsError::Einval);
    // And the converse: a pathname is not a descriptor.
    assert_eq!(vfs_parse_fs_param(&mut fc, &FsParameter::path("fd", "/dev/fuse"))
        .unwrap_err(), VfsError::Einval);
    put_fs_context(fc);
}

// No declared type consumes a binary blob, so `FSCONFIG_SET_BINARY` is refused
// by every filesystem registered here — and the refusal comes from the TABLE,
// which is what a filesystem wanting a blob would change.
#[test]
fn a_binary_blob_is_refused_by_every_declared_type() {
    let _g = guard();
    let ty = register("valfs_blob", Some(SPECS));
    let mut fc = ctx(ty);
    for key in ["fd", "journal_path", "subtype"] {
        assert_eq!(vfs_parse_fs_param(&mut fc, &FsParameter::blob(key, b"\x00\xff"))
            .unwrap_err(), VfsError::Einval, "blob for {key}");
    }
    put_fs_context(fc);
}

// A filesystem publishing NO table has no way to render a descriptor, a
// pathname or a blob into the option string that is its whole interface, so it
// refuses all three — while still swallowing every flag and string as before.
#[test]
fn a_filesystem_without_a_table_refuses_values_it_cannot_render() {
    let _g = guard();
    let ty = register("valfs_none", None);
    let mut fc = ctx(ty);
    assert_eq!(vfs_parse_fs_param(&mut fc, &FsParameter::fd("fd", 5, pinned_file()))
        .unwrap_err(), VfsError::Einval);
    assert_eq!(vfs_parse_fs_param(&mut fc, &FsParameter::path("journal_path", "/x"))
        .unwrap_err(), VfsError::Einval);
    assert_eq!(vfs_parse_fs_param(&mut fc, &FsParameter::blob("k", b"\x00"))
        .unwrap_err(), VfsError::Einval);
    // Unchanged: flags and strings still pass, which is what keeps every
    // pseudo-filesystem mountable.
    vfs_parse_fs_param(&mut fc, &FsParameter::flag("newinstance")).expect("flag");
    vfs_parse_fs_param(&mut fc, &FsParameter::string("gid", "5")).expect("string");
    put_fs_context(fc);
}

// ---- the superblock-flag rung ----------------------------------------------

// The flag rung is keyed on the NAME alone and runs before any value is looked
// at. FAILS-BEFORE: gating it on a bare word sent `mount -o ro=1` down to the
// filesystem table, which does not describe `ro`, and reported it unknown.
#[test]
fn a_superblock_flag_is_recognised_whatever_value_it_carries() {
    let _g = guard();
    let ty = register("valfs_sbf", Some(SPECS));
    let mut fc = ctx(ty);
    vfs_parse_fs_param(&mut fc, &FsParameter::string("ro", "1")).expect("ro=1 is still `ro`");
    assert_eq!(fc.sb_flags() & vfs::superblock::SB_RDONLY, vfs::superblock::SB_RDONLY);
    vfs_parse_fs_param(&mut fc, &FsParameter::string("rw", "0")).expect("rw=0 is still `rw`");
    assert_eq!(fc.sb_flags() & vfs::superblock::SB_RDONLY, 0);
    // It is consumed by the rung, not recorded as a filesystem parameter.
    assert!(fc.params().is_empty(), "a superblock flag is not a filesystem parameter");
    put_fs_context(fc);
}
