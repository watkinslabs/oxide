// A casefolded tmpfs mount, driven through the real filesystem: the mount
// option that declares the encoding, the attribute that turns folding on for
// one directory, and what the child index then answers.
//
// Every case here is a behaviour a program can observe — which spelling finds a
// file, which second create is refused, and which errno a bad attribute change
// reports.

use alloc::string::String;
use alloc::sync::Arc;

use vfs::{CreateCtx, FileType, Inode, InodeRef, VfsError};

use super::super::TmpfsFs;

/// `FS_CASEFOLD_FL`, the chattr bit that turns folding on for one directory.
const FS_CASEFOLD_FL: u32 = vfs::inode::FS_CASEFOLD_FL;

/// A mounted instance plus its root inode. The superblock has to be built for
/// real: the encoding lives on it, and nothing folds without one.
fn mount(data: &str) -> Option<(Arc<vfs::SuperBlock>, InodeRef)> {
    use vfs::fs::{FileSystem, FsFlags, FsType, superblock_from_filesystem};
    let fs = TmpfsFs::from_mount_data(String::from("/t"), data).ok()?;
    let root = fs.root_inode();
    let ty = FsType::new("tmpfs", super::super::uapi::TMPFS_MAGIC, FsFlags::empty(),
        alloc::boxed::Box::new(|_, _, _, _, _, _| Err(VfsError::Einval)));
    let sb = superblock_from_filesystem(ty, fs as Arc<dyn FileSystem>, Some(root.clone()),
        String::from("tmpfs"), 0).ok()?;
    Some((sb, root))
}

/// Turn folding on for `dir`, reporting the errno the attribute change gives.
fn set_casefold(dir: &Inode, on: bool) -> Result<(), VfsError> {
    let mut fa = dir.i_op().fileattr_get(dir)?;
    fa.flags = if on { fa.flags | FS_CASEFOLD_FL } else { fa.flags & !FS_CASEFOLD_FL };
    dir.i_op().fileattr_set(dir, &fa)
}

fn mkdir(dir: &Inode, name: &str) -> Result<InodeRef, VfsError> {
    dir.i_op().mkdir(dir, name, 0o755, &CreateCtx::root())
}

fn create(dir: &Inode, name: &str) -> Result<InodeRef, VfsError> {
    dir.i_op().create(dir, name, 0o644, &CreateCtx::root())
}

fn lookup(dir: &Inode, name: &str) -> Result<InodeRef, VfsError> {
    dir.i_op().lookup(dir, name)
}

#[test]
fn strict_encoding_without_an_encoding_fails_the_mount() {
    assert!(TmpfsFs::from_mount_data(String::from("/t"), "strict_encoding").is_err(),
        "strictness is a property of an encoding, so naming none describes nothing");
    assert!(TmpfsFs::from_mount_data(String::from("/t"), "casefold,strict_encoding").is_ok());
}

#[test]
fn only_a_utf8_charset_is_a_charset_this_kernel_has() {
    assert!(TmpfsFs::from_mount_data(String::from("/t"), "casefold").is_ok(),
        "the bare flag takes the kernel table's own version");
    assert!(TmpfsFs::from_mount_data(String::from("/t"), "casefold=utf8-12.1.0").is_ok());
    assert!(TmpfsFs::from_mount_data(String::from("/t"), "casefold=latin1").is_err());
    assert!(TmpfsFs::from_mount_data(String::from("/t"), "casefold=utf8-99.0.0").is_err(),
        "a version newer than the table would fold by a different table than it advertises");
}

#[test]
fn the_mount_declares_the_encoding_and_the_attribute_turns_folding_on() {
    let (sb, root) = mount("casefold").expect("a casefolded mount");
    assert!(sb.s_encoding().is_some(), "the instance declared an encoding");
    // Declaring it is not folding: the root is still byte-exact until asked.
    let dir = mkdir(&root, "plain").expect("mkdir");
    create(&dir, "File").expect("create");
    assert!(lookup(&dir, "file").is_err(), "a byte-exact directory keeps byte-exact lookups");

    let folded = mkdir(&root, "folded").expect("mkdir");
    set_casefold(&folded, true).expect("the attribute is accepted on an empty dir");
    create(&folded, "File").expect("create");
    assert!(lookup(&folded, "file").is_ok(), "every spelling finds the one child");
    assert!(lookup(&folded, "FILE").is_ok());
    assert!(lookup(&folded, "other").is_err(), "a different name is still absent");
}

#[test]
fn a_second_spelling_cannot_create_a_second_entry() {
    let (_sb, root) = mount("casefold").expect("a casefolded mount");
    let d = mkdir(&root, "d").expect("mkdir");
    set_casefold(&d, true).expect("attribute");
    create(&d, "Report").expect("create");
    assert_eq!(create(&d, "report").err(), Some(VfsError::Eexist),
        "one name, one entry — a case variant is the same name");
    assert_eq!(mkdir(&d, "REPORT").err(), Some(VfsError::Eexist));
    // And removal resolves the same way.
    assert!(d.i_op().unlink(&d, "REPORT").is_ok(), "unlink finds it by any spelling");
    assert!(lookup(&d, "Report").is_err());
}

#[test]
fn folding_is_inherited_by_a_directory_created_inside_a_folded_one() {
    let (_sb, root) = mount("casefold").expect("a casefolded mount");
    let outer = mkdir(&root, "outer").expect("mkdir");
    set_casefold(&outer, true).expect("attribute");
    let inner = mkdir(&outer, "inner").expect("mkdir");
    create(&inner, "Deep").expect("create");
    assert!(lookup(&inner, "deep").is_ok(),
        "a subtree may not silently revert to byte-exact lookups");
}

#[test]
fn the_attribute_ladder_reports_the_reference_errnos() {
    // No encoding: the missing encoding is the answer, whatever the type.
    let (_sb, plain_root) = mount("").expect("a plain mount");
    let d = mkdir(&plain_root, "d").expect("mkdir");
    assert_eq!(set_casefold(&d, true).err(), Some(VfsError::Eopnotsupp));
    let f = create(&plain_root, "f").expect("create");
    assert_eq!(set_casefold(&f, true).err(), Some(VfsError::Eopnotsupp),
        "the missing encoding outranks the wrong file type");

    // With an encoding: a regular file is the wrong type, and a non-empty
    // directory is too late — its names were hashed by the other rule.
    let (_sb2, root) = mount("casefold").expect("a casefolded mount");
    let file = create(&root, "f").expect("create");
    assert_eq!(set_casefold(&file, true).err(), Some(VfsError::Enotdir));
    let full = mkdir(&root, "full").expect("mkdir");
    create(&full, "child").expect("create");
    assert_eq!(set_casefold(&full, true).err(), Some(VfsError::Enotempty));
    let empty = mkdir(&root, "empty").expect("mkdir");
    assert!(set_casefold(&empty, true).is_ok());
    create(&empty, "x").expect("create");
    assert_eq!(set_casefold(&empty, false).err(), Some(VfsError::Enotempty),
        "clearing it is equally only legal while the directory is empty");
}

#[test]
fn a_strict_instance_mounts_and_folds_like_any_other() {
    // What strictness WOULD refuse cannot be expressed at this boundary: the
    // inode operations take `&str`, so every name reaching a filesystem is
    // already well-formed UTF-8, and the encoding accepts every well-formed
    // sequence. The mount option is honoured — the instance records that it is
    // strict — and folding behaves identically; the refusal itself has no
    // reachable input until names are carried as bytes.
    let (sb, root) = mount("casefold,strict_encoding").expect("a strict mount");
    assert!(sb.has_strict_encoding(), "the instance recorded the mode");
    let d = mkdir(&root, "d").expect("mkdir");
    set_casefold(&d, true).expect("attribute");
    create(&d, "Ok").expect("create");
    assert!(lookup(&d, "oK").is_ok());
}

#[test]
fn a_folded_directory_still_reports_the_spelling_it_was_created_with() {
    let (_sb, root) = mount("casefold").expect("a casefolded mount");
    let d = mkdir(&root, "d").expect("mkdir");
    set_casefold(&d, true).expect("attribute");
    create(&d, "MixedCase").expect("create");
    let dd = d.private::<super::super::dir::TmpfsDirData>().expect("dir data");
    let names: alloc::vec::Vec<String> = dd.kids.lock().keys().cloned().collect();
    assert_eq!(names, alloc::vec![String::from("MixedCase")],
        "folding decides what MATCHES, never what readdir shows");
    assert_eq!(lookup(&d, "mixedcase").map(|i| i.file_type()).ok(), Some(FileType::Regular));
}
