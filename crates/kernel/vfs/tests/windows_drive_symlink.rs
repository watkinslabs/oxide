//! The staged DOS drive layout walks through the VFS: `C:\windows\system32`
//! is a symlink to the shipped DLL directory, and the Windows loader looks
//! files up case-insensitively through it.

use vfs::{LookupFlags, FileType, path_lookup_path};

#[path = "conformance_common/mod.rs"]
mod fx;

const DLL_DIR: &[u8] = b"/usr/local/lib/oxide/windows/x86_64-windows";

fn staged_root() -> std::sync::Arc<vfs::Dentry> {
    let dll_dir = fx::dir(fx::next_ino(), &[("imm32.dll", fx::regular_file(fx::next_ino()))]);
    let windows_dir = fx::dir(fx::next_ino(), &[("x86_64-windows", dll_dir)]);
    let oxide = fx::dir(fx::next_ino(), &[("windows", windows_dir)]);
    let lib = fx::dir(fx::next_ino(), &[("oxide", oxide)]);
    let local = fx::dir(fx::next_ino(), &[("lib", lib)]);
    let usr = fx::dir(fx::next_ino(), &[("local", local)]);
    let c_windows = fx::dir(fx::next_ino(), &[("system32", fx::symlink_inode(fx::next_ino(), DLL_DIR))]);
    let c = fx::dir(fx::next_ino(), &[("windows", c_windows)]);
    let drives = fx::dir(fx::next_ino(), &[("c", c), ("z", fx::symlink_inode(fx::next_ino(), b"/"))]);
    let root = fx::dir(2, &[("usr", usr), ("windows", drives)]);
    vfs::Dentry::new_root(root)
}

fn windows_flags() -> LookupFlags { LookupFlags { case_insensitive: true, ..Default::default() } }

#[test]
fn system32_symlink_resolves_a_dll_with_default_and_windows_flags() {
    for flags in [LookupFlags::default(), windows_flags()] {
        let root = staged_root();
        let found = path_lookup_path(root.clone(), root, "/windows/c/windows/system32/imm32.dll", flags)
            .unwrap_or_else(|e| panic!("lookup failed: {e:?}"));
        assert_eq!(found.inode.file_type(), FileType::Regular);
    }
}

#[test]
fn the_z_drive_symlink_reaches_the_root_tree() {
    let root = staged_root();
    let found = path_lookup_path(root.clone(), root, "/windows/z/usr/local/lib/oxide/windows/x86_64-windows/imm32.dll", windows_flags()).unwrap();
    assert_eq!(found.inode.file_type(), FileType::Regular);
}
