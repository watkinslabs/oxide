//! A whole mount, driven through the operations the VFS calls.
//!
//! These are the cases a container runtime produces: an image's layers below,
//! a writable layer on top, and every write landing there while the image
//! stays untouched. They go through the same entry points a syscall would,
//! so a wiring mistake — an operation that reaches the wrong layer, or one
//! that never copies up — fails here rather than on a boot.

#![allow(unused_imports)]
extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use syscall::errno::Errno;
use vfs::file_ops::{DirContext, DirEmit};
use vfs::inode_ops::CreateCtx;
use vfs::types::{FileType, S_IFREG};
use vfs::posix_acl::{to_xattr, AclEntry, ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER,
                     ACL_UNDEFINED_ID, ACL_USER, ACL_USER_OBJ};
use vfs::fs::FileSystem;
use vfs::{Cred, GroupList, Iattr, InodeRef, VfsError, ATTR_MODE, MAY_READ, MAY_WRITE};

use crate::config::Config;
use crate::testfs::{layer, lookup as find_path, mkfile, mkpath, slurp};
use crate::whiteout;

use super::OverlayFs;

/// A resolver over named layers, standing in for the path walk a real mount
/// does.
struct Layers(BTreeMap<String, InodeRef>);

impl Layers {
    fn resolve(&self) -> impl Fn(&str) -> Result<InodeRef, Errno> + '_ {
        move |p: &str| self.0.get(p).cloned().ok_or(Errno::Enoent)
    }
}

/// An image layer, a writable layer and a work base, as a runtime lays them
/// out.
fn image() -> (Layers, InodeRef, InodeRef) {
    let up = layer(0);
    let lo = layer(1);
    let work = layer(2);
    let mut m = BTreeMap::new();
    m.insert("/upper".to_string(), up.clone());
    m.insert("/lower".to_string(), lo.clone());
    m.insert("/work".to_string(), work);
    (Layers(m), up, lo)
}

/// The names a directory shows through the overlay.
fn names(dir: &InodeRef) -> Vec<String> {
    struct Sink(Vec<String>);
    impl DirEmit for Sink {
        fn emit(&mut self, name: &str, _i: u64, _t: FileType, _n: u64) -> bool {
            self.0.push(name.to_string());
            true
        }
    }
    let mut sink = Sink(Vec::new());
    let mut ctx = DirContext::new(0, &mut sink);
    dir.readdir(&mut ctx).unwrap();
    sink.0.sort();
    sink.0
}

/// The option string a container runtime writes.
const OPTS: &str = "lowerdir=/lower,upperdir=/upper,workdir=/work";


#[path = "tests/lookup.rs"]
mod lookup;
#[path = "tests/copy_up.rs"]
mod copy_up;
#[path = "tests/credentials.rs"]
mod credentials;
#[path = "tests/mount_validation.rs"]
mod mount_validation;
#[path = "tests/options.rs"]
mod options;
