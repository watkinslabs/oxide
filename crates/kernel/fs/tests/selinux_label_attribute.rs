//! Reading `security.selinux` must report the object's LIVE label, from the
//! kernel's own inode state, and must reach the filesystem's attribute store
//! only when no security module claims the name.
//!
//! This is the `/dev/tty2` case. A device node lives on a filesystem that
//! stores no attributes at all, so a label read served from the store can only
//! answer "this filesystem does not do attributes" — for an object that is
//! labelled. The login stack reads that label, treats the failure as "no
//! label", and carries the resulting null into a string operation, which is
//! where the session worker dies. The label is kernel state; the store is only
//! where it was last persisted.
//!
//! The whole point is the STORELESS inode: an assertion made only against a
//! filesystem that has a store cannot fail when the label module is bypassed,
//! because the store answers plausibly. Reverting the `inode_getsecurity` hook
//! turns `a_storeless_filesystem_still_reports_its_label` red with the exact
//! `EOPNOTSUPP` the boot logged.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;

use fs::xattr::{vfs_getxattr, XattrCred};
use selinux::status::{BootConfig, Enforcing};
use syscall::errno::Errno;
use vfs::{default_file_ops, default_inode_ops, mk_mode, FileType, InodeBuilder, InodeRef};

/// The policy the composed image ships. Asserting against the real thing keeps
/// this a statement about a system people boot, not about a fixture.
const DISTRO_POLICY: &str =
    "/home/nd/oxide/images/build/lite-x86_64-root/etc/selinux/targeted/policy/policy.34";

/// Fixture superblock identity — arbitrary but stable.
const TEST_MAGIC: u64 = 0x7402_5346;
const TEST_DEV: u64 = 0x7402;
const TEST_BLOCKSIZE: u32 = 4096;

const NAME: &str = "security.selinux";

fn e(x: Errno) -> i64 { -(x.as_i32() as i64) }

/// A filesystem type named at run time, because the labelling decision is keyed
/// by the NAME the policy states its rules against.
struct NamedType(&'static str);
impl vfs::FileSystemType for NamedType {
    fn name(&self) -> &str { self.0 }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> vfs::KResult<Arc<vfs::SuperBlock>> {
        Err(vfs::VfsError::Enodev)
    }
}

struct NoSuperOps;
impl vfs::SuperOps for NoSuperOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Err(vfs::VfsError::Enosys) }
}

/// Install the real policy into the ONE live security server, permissively.
///
/// Permissive is deliberate: this file asserts what a label read REPORTS, and
/// enforcing mode would let an unrelated access-vector denial on the read's
/// `getattr` decide the result instead, hiding the thing under test.
/// Returns false when the policy is not on this machine.
fn policy_loaded() -> bool {
    let image = match std::fs::read(DISTRO_POLICY) {
        Ok(b) => b,
        Err(_) => { std::println!("skipping: {DISTRO_POLICY} is not present"); return false }
    };
    selinux_runtime::install(BootConfig { enabled: true, enforcing: Some(Enforcing::Permissive) });
    let loaded = selinux_runtime::with(|s| s.load_policy(&image).is_ok()).unwrap_or(false);
    assert!(loaded, "the distribution policy must load");
    assert!(selinux_runtime::active(), "a loaded policy means the module consults it");
    true
}

/// An inode of `ft` on a filesystem called `fstype`, with or without an
/// attribute store. `store: false` is devtmpfs, procfs, sockfs, pipefs — every
/// filesystem whose objects are labelled but hold nothing.
fn inode_on(fstype: &'static str, ft: FileType, store: bool) -> (Arc<vfs::SuperBlock>, InodeRef) {
    let sb = vfs::SuperBlock::new(Arc::new(NamedType(fstype)), Arc::new(NoSuperOps),
        TEST_MAGIC, TEST_DEV, TEST_BLOCKSIZE, String::from(fstype), Arc::new(()));
    let b = InodeBuilder::new(1, mk_mode(ft, 0o666), default_inode_ops(), default_file_ops())
        .owner(0, 0).sb(Arc::downgrade(&sb));
    let ino = if store { b.xattrs(vfs::SimpleXattrs::new()).build() } else { b.build() };
    (sb, ino)
}

fn read_label(ino: &InodeRef) -> Result<alloc::vec::Vec<u8>, i64> {
    vfs_getxattr(ino, NAME, &XattrCred::root())
}

/// The failure the boot logged: `pam_selinux` asking `/dev/tty2` for its label
/// and being told the operation is not supported.
#[test]
fn a_storeless_filesystem_still_reports_its_label() {
    if !policy_loaded() { return }
    let (_sb, tty) = inode_on("devtmpfs", FileType::CharDev, false);

    let v = read_label(&tty).expect("a labelled device node reports its label");
    assert_eq!(*v.last().unwrap(), 0,
               "the value carries its terminator, as every reader of it assumes");
    let text = core::str::from_utf8(&v[..v.len() - 1]).expect("a context is text");
    assert_eq!(text.split(':').count(), 4, "user:role:type:level — got {text:?}");
}

/// The same read on a filesystem that DOES store attributes: still the live
/// label, still not the store, because the two disagree on any object whose
/// label was computed rather than written.
#[test]
fn a_stored_attribute_does_not_outrank_the_live_label() {
    if !policy_loaded() { return }
    let (_sb, f) = inode_on("ext4", FileType::Regular, true);
    // Plant a label in the store that is NOT the one the mount computes, and
    // is not even a context the policy can read. It is planted in the SAME
    // framing a real stored label has — terminator included — so that serving
    // the read from the store produces a value this assertion can actually
    // reject. A planted value framed differently from a real one would make the
    // comparison unable to match, and the test would pass on the store's answer.
    const PLANTED: &str = "planted_u:planted_r:planted_t:s0";
    let mut stored = PLANTED.as_bytes().to_vec();
    stored.push(0);
    f.setxattr(NAME, stored, false, false).expect("the store accepts a value");

    let v = read_label(&f).expect("a file on a labelled mount reports its label");
    let text = core::str::from_utf8(&v[..v.len() - 1]).expect("a context is text");
    assert_ne!(text, PLANTED, "the live label answers the read, not what the store holds");
    assert_eq!(text.split(':').count(), 4, "user:role:type:level — got {text:?}");
}

/// A policy update invalidates the inode cache without walking every inode.
#[test]
fn a_policy_generation_rejects_an_older_inode_sid() {
    if !policy_loaded() { return }
    let (_sb, inode) = inode_on("ext4", FileType::Regular, true);
    let old_seq = selinux_runtime::policy_seq();
    inode.set_security_sid_at(0xdead_beef, old_seq);
    let image = std::fs::read(DISTRO_POLICY).expect("policy image remains available");
    selinux_runtime::with(|s| s.load_policy(&image).expect("policy reload"));
    let sid = fs::selinux::inode_sid(&inode).expect("the current policy resolves the inode");
    assert_ne!(sid, 0xdead_beef, "a prior policy generation must not survive");
}

/// The `nolsm` fallback: a `security.*` name no module owns is the filesystem's
/// own attribute, and reads exactly as it was written.
#[test]
fn an_attribute_no_module_claims_still_comes_from_the_store() {
    if !policy_loaded() { return }
    let (_sb, f) = inode_on("ext4", FileType::Regular, true);
    f.setxattr("security.ima", b"digest".to_vec(), false, false).expect("stored");

    assert_eq!(read_attr(&f, "security.ima"), Ok(b"digest".to_vec()));
    // And absent from a store that exists is ENODATA, not EOPNOTSUPP: the
    // distinction is what tells a caller "no such attribute" apart from
    // "this filesystem cannot hold one".
    assert_eq!(read_attr(&f, "security.evm"), Err(e(Errno::Enodata)));

    // On a storeless filesystem the same unclaimed name has nowhere to come
    // from, and says so.
    let (_sb2, tty) = inode_on("devtmpfs", FileType::CharDev, false);
    assert_eq!(read_attr(&tty, "security.ima"), Err(e(Errno::Eopnotsupp)));
}

fn read_attr(ino: &InodeRef, name: &str) -> Result<alloc::vec::Vec<u8>, i64> {
    vfs_getxattr(ino, name, &XattrCred::root())
}
