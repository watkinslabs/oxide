// Label helpers shared by the subsystems that own labelled objects.
//
// A SID is stored on the object by its owner, never in a table here. A second
// table keyed by object identity would be a source of truth that can disagree
// with the object's own field, and it would keep entries alive for objects
// that are gone.

use selinux::sidtab::Sid;
use selinux::uapi::classmap::class_by_name;
use selinux::uapi::initsid::InitSid;

/// Extended attribute carrying an object's written security context.
pub const XATTR_NAME_SELINUX: &str = "security.selinux";

/// File-type bits of an inode mode.
const S_IFMT: u32 = 0o170000;
/// Regular file.
const S_IFREG: u32 = 0o100000;
/// Directory.
const S_IFDIR: u32 = 0o040000;
/// Symbolic link.
const S_IFLNK: u32 = 0o120000;
/// Character device.
const S_IFCHR: u32 = 0o020000;
/// Block device.
const S_IFBLK: u32 = 0o060000;
/// Named pipe.
const S_IFIFO: u32 = 0o010000;
/// Socket.
const S_IFSOCK: u32 = 0o140000;

/// Access-mask bit: the caller intends to execute.
pub const MAY_EXEC: u32 = 0x01;
/// Access-mask bit: the caller intends to write.
pub const MAY_WRITE: u32 = 0x02;
/// Access-mask bit: the caller intends to read.
pub const MAY_READ: u32 = 0x04;
/// Access-mask bit: the caller intends to append.
pub const MAY_APPEND: u32 = 0x08;
/// Every access-mask bit a permission check acts on.
pub const MAY_MASK: u32 = MAY_EXEC | MAY_WRITE | MAY_READ | MAY_APPEND;

/// Security class of an inode, from its file-type bits. # C: O(classes)
///
/// A device node is NOT a regular file for policy purposes: the classes carry
/// different permission sets and different rules, so collapsing them would
/// consult the wrong rules and answer with another class's grants.
pub fn inode_class(mode: u32) -> Option<u16> {
    class_by_name(match mode & S_IFMT {
        S_IFREG => "file",
        S_IFDIR => "dir",
        S_IFLNK => "lnk_file",
        S_IFCHR => "chr_file",
        S_IFBLK => "blk_file",
        S_IFIFO => "fifo_file",
        S_IFSOCK => "sock_file",
        // A mode with no type bits is an in-memory object with no on-disk
        // form; those are labelled as anonymous inodes.
        _ => "anon_inode",
    })
}

/// Translate an access mask into the access vector of an inode's class. # C: O(perms)
///
/// Append is checked INSTEAD of write, not as well as it: a policy that grants
/// append without write must not have the write bit demanded of it, or every
/// append-only domain is refused. Directories have no append and map their
/// three bits to their own permission names.
pub fn mask_to_av(mode: u32, mask: u32) -> u32 {
    let Some(class) = inode_class(mode) else { return 0 };
    let bit = |name: &str| selinux::uapi::classmap::perm_bit(class, name).unwrap_or(0);
    let mut av = 0u32;
    if mode & S_IFMT == S_IFDIR {
        if mask & MAY_EXEC != 0 { av |= bit("search"); }
        if mask & MAY_WRITE != 0 { av |= bit("write"); }
        if mask & MAY_READ != 0 { av |= bit("read"); }
        return av;
    }
    if mask & MAY_EXEC != 0 { av |= bit("execute"); }
    if mask & MAY_READ != 0 { av |= bit("read"); }
    if mask & MAY_APPEND != 0 { av |= bit("append"); }
    else if mask & MAY_WRITE != 0 { av |= bit("write"); }
    av
}

/// SID an object takes when its own label cannot be determined. # C: O(1)
pub fn unlabeled_sid() -> Sid { InitSid::Unlabeled.sid() }

/// SID of the kernel itself, used by kernel threads. # C: O(1)
pub fn kernel_sid() -> Sid { InitSid::Kernel.sid() }

/// SID handed to the first user process before a policy is loaded. # C: O(1)
pub fn init_sid() -> Sid { InitSid::Init.sid() }

/// SID of the security server pseudo-object. # C: O(1)
///
/// Every operation on the policy itself is a check against this SID, so a
/// caller that wants to load a policy or set enforcement is asking whether it
/// may act on the security server, not on any file.
pub fn security_sid() -> Sid { InitSid::Security.sid() }

/// Resolve a written context to a SID, falling back to unlabeled. # C: O(categories)
///
/// A label the current policy cannot interpret does NOT make the object
/// inaccessible: it becomes unlabeled, which policy can still write rules
/// about. Refusing outright would make a policy reload that drops one type
/// lock the system out of every object that carried it.
pub fn sid_from_context_or_unlabeled(written: &str) -> Sid {
    crate::with(|s| s.context_to_sid(written).unwrap_or_else(|_| unlabeled_sid()))
        .unwrap_or_else(unlabeled_sid)
}

#[cfg(test)]
#[path = "tests/label.rs"]
mod tests;
