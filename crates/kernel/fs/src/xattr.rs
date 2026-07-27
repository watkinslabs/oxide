// Extended-attribute syscall family (188-199 + the 463-466 `*xattrat` slots),
// the VFS-policy half of Linux `fs/xattr.c`. Module manifest:
//
//   policy — namespace resolution, `xattr_permission`, the commoncap gate,
//            and every ABI limit (`XATTR_{NAME,SIZE,LIST}_MAX`, flags).
//   acl    — the `system.posix_acl_*` detour (`do_set_acl`/`vfs_remove_acl`).
//   ops    — `vfs_{set,get,list,remove}xattr`: policy then storage through the
//            owning filesystem's `i_op` hooks.
//   user   — user-buffer import/copy-out (`setxattr_copy`, `xattr_args`).
//
// STORAGE is owned by the filesystem, never by this layer (D45): tmpfs keeps a
// per-inode `vfs::SimpleXattrs`, ext4 writes the same set through to the
// on-disk ibody / external xattr block. There is no global fallback table.

mod policy;
mod acl;
mod ops;
mod user;
#[cfg(test)]
mod tests;

pub use policy::{current_xattr_cred, XattrCred, XATTR_CREATE, XATTR_LIST_MAX, XATTR_NAME_MAX,
                 XATTR_REPLACE, XATTR_SIZE_MAX};
pub use ops::{query_into, query_len, vfs_getxattr, vfs_listxattr, vfs_removexattr, vfs_setxattr};
pub use user::{get_on, import_name, import_set, import_xattr_args, list_on, remove_on, set_on,
               SetCtx};
