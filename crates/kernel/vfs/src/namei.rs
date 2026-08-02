//! `path_lookup` per `docs/16§3` — the single component-walking name
//! resolver, structured around a Linux-style `Nameidata`.
//!
//! Module manifest:
//! - `types`: lookup flags, credentials, resolved path, link targets.
//! - `permission`: Linux DAC core (`generic_permission`, POSIX ACLs,
//!   `inode_permission`, `may_lookup`, `may_open`).
//! - `create`: `vfs_create` + `d_instantiate` as one operation.
//! - `may_create` / `may_delete` / `may_link` / `may_rename`: the namespace
//!   mutation gates, one file per Linux `may_*` contract.
//! - `traverse`: mount crossing, `..`, negative-cache gate, lexical component queue.
//! - `walk`: `Nameidata` state and component-walk engine.
//! - `root`: global root provider plus absolute resolve/mount-identification helpers.
//! - `lookup`: public lookup wrapper entry points.

mod child;
mod create;
mod group_list;
mod device_permission;
mod lookup;
mod may_create;
mod may_delete;
mod may_link;
mod may_rename;
mod permission;
mod root;
mod traverse;
mod state;
mod types;
mod walk;

pub use lookup::{mount_target_from_resolved_path, mountpoint_lookup_at_root_cred, path_lookup, path_lookup_at_cred, path_lookup_at_root_cred, path_lookup_cred, path_lookup_path};
pub use create::vfs_create_at;
pub use device_permission::{device_permission, may_open_dev, set_device_permission_hook, DevicePermissionHook};
pub use permission::{generic_permission, inode_permission, may_open};
pub use may_create::{may_create, may_create_in_sticky};
pub use may_delete::{may_delete, may_delete_dentry};
pub use may_link::{may_link, may_link_source, may_linkat};
pub use may_rename::{may_rename, rename_flags_check, RENAME_EXCHANGE, RENAME_NOREPLACE, RENAME_WHITEOUT};
pub use root::{resolve_abs, resolve_path_dentry, root_dentry, set_root_dentry_provider, walk_to_mount};
pub use group_list::GroupList;
pub use types::{Cred, LastType, LinkTarget, LookupFlags, MountTarget, VfsPath, MAX_NESTED_LINKS, MAX_SYMLINK_DEPTH, MAY_EXEC, MAY_READ, MAY_WRITE, S_IALLUGO, S_ISGID, S_ISUID, S_IXGRP};
pub use state::Nameidata;

pub(super) use permission::may_lookup;
pub(super) use traverse::{components, dotdot_step, follow_mount_down, neg_cache_ok};
pub(super) use state::WalkOutcome;
