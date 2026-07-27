//! `path_lookup` per `docs/16§3` — the single component-walking name
//! resolver, structured around a Linux-style `Nameidata`.
//!
//! Module manifest:
//! - `types`: lookup flags, credentials, resolved path, link targets.
//! - `permission`: Linux DAC/owner/create/delete/rename/chmod/chown gates.
//! - `traverse`: mount crossing, `..`, negative-cache gate, lexical component queue.
//! - `walk`: `Nameidata` state and component-walk engine.
//! - `root`: global root provider plus absolute resolve/mount-identification helpers.
//! - `lookup`: public lookup wrapper entry points.

mod group_list;
mod lookup;
mod permission;
mod root;
mod traverse;
mod state;
mod types;
mod walk;

pub use lookup::{mount_target_from_resolved_path, mountpoint_lookup_at_root_cred, path_lookup, path_lookup_at_cred, path_lookup_at_root_cred, path_lookup_cred, path_lookup_path};
pub use permission::{chmod_sgid_strip, chown_kill_priv, generic_permission, inode_permission, may_chmod, may_chown, may_create, may_create_in_sticky, may_delete, may_link, may_link_source, may_open, may_rename, rename_flags_check, RENAME_EXCHANGE, RENAME_NOREPLACE, RENAME_WHITEOUT};
pub use root::{resolve_abs, resolve_path_dentry, root_dentry, set_root_dentry_provider, walk_to_mount};
pub use group_list::GroupList;
pub use types::{Cred, LastType, LinkTarget, LookupFlags, MountTarget, VfsPath, MAX_NESTED_LINKS, MAX_SYMLINK_DEPTH, MAY_EXEC, MAY_READ, MAY_WRITE, S_ISGID, S_ISUID, S_IXGRP};
pub use state::Nameidata;

pub(super) use permission::may_lookup;
pub(super) use traverse::{components, dotdot_step, follow_mount_down, neg_cache_ok};
pub(super) use state::WalkOutcome;
