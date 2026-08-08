// The mount options tracefs, debugfs and configfs accept, and the stamp that
// enforces them.
//
// tracefs and debugfs take the same `uid=`/`gid=`/`mode=` triple and apply it
// to the inode at the top of their tree; debugfs additionally declares
// `source`. configfs declares nothing, and an empty table is how that is said
// in a checkable way.
//
// The two differ in ONE respect, and it is not cosmetic: tracefs refuses a key
// it does not know, debugfs swallows it. A `mount -t debugfs -o whatever` that
// the reference completes must not fail here, and a `mount -t tracefs -o
// whatever` the reference refuses must not succeed — so the leniency is
// declared per filesystem rather than assumed for the pair.
//
// The keys, the parse and the fold live in `kernfs::mount_opts`, shared with
// every other pseudo-filesystem whose option surface is its root's ownership.
// This module owns only which table each type publishes and which tree each
// stamp lands on.

extern crate alloc;

use alloc::sync::Arc;

use kernfs::mount_opts::{apply_root_attr, opts_for_mount, RootAttrOpts, UnknownKey};
use vfs::fs::{FsParamSpec, FsParameter};
use vfs::{KResult, VfsError};

/// `tracefs_param_specs`.
pub static TRACEFS_PARAMS: &[FsParamSpec] = kernfs::mount_opts::ROOT_ATTR_PARAMS;

/// `debugfs_param_specs` — the tracefs three plus `source`.
pub static DEBUGFS_PARAMS: &[FsParamSpec] = kernfs::mount_opts::ROOT_ATTR_SOURCE_PARAMS;

/// configfs registers context operations with no `parse_param` at all, so every
/// key reaches the "unknown parameter" report. An empty table says exactly that.
pub static CONFIGFS_PARAMS: &[FsParamSpec] = kernfs::mount_opts::NO_PARAMETERS;

/// tracefs refuses a key it does not declare.
pub const TRACEFS_UNKNOWN: UnknownKey = UnknownKey::Refuse;
/// debugfs does not: its parse turns the "no such parameter" answer into
/// success, so an unrecognised key is accepted and dropped. A strict table here
/// would fail mounts the reference completes.
pub const DEBUGFS_UNKNOWN: UnknownKey = UnknownKey::Ignore;

/// Parse a tracefs mount's options and stamp them on the tracefs tree root.
/// # C: O(len data)
pub fn mount_tracefs(data: &str, pinned: &[FsParameter]) -> KResult<RootAttrOpts> {
    let opts = opts_for_mount(TRACEFS_PARAMS, data, pinned, TRACEFS_UNKNOWN)?;
    apply_root_attr(&crate::trace_root(), &opts);
    Ok(opts)
}

/// Parse a debugfs mount's options and stamp them on the debugfs tree root.
/// # C: O(len data)
pub fn mount_debugfs(data: &str, pinned: &[FsParameter]) -> KResult<RootAttrOpts> {
    let opts = opts_for_mount(DEBUGFS_PARAMS, data, pinned, DEBUGFS_UNKNOWN)?;
    apply_root_attr(&crate::debug_root(), &opts);
    Ok(opts)
}

/// Admit a configfs mount's options: it takes none, so a non-empty option
/// string is the caller naming a parameter configfs does not have. # C: O(len data)
pub fn mount_configfs(data: &str, pinned: &[FsParameter]) -> KResult<()> {
    opts_for_mount(CONFIGFS_PARAMS, data, pinned, UnknownKey::Refuse)?;
    Ok(())
}

/// Fold one already-admitted parameter into a debugfs mount's answer, for the
/// `fsconfig(2)` path where parameters arrive one at a time rather than as a
/// blob. Returns whether the key belonged to debugfs at all. # C: O(len value)
pub fn debugfs_param(opts: &mut RootAttrOpts, param: &FsParameter) -> KResult<bool> {
    match vfs::fs::admit_fs_param(DEBUGFS_PARAMS, param) {
        vfs::fs::FsParamVerdict::Unknown => return Ok(false),
        // A declared key given the wrong value shape is refused even by the
        // lenient filesystem: leniency covers "no such parameter", never a bad
        // value.
        vfs::fs::FsParamVerdict::WrongValueShape(_) => return Err(VfsError::Einval),
        vfs::fs::FsParamVerdict::Accept(_) => {}
    }
    let value = param.as_str();
    kernfs::mount_opts::apply_param(opts, param.key.as_str(), value)
        .map_err(|_| VfsError::Einval)?;
    Ok(true)
}

/// Stamp a debugfs mount's collected answer on the debugfs tree root. # C: O(1)
pub fn stamp_debugfs(opts: &RootAttrOpts) { apply_root_attr(&crate::debug_root(), opts); }

/// The debugfs superblock identity string, so the mount path and the context
/// path cannot name the instance differently. # C: O(1)
pub const DEBUGFS_S_ID: &str = "debugfs";

/// Build the debugfs superblock. One constructor, reached from both the
/// classic `mount(2)` shim and the `fsconfig(2)` context. # C: O(1)
pub fn debugfs_superblock(ty: Arc<dyn vfs::FileSystemType>, sb_flags: u64)
    -> KResult<Arc<vfs::SuperBlock>>
{
    let fs: Arc<dyn vfs::fs::FileSystem> = Arc::new(crate::fs_impl::DebugfsFs);
    vfs::fs::superblock_from_filesystem(ty, fs, None, DEBUGFS_S_ID.into(), sb_flags)
}

#[cfg(test)]
mod tests;
