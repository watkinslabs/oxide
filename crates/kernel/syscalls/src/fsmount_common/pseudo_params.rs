// Parameter tables for the pseudo-filesystems whose whole implementation is the
// generic tree — the types `registry.rs` builds from `kernfs::PseudoFs` rather
// than from a crate of their own.
//
// A type with no crate still has an option contract, and it is registered here
// because this is where the type is registered; there is no second place a name
// could be declared and drift from the one that consumes it.
//
// UNGATED so the whole decision surface is reachable by `cargo test`:
// `registry.rs` itself is `#[cfg(target_os = "oxide-kernel")]`, so anything
// decided there is compiled out of a hosted build and cannot be tested.

extern crate alloc;

use alloc::sync::Arc;

use kernfs::mount_opts::{apply_root_attr, opts_for_mount, UnknownKey};
use kernfs::PseudoFs;
use vfs::fs::{FsParamSpec, FsParamType, FsParameter};
use vfs::KResult;

/// `efivarfs_parameters` — owner only. efivarfs has no `mode=`, so
/// `mount -t efivarfs -o mode=700` fails, which is only true because this is a
/// different table from the tracefs one.
pub static EFIVARFS_PARAMS: &[FsParamSpec] = kernfs::mount_opts::OWNER_ONLY_PARAMS;

/// `bpf_fs_parameters`.
///
/// `uid`/`gid`/`mode` name the bpffs root and are consumed here. The four
/// `delegate_*` values name the bpf commands, map types, program types and
/// attach types a mount hands to unprivileged holders of a token created from
/// it; they are declared because the reference accepts them and a mount naming
/// one must not fail, and their enforcement belongs to the bpf token
/// subsystem, not to the mount.
pub static BPF_PARAMS: &[FsParamSpec] = &[
    FsParamSpec::value("delegate_attachs", FsParamType::String),
    FsParamSpec::value("delegate_cmds",    FsParamType::String),
    FsParamSpec::value("delegate_maps",    FsParamType::String),
    FsParamSpec::value("delegate_progs",   FsParamType::String),
    FsParamSpec::value("gid",              FsParamType::U32),
    FsParamSpec::value("mode",             FsParamType::U32Oct),
    FsParamSpec::value("uid",              FsParamType::U32),
];

/// Build a generic-tree filesystem instance whose mount named its root's owner
/// and mode, admitting the option string against `specs` and stamping what it
/// named on the tree this mount created.
///
/// The stamp lands BEFORE the superblock is attached: the root inode is a cache
/// entry rebuilt on demand from the tree node, so writing the node is what makes
/// the option outlive the first eviction. # C: O(len data)
pub fn pseudo_with_root_attr(name: &'static str, magic: u64, specs: &'static [FsParamSpec],
    data: &str, pinned: &[FsParameter]) -> KResult<Arc<PseudoFs>>
{
    let opts = opts_for_mount(specs, data, pinned, UnknownKey::Refuse)?;
    let fs = PseudoFs::new(name, magic);
    apply_root_attr(fs.root_dir(), &opts);
    Ok(fs)
}

/// Admit the option string of a type that declares no parameters. A non-empty
/// string is the caller naming something the filesystem does not have.
/// # C: O(len data)
pub fn admit_no_params(data: &str, pinned: &[FsParameter]) -> KResult<()> {
    opts_for_mount(kernfs::mount_opts::NO_PARAMETERS, data, pinned, UnknownKey::Refuse)?;
    Ok(())
}

/// [`admit_no_params`] for a type whose whole implementation is the generic
/// tree. # C: O(len data)
pub fn pseudo_no_params(name: &'static str, magic: u64, data: &str, pinned: &[FsParameter])
    -> KResult<Arc<PseudoFs>>
{
    admit_no_params(data, pinned)?;
    Ok(PseudoFs::new(name, magic))
}

#[cfg(test)]
#[path = "pseudo_params/tests.rs"]
mod tests;
