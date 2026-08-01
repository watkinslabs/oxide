// Module manifest: `flags` owns filesystem-type flags, `api` owns the
// `FileSystem`/`FsType` interfaces, `registry` owns type registration, and
// `get_tree` owns shared-superblock helpers. `fs_context` owns the modern
// mount-API context model, `fs_parser` the parameter descriptions every mount
// option is admitted against.

mod api;
pub mod fs_context;
pub mod fs_parser;
mod flags;
mod get_tree;
mod registry;

pub use api::{
    superblock_from_filesystem, FileSystem, FsConstructor, FsType, KResult,
};
pub use flags::FsFlags;
pub use fs_context::{
    FsContext, FsContextOps, FsContextPhase, FsContextPurpose, FsContextSecurity, FsParameter,
    FsValue, ClassicMountFsContextOps, ParamResult, SB_FLAGS_USER_MASK, apply_sb_flags, put_fs_context,
    generic_parse_monolithic, parse_monolithic_mount_data,
    finish_clean_context, reconfigure_super, vfs_clean_context, vfs_cmd_create,
    vfs_cmd_reconfigure, vfs_get_tree, vfs_get_tree_exclusive, vfs_parse_fs_param, vfs_parse_fs_param_source,
    vfs_parse_fs_string,
};
pub use fs_parser::{
    admit as admit_fs_param, lookup_key as lookup_fs_param_key, FsParamMatch, FsParamSpec,
    FsParamType, FsParamVerdict,
};
pub use get_tree::{get_tree_keyed, get_tree_nodev, get_tree_single, reconfigure_single};
pub use registry::{filesystems_proc_body, get_fs, get_fs_type, register_filesystem, register_fs,
    registered_filesystems, unregister_filesystem, unregister_fs};
