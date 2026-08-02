// The parameters fuse accepts, published so `mount(2)` and `fsconfig(2)` reach
// the same verdict on a key.
//
// libfuse's `fuse_mount_sys` always passes `fd=`, `rootmode=`, `user_id=` and
// `group_id=`; the rest are per-mount policy. `source` is listed explicitly
// because fuse names it as a parameter of its own rather than leaving it to
// the generic fallback.

use alloc::sync::Arc;
use vfs::fs::{FsParamSpec, FsParamType, FsParameter};

/// The parameter naming the `/dev/fuse` channel. One spelling, shared by the
/// table, the option-string parse and the pinned-descriptor lookup.
pub const FUSE_FD_KEY: &str = "fd";

/// `fuse_fs_parameters`.
pub static FUSE_PARAMS: &[FsParamSpec] = &[
    FsParamSpec::value("source", FsParamType::String),
    FsParamSpec::value(FUSE_FD_KEY, FsParamType::Fd),
    FsParamSpec::value("rootmode", FsParamType::U32Oct),
    FsParamSpec::value("user_id", FsParamType::U32),
    FsParamSpec::value("group_id", FsParamType::U32),
    FsParamSpec::flag("default_permissions"),
    FsParamSpec::flag("allow_other"),
    FsParamSpec::value("max_read", FsParamType::U32),
    FsParamSpec::value("blksize", FsParamType::U32),
    FsParamSpec::value("subtype", FsParamType::String),
];

/// The `/dev/fuse` channel the mount was given as a PINNED open file, if it was
/// given one.
///
/// `None` is not an error: `mount -o fd=17` supplies the same channel as a
/// decimal number and is resolved in the mounting task's descriptor table. The
/// LAST occurrence wins, matching the option string, where a repeated key
/// overwrites. # C: O(N_pinned)
pub fn pinned_channel(pinned: &[FsParameter]) -> Option<Arc<vfs::File>> {
    pinned.iter().rev().find(|p| p.key == FUSE_FD_KEY).and_then(|p| p.as_file()).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use vfs::fs::{FsParamVerdict, admit_fs_param as admit};

    fn accepted(p: &FsParameter) -> bool {
        matches!(admit(FUSE_PARAMS, p), FsParamVerdict::Accept(_))
    }

    // The literal option string libfuse builds for `mount(2)`.
    #[test]
    fn the_option_set_libfuse_passes_is_admitted() {
        for (k, v) in [("fd", "5"), ("rootmode", "40000"), ("user_id", "1000"),
                       ("group_id", "1000"), ("max_read", "131072"), ("blksize", "512"),
                       ("subtype", "sshfs"), ("source", "/dev/fuse")] {
            assert!(accepted(&FsParameter::string(k, v)), "fuse -o {k}={v}");
        }
        for k in ["default_permissions", "allow_other"] {
            assert!(accepted(&FsParameter::flag(k)), "fuse -o {k}");
        }
    }

    #[test]
    fn a_key_fuse_does_not_take_is_rejected() {
        assert_eq!(admit(FUSE_PARAMS, &FsParameter::string("nosuchopt", "1")),
            FsParamVerdict::Unknown);
        assert!(matches!(admit(FUSE_PARAMS, &FsParameter::flag("rootmode")),
            FsParamVerdict::WrongValueShape(_)));
    }
}
