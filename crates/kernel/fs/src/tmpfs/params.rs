// The parameters tmpfs and ramfs accept, published so `mount(2)` and
// `fsconfig(2)` reach the same verdict on a key.
//
// The list is the set the reference accepts, not the subset this
// implementation acts on — a mount that Linux accepts must not fail here, and
// a key Linux rejects must not be swallowed. Keys accepted but not yet acted
// on are recorded as known issues rather than quietly dropped from the table;
// removing a name from here makes real mounts FAIL, which is a different and
// much worse kind of dishonesty than accepting and ignoring.
//
// Value SHAPE (flag vs value) is the only thing admission checks, so it is the
// part that must be exact: `noswap` is a bare word and `mount -o noswap=1`
// must be refused, while `size` needs a value and `mount -o size` must be
// refused. The numeric spelling of a value is the parser's business
// (`mount_opts.rs`), not admission's.

use vfs::fs::{FsParamSpec, FsParamType};

/// `shmem_fs_parameters`. `casefold` is listed TWICE on purpose: the reference
/// carries it as both a bare flag (use the latest encoding) and a string (name
/// a UTF-8 version), and the lookup resolves whichever the caller supplied.
pub static TMPFS_PARAMS: &[FsParamSpec] = &[
    FsParamSpec::value("gid",        FsParamType::U32),
    FsParamSpec::value("huge",       FsParamType::String),
    FsParamSpec::value("mode",       FsParamType::U32Oct),
    FsParamSpec::value("mpol",       FsParamType::String),
    FsParamSpec::value("nr_blocks",  FsParamType::String),
    FsParamSpec::value("nr_inodes",  FsParamType::String),
    FsParamSpec::value("size",       FsParamType::String),
    FsParamSpec::value("uid",        FsParamType::U32),
    FsParamSpec::flag("inode32"),
    FsParamSpec::flag("inode64"),
    FsParamSpec::flag("noswap"),
    FsParamSpec::flag("quota"),
    FsParamSpec::flag("usrquota"),
    FsParamSpec::flag("grpquota"),
    FsParamSpec::value("usrquota_block_hardlimit", FsParamType::String),
    FsParamSpec::value("usrquota_inode_hardlimit", FsParamType::String),
    FsParamSpec::value("grpquota_block_hardlimit", FsParamType::String),
    FsParamSpec::value("grpquota_inode_hardlimit", FsParamType::String),
    FsParamSpec::value("casefold",   FsParamType::String),
    FsParamSpec::flag("casefold"),
    FsParamSpec::flag("strict_encoding"),
];

/// `ramfs_fs_parameters` — ramfs takes exactly one option, which is why it is
/// a separate table and not an alias of the tmpfs one.
pub static RAMFS_PARAMS: &[FsParamSpec] = &[
    FsParamSpec::value("mode", FsParamType::U32Oct),
];

#[cfg(test)]
mod tests {
    use super::*;
    use vfs::fs::{FsParameter, FsParamVerdict, admit_fs_param as admit};

    fn accepted(specs: &[FsParamSpec], p: &FsParameter) -> bool {
        matches!(admit(specs, p), FsParamVerdict::Accept(_))
    }

    // Every option the boot userspace passes to a tmpfs mount. If one of these
    // stops being accepted, /run, /tmp, /dev/shm or /run/user/<uid> fails to
    // mount and the session never starts.
    #[test]
    fn the_options_real_mounts_pass_are_all_admitted() {
        for (k, v) in [("mode", "0755"), ("mode", "1777"), ("mode", "0700"),
                       ("uid", "979"), ("gid", "979"),
                       ("size", "10%"), ("size", "4194304"), ("nr_blocks", "1024"),
                       ("nr_inodes", "819200"), ("huge", "never"), ("mpol", "local")] {
            assert!(accepted(TMPFS_PARAMS, &FsParameter::string(k, v)), "tmpfs -o {k}={v}");
        }
        for k in ["noswap", "inode32", "inode64", "usrquota", "grpquota", "quota"] {
            assert!(accepted(TMPFS_PARAMS, &FsParameter::flag(k)), "tmpfs -o {k}");
        }
    }

    #[test]
    fn a_key_tmpfs_does_not_take_is_rejected() {
        assert_eq!(admit(TMPFS_PARAMS, &FsParameter::string("nosuchopt", "1")),
            FsParamVerdict::Unknown);
        // ramfs options are NOT tmpfs options and vice versa.
        assert_eq!(admit(RAMFS_PARAMS, &FsParameter::string("size", "64m")),
            FsParamVerdict::Unknown);
        assert!(accepted(RAMFS_PARAMS, &FsParameter::string("mode", "0755")));
    }

    // Shape, not spelling: the two are different refusals and only one of them
    // may fall through to `source`.
    #[test]
    fn value_shape_is_enforced_both_ways() {
        assert!(matches!(admit(TMPFS_PARAMS, &FsParameter::string("noswap", "1")),
            FsParamVerdict::WrongValueShape(_)));
        assert!(matches!(admit(TMPFS_PARAMS, &FsParameter::flag("size")),
            FsParamVerdict::WrongValueShape(_)));
    }

    // The reference lists `casefold` as both shapes; both must resolve, and to
    // the entry that matches what the caller wrote.
    #[test]
    fn casefold_resolves_as_both_a_flag_and_a_value() {
        match admit(TMPFS_PARAMS, &FsParameter::string("casefold", "utf8-12.1.0")) {
            FsParamVerdict::Accept(m) => assert!(!m.spec.ty.is_flag()),
            other => panic!("expected value Accept, got {other:?}"),
        }
        match admit(TMPFS_PARAMS, &FsParameter::flag("casefold")) {
            FsParamVerdict::Accept(m) => assert!(m.spec.ty.is_flag()),
            other => panic!("expected flag Accept, got {other:?}"),
        }
    }

    // tmpfs opts into no `no<name>` spelling, so `nonoswap` is not a key.
    #[test]
    fn no_prefixed_spellings_are_not_invented() {
        assert_eq!(admit(TMPFS_PARAMS, &FsParameter::flag("noinode32")), FsParamVerdict::Unknown);
        assert_eq!(admit(TMPFS_PARAMS, &FsParameter::flag("nonoswap")), FsParamVerdict::Unknown);
    }
}
