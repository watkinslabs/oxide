// The parameters hugetlbfs accepts, published so `mount(2)` and `fsconfig(2)`
// reach the same verdict on a key.
//
// Value SHAPE (flag vs value) is the only thing admission checks, so it is the
// part that must be exact. The numeric spelling of a value is the parser's
// business (`mount_opts.rs`), not admission's — which is why the four size-ish
// keys are `String` rather than a numeric type: they take `k`/`m`/`g` suffixes
// and a trailing `%`, neither of which a plain integer shape admits.

use vfs::fs::{FsParamSpec, FsParamType};

/// `hugetlb_fs_parameters`.
pub static HUGETLBFS_PARAMS: &[FsParamSpec] = &[
    FsParamSpec::value("gid",       FsParamType::U32),
    FsParamSpec::value("min_size",  FsParamType::String),
    FsParamSpec::value("mode",      FsParamType::U32Oct),
    FsParamSpec::value("nr_inodes", FsParamType::String),
    FsParamSpec::value("pagesize",  FsParamType::String),
    FsParamSpec::value("size",      FsParamType::String),
    FsParamSpec::value("uid",       FsParamType::U32),
];

#[cfg(test)]
mod tests {
    use super::*;
    use vfs::fs::{FsParameter, FsParamVerdict, admit_fs_param as admit};

    fn accepted(p: &FsParameter) -> bool {
        matches!(admit(HUGETLBFS_PARAMS, p), FsParamVerdict::Accept(_))
    }

    #[test]
    fn every_option_a_real_hugetlbfs_mount_uses_is_admitted() {
        for (k, v) in [("size", "2G"), ("min_size", "512M"), ("nr_inodes", "1k"),
                       ("pagesize", "2M"), ("mode", "1777"), ("uid", "0"), ("gid", "0")] {
            assert!(accepted(&FsParameter::string(k, v)), "{k}={v} must be admitted");
        }
    }

    #[test]
    fn a_key_that_needs_a_value_is_refused_as_a_bare_flag() {
        for k in ["size", "min_size", "nr_inodes", "pagesize", "mode", "uid", "gid"] {
            assert!(!accepted(&FsParameter::flag(k)), "bare {k} must be refused");
        }
    }

    #[test]
    fn a_key_hugetlbfs_does_not_have_is_not_swallowed() {
        for k in ["huge", "noswap", "nr_blocks", "mpol", "quota"] {
            assert!(matches!(admit(HUGETLBFS_PARAMS, &FsParameter::string(k, "1")),
                             FsParamVerdict::Unknown), "{k} must not be admitted");
        }
    }
}
