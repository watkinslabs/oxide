// The parameters ext4 accepts, published so `mount(2)` and `fsconfig(2)` reach
// the same verdict on a key.
//
// This is the reference's list in full, including the names it keeps only to
// accept-and-warn (options removed from the filesystem years ago, and the
// ext2/ext3 spellings ext4 still answers to). Those entries are load-bearing:
// dropping one turns a mount the reference accepts into a hard failure, and
// `/` is the mount in question.
//
// Admission checks value SHAPE only. Several names are deliberately listed
// twice with different shapes — the reference accepts `barrier`, `dax`,
// `auto_da_alloc`, `init_itable` and `test_dummy_encryption` both as a bare
// word and with a value — and the lookup resolves whichever the caller wrote.
//
// Which of these this implementation ACTS on is a separate question from which
// it accepts; the quota family is honoured (`Ext4Mount::open_with_data`), the
// rest are accepted and recorded as known issues. Silence here would be a
// worse answer than either.

use vfs::fs::{FsParamSpec, FsParamType};

/// `ext4_param_specs`.
pub static EXT4_PARAMS: &[FsParamSpec] = &[
    FsParamSpec::flag("bsddf"),
    FsParamSpec::flag("minixdf"),
    FsParamSpec::flag("grpid"),
    FsParamSpec::flag("bsdgroups"),
    FsParamSpec::flag("nogrpid"),
    FsParamSpec::flag("sysvgroups"),
    FsParamSpec::value("resgid", FsParamType::U32),
    FsParamSpec::value("resuid", FsParamType::U32),
    FsParamSpec::value("sb", FsParamType::U32),
    FsParamSpec::value("errors", FsParamType::String),
    FsParamSpec::flag("nouid32"),
    FsParamSpec::flag("debug"),
    FsParamSpec::flag("oldalloc"),
    FsParamSpec::flag("orlov"),
    FsParamSpec::flag("user_xattr"),
    FsParamSpec::flag("acl"),
    FsParamSpec::flag("norecovery"),
    FsParamSpec::flag("noload"),
    FsParamSpec::flag("bh"),
    FsParamSpec::flag("nobh"),
    FsParamSpec::value("commit", FsParamType::U32),
    FsParamSpec::value("min_batch_time", FsParamType::U32),
    FsParamSpec::value("max_batch_time", FsParamType::U32),
    FsParamSpec::value("journal_dev", FsParamType::U32),
    FsParamSpec::value("journal_path", FsParamType::Path),
    FsParamSpec::flag("journal_checksum"),
    FsParamSpec::flag("nojournal_checksum"),
    FsParamSpec::flag("journal_async_commit"),
    FsParamSpec::flag("abort"),
    FsParamSpec::value("data", FsParamType::String),
    FsParamSpec::value("data_err", FsParamType::String),
    FsParamSpec::value("usrjquota", FsParamType::String),
    FsParamSpec::value("grpjquota", FsParamType::String),
    FsParamSpec::value("jqfmt", FsParamType::String),
    FsParamSpec::flag("grpquota"),
    FsParamSpec::flag("quota"),
    FsParamSpec::flag("noquota"),
    FsParamSpec::flag("usrquota"),
    FsParamSpec::flag("prjquota"),
    FsParamSpec::flag("barrier"),
    FsParamSpec::value("barrier", FsParamType::U32),
    FsParamSpec::flag("nobarrier"),
    FsParamSpec::flag("i_version"),
    FsParamSpec::flag("dax"),
    FsParamSpec::value("dax", FsParamType::String),
    FsParamSpec::value("stripe", FsParamType::U32),
    FsParamSpec::flag("delalloc"),
    FsParamSpec::flag("nodelalloc"),
    FsParamSpec::flag("warn_on_error"),
    FsParamSpec::flag("nowarn_on_error"),
    FsParamSpec::value("debug_want_extra_isize", FsParamType::U32),
    FsParamSpec::flag("mblk_io_submit"),
    FsParamSpec::flag("nomblk_io_submit"),
    FsParamSpec::flag("block_validity"),
    FsParamSpec::flag("noblock_validity"),
    FsParamSpec::value("inode_readahead_blks", FsParamType::U32),
    FsParamSpec::value("journal_ioprio", FsParamType::U32),
    FsParamSpec::value("auto_da_alloc", FsParamType::U32),
    FsParamSpec::flag("auto_da_alloc"),
    FsParamSpec::flag("noauto_da_alloc"),
    FsParamSpec::flag("dioread_nolock"),
    FsParamSpec::flag("nodioread_nolock"),
    FsParamSpec::flag("dioread_lock"),
    FsParamSpec::flag("discard"),
    FsParamSpec::flag("nodiscard"),
    FsParamSpec::value("init_itable", FsParamType::U32),
    FsParamSpec::flag("init_itable"),
    FsParamSpec::flag("noinit_itable"),
    FsParamSpec::value("max_dir_size_kb", FsParamType::U32),
    FsParamSpec::flag("test_dummy_encryption"),
    FsParamSpec::value("test_dummy_encryption", FsParamType::String),
    FsParamSpec::flag("inlinecrypt"),
    FsParamSpec::flag("nombcache"),
    FsParamSpec::flag("no_mbcache"),
    FsParamSpec::flag("prefetch_block_bitmaps"),
    FsParamSpec::flag("no_prefetch_block_bitmaps"),
    FsParamSpec::value("mb_optimize_scan", FsParamType::U32),
    FsParamSpec::value("check", FsParamType::String),
    FsParamSpec::flag("nocheck"),
    FsParamSpec::flag("reservation"),
    FsParamSpec::flag("noreservation"),
    FsParamSpec::value("journal", FsParamType::U32),
];

#[cfg(test)]
mod tests {
    use super::*;
    use vfs::fs::{FsParameter, FsParamVerdict, admit_fs_param as admit};

    fn accepted(p: &FsParameter) -> bool {
        matches!(admit(EXT4_PARAMS, p), FsParamVerdict::Accept(_))
    }

    // The options a real root filesystem is mounted and remounted with. `/` is
    // the mount at stake, so each of these failing is an unbootable system.
    #[test]
    fn the_options_a_root_filesystem_is_mounted_with_are_admitted() {
        for (k, v) in [("data", "ordered"), ("data", "writeback"), ("data", "journal"),
                       ("errors", "remount-ro"), ("errors", "continue"), ("errors", "panic"),
                       ("commit", "5"), ("stripe", "0"), ("jqfmt", "vfsv0"),
                       ("usrjquota", "aquota.user"), ("grpjquota", "aquota.group"),
                       ("resuid", "0"), ("resgid", "0"), ("journal_ioprio", "3")] {
            assert!(accepted(&FsParameter::string(k, v)), "ext4 -o {k}={v}");
        }
        for k in ["acl", "user_xattr", "barrier", "nobarrier", "discard", "nodiscard",
                  "delalloc", "nodelalloc", "noload", "norecovery", "quota", "noquota",
                  "usrquota", "grpquota", "prjquota", "journal_checksum", "block_validity",
                  "nombcache", "inlinecrypt", "dioread_nolock", "init_itable", "noinit_itable"] {
            assert!(accepted(&FsParameter::flag(k)), "ext4 -o {k}");
        }
    }

    // An empty journalled-quota name CLEARS the quota file. It is a value, not
    // a flag, so it must round-trip as an empty string rather than degrade to a
    // bare word.
    #[test]
    fn an_empty_journalled_quota_name_is_a_value_not_a_flag() {
        assert!(accepted(&FsParameter::string("usrjquota", "")));
        assert!(matches!(admit(EXT4_PARAMS, &FsParameter::flag("usrjquota")),
            FsParamVerdict::WrongValueShape(_)));
    }

    // The names the reference keeps only to accept-and-warn still have to be
    // accepted; a mount naming one must not fail.
    #[test]
    fn removed_and_ext2_era_spellings_are_still_accepted() {
        for k in ["oldalloc", "orlov", "bh", "nobh", "i_version", "mblk_io_submit",
                  "nomblk_io_submit", "nocheck", "reservation", "noreservation",
                  "prefetch_block_bitmaps", "no_mbcache"] {
            assert!(accepted(&FsParameter::flag(k)), "ext4 -o {k}");
        }
        assert!(accepted(&FsParameter::string("journal", "0")));
        assert!(accepted(&FsParameter::string("check", "none")));
    }

    // The names carried in both shapes resolve to whichever the caller wrote.
    #[test]
    fn dual_shape_names_resolve_by_what_the_caller_supplied() {
        for k in ["barrier", "dax", "auto_da_alloc", "init_itable", "test_dummy_encryption"] {
            match admit(EXT4_PARAMS, &FsParameter::flag(k)) {
                FsParamVerdict::Accept(m) => assert!(m.spec.ty.is_flag(), "{k} as flag"),
                other => panic!("{k} flag: {other:?}"),
            }
            match admit(EXT4_PARAMS, &FsParameter::string(k, "1")) {
                FsParamVerdict::Accept(m) => assert!(!m.spec.ty.is_flag(), "{k} as value"),
                other => panic!("{k} value: {other:?}"),
            }
        }
    }

    #[test]
    fn a_key_ext4_does_not_take_is_rejected() {
        assert_eq!(admit(EXT4_PARAMS, &FsParameter::string("nosuchopt", "1")),
            FsParamVerdict::Unknown);
        // A near-miss on a real key is still a miss, not a silent accept.
        assert_eq!(admit(EXT4_PARAMS, &FsParameter::string("dat", "ordered")),
            FsParamVerdict::Unknown);
        // The reference does not carry these spellings, so neither do we.
        assert_eq!(admit(EXT4_PARAMS, &FsParameter::flag("noacl")), FsParamVerdict::Unknown);
        assert_eq!(admit(EXT4_PARAMS, &FsParameter::flag("nouser_xattr")),
            FsParamVerdict::Unknown);
    }
}
