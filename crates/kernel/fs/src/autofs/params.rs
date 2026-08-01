// The parameters autofs accepts, published so `mount(2)` and `fsconfig(2)`
// reach the same verdict on a key.
//
// autofs is mounted exclusively by automount(8)/systemd-automount, which
// always names `fd=`, `pgrp=`, `minproto=`, `maxproto=` plus exactly one of
// `direct`/`indirect`/`offset`. Every one of those must be admitted or no
// automount unit can start.

use vfs::fs::{FsParamSpec, FsParamType};

/// `autofs_param_specs`.
pub static AUTOFS_PARAMS: &[FsParamSpec] = &[
    FsParamSpec::flag("direct"),
    FsParamSpec::value("fd", FsParamType::Fd),
    FsParamSpec::value("gid", FsParamType::U32),
    FsParamSpec::flag("ignore"),
    FsParamSpec::flag("indirect"),
    FsParamSpec::value("maxproto", FsParamType::U32),
    FsParamSpec::value("minproto", FsParamType::U32),
    FsParamSpec::flag("offset"),
    FsParamSpec::value("pgrp", FsParamType::U32),
    FsParamSpec::flag("strictexpire"),
    FsParamSpec::value("uid", FsParamType::U32),
];

#[cfg(test)]
mod tests {
    use super::*;
    use vfs::fs::{FsParameter, FsParamVerdict, admit_fs_param as admit};

    fn accepted(p: &FsParameter) -> bool {
        matches!(admit(AUTOFS_PARAMS, p), FsParamVerdict::Accept(_))
    }

    // The literal option set systemd-automount hands `mount(2)`.
    #[test]
    fn the_option_set_an_automount_unit_passes_is_admitted() {
        for (k, v) in [("fd", "3"), ("pgrp", "1"), ("minproto", "5"), ("maxproto", "5"),
                       ("uid", "0"), ("gid", "0")] {
            assert!(accepted(&FsParameter::string(k, v)), "autofs -o {k}={v}");
        }
        for k in ["direct", "indirect", "offset", "strictexpire", "ignore"] {
            assert!(accepted(&FsParameter::flag(k)), "autofs -o {k}");
        }
    }

    #[test]
    fn a_key_autofs_does_not_take_is_rejected() {
        assert_eq!(admit(AUTOFS_PARAMS, &FsParameter::string("timeout", "60")),
            FsParamVerdict::Unknown);
        assert!(matches!(admit(AUTOFS_PARAMS, &FsParameter::flag("fd")),
            FsParamVerdict::WrongValueShape(_)));
        assert!(matches!(admit(AUTOFS_PARAMS, &FsParameter::string("direct", "1")),
            FsParamVerdict::WrongValueShape(_)));
    }
}
