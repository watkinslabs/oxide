//! Mount-option tables published at the VFS boundary.

use vfs::fs::{FsParamSpec, FsParamType};

macro_rules! fat_params {
    ($($specific:expr),* $(,)?) => {
        &[
            FsParamSpec::value("uid", FsParamType::U32),
            FsParamSpec::value("gid", FsParamType::U32),
            FsParamSpec::value("umask", FsParamType::U32Oct),
            FsParamSpec::value("dmask", FsParamType::U32Oct),
            FsParamSpec::value("fmask", FsParamType::U32Oct),
            FsParamSpec::value("allow_utime", FsParamType::U32Oct),
            FsParamSpec::value("codepage", FsParamType::U32),
            FsParamSpec::value("check", FsParamType::String),
            FsParamSpec::value("tz", FsParamType::String),
            FsParamSpec::value("time_offset", FsParamType::String),
            FsParamSpec::value("errors", FsParamType::String),
            FsParamSpec::flag("nfs"),
            FsParamSpec::value("nfs", FsParamType::String),
            FsParamSpec::flag("usefree"),
            FsParamSpec::flag("nocase"),
            FsParamSpec::flag("quiet"),
            FsParamSpec::flag("showexec"),
            FsParamSpec::flag("sys_immutable"),
            FsParamSpec::flag("flush"),
            FsParamSpec::flag("discard"),
            FsParamSpec::flag("dos1xfloppy"),
            $($specific),*
        ]
    };
}

/// Parameters accepted by the long-name filesystem type.
pub const VFAT_PARAMS: &[FsParamSpec] = fat_params![
    FsParamSpec::value("shortname", FsParamType::String),
    FsParamSpec::value("iocharset", FsParamType::String),
    FsParamSpec::flag("rodir"),
    FsParamSpec::flag("utf8"),
    FsParamSpec::value("utf8", FsParamType::String),
    FsParamSpec::flag("uni_xlate"),
    FsParamSpec::value("uni_xlate", FsParamType::String),
    FsParamSpec::flag("nonumtail"),
    FsParamSpec::value("nonumtail", FsParamType::String),
];

/// Parameters accepted by the short-name-only filesystem type.
pub const MSDOS_PARAMS: &[FsParamSpec] = fat_params![
    FsParamSpec::flag_no("dots"),
    FsParamSpec::flag("dotsOK"),
    FsParamSpec::value("dotsOK", FsParamType::String),
];
