// The 9P mount entry point: parse the options, resolve the transport, attach.

extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;

use ninep::opts::{self, Access, MountOpts};
use vfs::fs::{FsParamSpec, FsParamType};
use vfs::{KResult, VfsError};

use super::fs::{mount_session, NinepFs};

/// The filesystem type name a mount names.
pub const NINEP_FS_NAME: &str = "9p";

/// Options a 9P mount admits. A 9P mount has always IGNORED an option it does
/// not recognise, and the mount helpers rely on that, so the table is declared
/// for the ones that mean something and the parser lets the rest through.
pub static NINEP_PARAMS: &[FsParamSpec] = &[
    FsParamSpec::value("source", FsParamType::String),
    FsParamSpec::value("trans", FsParamType::String),
    FsParamSpec::value("version", FsParamType::String),
    FsParamSpec::value("msize", FsParamType::U32),
    FsParamSpec::value("access", FsParamType::String),
    FsParamSpec::value("cache", FsParamType::String),
    FsParamSpec::value("cachetag", FsParamType::String),
    FsParamSpec::value("aname", FsParamType::String),
    FsParamSpec::value("uname", FsParamType::String),
    FsParamSpec::value("dfltuid", FsParamType::U32),
    FsParamSpec::value("dfltgid", FsParamType::U32),
    FsParamSpec::value("debug", FsParamType::String),
    FsParamSpec::value("afid", FsParamType::U32),
    FsParamSpec::value("negtimeout", FsParamType::U32),
    FsParamSpec::value("locktimeout", FsParamType::U32),
    FsParamSpec::value("rfdno", FsParamType::U32),
    FsParamSpec::value("wfdno", FsParamType::U32),
    FsParamSpec::value("port", FsParamType::U32),
    FsParamSpec::flag("posixacl"),
    FsParamSpec::flag("noextend"),
    FsParamSpec::flag("nodevmap"),
    FsParamSpec::flag("directio"),
    FsParamSpec::flag("noxattr"),
    FsParamSpec::flag("ignoreqv"),
    FsParamSpec::flag("privport"),
];

/// The numeric identity a mount attaches under.
///
/// `access=<uid>` names one explicitly. `access=any` uses the mount's own
/// default, since every user shares one handle. The per-user modes attach as
/// the mounting caller, which is the identity the server will check every
/// operation against. # C: O(1)
pub fn attach_uid(opts: &MountOpts, caller_uid: u32) -> u32 {
    match opts.access {
        Access::Single(u) => u,
        Access::Any => opts.dfltuid,
        Access::User | Access::Client => caller_uid,
    }
}

/// Mount a 9P share.
///
/// `source` is the transport's device name: a virtio mount tag, a host, or a
/// socket path. `data` is the raw option string. # C: options + two RPCs
pub fn mount_9p(source: &str, data: &str, caller_uid: u32) -> KResult<Arc<NinepFs>> {
    let parsed = opts::parse(source, data).map_err(VfsError::from)?;
    let transport = ninep::transport::registry::open(&parsed).map_err(VfsError::from)?;
    let uid = attach_uid(&parsed, caller_uid);
    mount_session(transport, parsed, uid)
}

/// Render the option tail for a mount table. # C: O(1)
pub fn show_options(opts: &MountOpts) -> String { opts.show() }
