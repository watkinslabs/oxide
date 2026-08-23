//! What one mount was asked for, and what it reports back.
//!
//! NTFS records an owner and a security descriptor per file, but neither is a
//! POSIX identity: the mount's `uid=`/`gid=`/`fmask=`/`dmask=` are what a
//! caller sees, exactly as on FAT and exFAT, unless `acl` asks for the
//! descriptor's own answer.

use alloc::format;
use alloc::string::String;

use syscall::errno::Errno;

/// How NTFS named data streams are presented to callers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StreamInterface {
    None,
    Xattr,
    Windows,
}

/// Longest name this filesystem admits.
pub const NTFS_NAME_MAX: u64 = crate::uapi::NTFS_NAME_LEN as u64;

/// Permission bits `allow_utime=` may carry.
pub const UTIME_BITS: u16 = 0o022;

/// Everything one mount was asked for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Options {
    pub uid: u32,
    pub gid: u32,
    pub fmask: u16,
    pub dmask: u16,
    pub allow_utime: Option<u16>,
    /// Whether hidden and system files are listed.
    pub show_sys_files: bool,
    /// Whether the file's own security descriptor decides its mode.
    pub acl: bool,
    /// Whether a name may differ from another only in case.
    pub case_sensitive: bool,
    /// Whether freed clusters are discarded on the device.
    pub discard: bool,
    /// Whether the journal is replayed at mount.
    pub force: bool,
    /// How alternate data streams are presented.
    pub streams: StreamInterface,
    /// Whether a compressed file may be created.
    pub compress: bool,
    /// Whether every metadata write reaches the medium immediately.
    pub sync: bool,
}

impl Options {
    /// What a mount that named nothing gets. # C: O(1)
    pub fn defaults() -> Self {
        Self {
            uid: 0,
            gid: 0,
            fmask: 0,
            dmask: 0,
            allow_utime: None,
            show_sys_files: false,
            acl: false,
            case_sensitive: false,
            discard: false,
            force: false,
            streams: StreamInterface::Xattr,
            compress: false,
            sync: false,
        }
    }

    /// Fill in what the mount did not say but must still have. # C: O(1)
    pub fn settle(&mut self) {
        if self.allow_utime.is_none() { self.allow_utime = Some(!self.dmask & UTIME_BITS); }
    }

    /// The write bits a non-owner may set times through. # C: O(1)
    pub fn utime_bits(&self) -> u16 { self.allow_utime.unwrap_or(!self.dmask & UTIME_BITS) }
}

/// Separator between options, and between a key and its value.
const SEP: char = ',';
const ASSIGN: char = '=';

/// Parse `data` on top of `base`.
///
/// A key this filesystem does not know is skipped rather than refused: the
/// generic per-mount words travel in the same string. A key it DOES know with
/// a value it cannot read is `EINVAL`.
/// # C: O(len(data))
pub fn parse(base: Options, data: &str) -> Result<Options, Errno> {
    let mut o = base;
    for token in data.split(SEP).map(str::trim).filter(|t| !t.is_empty()) {
        let (key, val) = match token.split_once(ASSIGN) {
            Some((k, v)) => (k, Some(v)),
            None => (token, None),
        };
        one(&mut o, key, val)?;
    }
    o.settle();
    Ok(o)
}

/// Apply one key. # C: O(1)
fn one(o: &mut Options, key: &str, val: Option<&str>) -> Result<(), Errno> {
    match key {
        "uid" => o.uid = dec(val)?,
        "gid" => o.gid = dec(val)?,
        "umask" => { let m = mask(val)?; o.fmask = m; o.dmask = m; }
        "fmask" => o.fmask = mask(val)?,
        "dmask" => o.dmask = mask(val)?,
        "allow_utime" => o.allow_utime = Some(mask(val)? & UTIME_BITS),
        "iocharset" | "nls" => { charset(need(val)?)?; }
        "sys_immutable" | "showmeta" => { flag(val)?; o.show_sys_files = true; }
        "acl" => { flag(val)?; o.acl = true; }
        "noacl" => { flag(val)?; o.acl = false; }
        "case_sensitive" => { flag(val)?; o.case_sensitive = true; }
        "nocase_sensitive" => { flag(val)?; o.case_sensitive = false; }
        "discard" => { flag(val)?; o.discard = true; }
        "nodiscard" => { flag(val)?; o.discard = false; }
        "force" => { flag(val)?; o.force = true; }
        "noforce" => { flag(val)?; o.force = false; }
        "streams_interface" => o.streams = streams(need(val)?)?,
        "compress" => { flag(val)?; o.compress = true; }
        "nocompress" => { flag(val)?; o.compress = false; }
        "sparse" | "nosparse" | "prealloc" | "noprealloc" | "hide_dot_files" => flag(val)?,
        _ => {}
    }
    Ok(())
}

/// A key that must carry a value. # C: O(1)
fn need(val: Option<&str>) -> Result<&str, Errno> { val.ok_or(Errno::Einval) }

/// A key that must NOT carry one. # C: O(1)
fn flag(val: Option<&str>) -> Result<(), Errno> {
    if val.is_some() { return Err(Errno::Einval); }
    Ok(())
}

/// A decimal value. # C: O(len)
fn dec(val: Option<&str>) -> Result<u32, Errno> {
    need(val)?.parse::<u32>().map_err(|_| Errno::Einval)
}

/// An OCTAL permission mask. # C: O(len)
fn mask(val: Option<&str>) -> Result<u16, Errno> {
    let text = need(val)?;
    if text.is_empty() { return Err(Errno::Einval); }
    u16::from_str_radix(text, 8).map_err(|_| Errno::Einval)
}

/// The one charset spelling this build can honour. # C: O(len)
fn charset(val: &str) -> Result<(), Errno> {
    if !val.eq_ignore_ascii_case("utf8") { return Err(Errno::Einval); }
    Ok(())
}

/// How alternate data streams are presented. # C: O(1)
fn streams(val: &str) -> Result<StreamInterface, Errno> {
    match val {
        "none" => Ok(StreamInterface::None),
        "xattr" => Ok(StreamInterface::Xattr),
        "windows" => Ok(StreamInterface::Windows),
        _ => Err(Errno::Einval),
    }
}

/// Render `o` as the tail `/proc/mounts` carries. # C: O(number of options)
pub fn show(o: &Options) -> String {
    let mut s = String::new();
    if o.uid != 0 { s.push_str(&format!(",uid={}", o.uid)); }
    if o.gid != 0 { s.push_str(&format!(",gid={}", o.gid)); }
    s.push_str(&format!(",fmask={:04o}", o.fmask));
    s.push_str(&format!(",dmask={:04o}", o.dmask));
    if let Some(bits) = o.allow_utime {
        if bits != 0 { s.push_str(&format!(",allow_utime={:04o}", bits)); }
    }
    s.push_str(",iocharset=utf8");
    if o.show_sys_files { s.push_str(",showmeta"); }
    if o.acl { s.push_str(",acl"); }
    if o.case_sensitive { s.push_str(",case_sensitive"); }
    if o.discard { s.push_str(",discard"); }
    if o.force { s.push_str(",force"); }
    s.push_str(match o.streams {
        StreamInterface::None => ",streams_interface=none",
        StreamInterface::Xattr => ",streams_interface=xattr",
        StreamInterface::Windows => ",streams_interface=windows",
    });
    if o.compress { s.push_str(",compress"); }
    s
}

#[cfg(test)]
#[path = "tests/opts.rs"]
mod tests;
