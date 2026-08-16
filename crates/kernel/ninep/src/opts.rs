// Mount-option parsing for a 9P mount.
//
// Pure: takes the option string, yields a typed set or an error. Nothing here
// touches a transport or a superblock, so every default, every clamp and every
// rejection is checkable hosted.

extern crate alloc;
use alloc::string::{String, ToString};

use crate::codec::Dialect;
use crate::err::{NpError, NpResult};
use crate::uapi::limits;

/// Cache-policy bits. A mode is a SET of these, not an ordinal: `loose`
/// enables four behaviours at once and `mmap` two, so testing for one
/// behaviour must test its bit and never compare the whole mode.
pub mod cache_bits {
    /// Page-cache file data (enables readahead).
    pub const FILE: u32 = 0x01;
    /// Cache metadata and dentries across lookups.
    pub const META: u32 = 0x02;
    /// Allow dirty pages, hence writable shared mappings.
    pub const WRITEBACK: u32 = 0x04;
    /// Accept non-coherent caching: do not revalidate against the server.
    pub const LOOSE: u32 = 0x08;
    /// Additionally persist pages in a local backing cache.
    pub const FSCACHE: u32 = 0x80;
}

/// Named cache policies, spelled as the mount option spells them.
pub mod cache_modes {
    use super::cache_bits::*;
    /// Every access reaches the server.
    pub const NONE: u32 = 0;
    /// File data may be read ahead, nothing else is cached.
    pub const READAHEAD: u32 = FILE;
    /// Adds dirty pages, which is what a writable shared mapping needs.
    pub const MMAP: u32 = FILE | WRITEBACK;
    /// Cache data and metadata without revalidating.
    pub const LOOSE_MODE: u32 = FILE | META | WRITEBACK | LOOSE;
    /// `loose` plus a persistent local cache.
    pub const FSCACHE_MODE: u32 = LOOSE_MODE | FSCACHE;
}

/// Who a mount performs operations as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// One attach per accessing user; the SERVER enforces permissions.
    User,
    /// One shared attach for everybody.
    Any,
    /// One attach per accessing user, and the CLIENT also enforces the POSIX
    /// permission bits it read. Requires the `.L` dialect, which is the only
    /// one that reports usable numeric owners and modes.
    Client,
    /// Only this numeric user may use the mount at all.
    Single(u32),
}

/// Which transport a mount asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trans {
    /// A virtio-9p device, selected by its mount tag.
    Virtio,
    /// Two already-open descriptors supplied by the caller.
    Fd,
    /// A TCP connection to the mount source.
    Tcp,
    /// A Unix-domain stream socket at the mount source path.
    Unix,
}

impl Trans {
    /// # C: O(1)
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "virtio" => Some(Trans::Virtio),
            "fd" => Some(Trans::Fd),
            "tcp" => Some(Trans::Tcp),
            "unix" => Some(Trans::Unix),
            _ => None,
        }
    }
    /// # C: O(1)
    pub fn as_str(self) -> &'static str {
        match self {
            Trans::Virtio => "virtio", Trans::Fd => "fd",
            Trans::Tcp => "tcp", Trans::Unix => "unix",
        }
    }
}

/// Default owner reported for an object on a mount whose dialect has no
/// numeric ids. Not zero: attributing an unknown server-side owner to root
/// would grant root's access on a client-enforcing mount.
pub const DEFAULT_UID: u32 = u32::MAX - 1;
/// Group counterpart of [`DEFAULT_UID`].
pub const DEFAULT_GID: u32 = u32::MAX - 1;
/// Attach name used when the mount names no user.
pub const DEFAULT_UNAME: &str = "nobody";
/// Seconds a blocking lock waits between retries when the server says the
/// range is contended.
pub const DEFAULT_LOCK_TIMEOUT_SECS: u32 = 30;
/// Milliseconds a negative dentry survives under `cache=loose`, which has no
/// revalidation to notice the name appearing.
pub const LOOSE_NEG_TIMEOUT_MS: u32 = 24 * 60 * 60 * 1000;

/// A parsed 9P mount.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountOpts {
    /// Mount source: a virtio tag, a host, or a socket path.
    pub source: String,
    pub trans: Trans,
    pub version: Dialect,
    pub msize: u32,
    pub access: Access,
    pub cache: u32,
    /// Name of the persistent cache volume under `cache=fscache`.
    pub cachetag: Option<String>,
    /// Tree name passed in `Tattach`.
    pub aname: String,
    /// User name passed in `Tattach`.
    pub uname: String,
    pub dfltuid: u32,
    pub dfltgid: u32,
    pub posixacl: bool,
    pub debug: u32,
    /// Refuse to materialise device, socket and fifo nodes the server reports.
    pub nodev: bool,
    /// Bypass the page cache for every handle on this mount.
    pub directio: bool,
    pub noxattr: bool,
    /// Do not treat `qid.version == 0` as "never cache this object".
    pub ignoreqv: bool,
    /// Pre-established authentication fid, if the caller obtained one.
    pub afid: Option<u32>,
    /// Milliseconds a negative dentry is retained.
    pub negtimeout_ms: u32,
    /// Seconds between blocking-lock retries.
    pub locktimeout_secs: u32,
    /// `trans=fd` read descriptor.
    pub rfdno: Option<u32>,
    /// `trans=fd` write descriptor.
    pub wfdno: Option<u32>,
    pub port: u16,
    /// Bind the local end of a TCP connection to a reserved port.
    pub privport: bool,
}

impl Default for MountOpts {
    fn default() -> Self {
        Self {
            source: String::new(),
            trans: Trans::Virtio,
            version: Dialect::DotL,
            msize: limits::DEFAULT_MSIZE,
            access: Access::User,
            cache: cache_modes::NONE,
            cachetag: None,
            aname: String::new(),
            uname: DEFAULT_UNAME.to_string(),
            dfltuid: DEFAULT_UID,
            dfltgid: DEFAULT_GID,
            posixacl: false,
            debug: 0,
            nodev: false,
            directio: false,
            noxattr: false,
            ignoreqv: false,
            afid: None,
            negtimeout_ms: 0,
            locktimeout_secs: DEFAULT_LOCK_TIMEOUT_SECS,
            rfdno: None,
            wfdno: None,
            port: limits::FD_PORT,
            privport: false,
        }
    }
}

fn parse_u32(v: &str) -> NpResult<u32> {
    if v.is_empty() { return Err(NpError::Server(22)); }
    let mut n: u32 = 0;
    for b in v.bytes() {
        let d = match b { b'0'..=b'9' => u32::from(b - b'0'), _ => return Err(NpError::Server(22)) };
        n = n.checked_mul(10).and_then(|x| x.checked_add(d)).ok_or(NpError::Server(22))?;
    }
    Ok(n)
}

fn parse_hex32(v: &str) -> NpResult<u32> {
    let s = v.strip_prefix("0x").unwrap_or(v);
    if s.is_empty() { return Err(NpError::Server(22)); }
    let mut n: u32 = 0;
    for b in s.bytes() {
        let d = match b {
            b'0'..=b'9' => u32::from(b - b'0'),
            b'a'..=b'f' => u32::from(b - b'a') + 10,
            b'A'..=b'F' => u32::from(b - b'A') + 10,
            _ => return Err(NpError::Server(22)),
        };
        n = n.checked_mul(16).and_then(|x| x.checked_add(d)).ok_or(NpError::Server(22))?;
    }
    Ok(n)
}

/// Resolve a `cache=` word. An unrecognised word is an ERROR, not a fallback to
/// `none`: silently mounting uncached when the caller asked for writeback turns
/// a performance option into a correctness surprise the caller cannot see.
/// # C: O(1)
pub fn parse_cache(v: &str) -> NpResult<u32> {
    match v {
        "none" => Ok(cache_modes::NONE),
        "readahead" => Ok(cache_modes::READAHEAD),
        "mmap" => Ok(cache_modes::MMAP),
        "loose" => Ok(cache_modes::LOOSE_MODE),
        "fscache" => Ok(cache_modes::FSCACHE_MODE),
        _ => Err(NpError::Server(22)),
    }
}

/// Resolve an `access=` word: a name, or a bare numeric user id. # C: O(1)
pub fn parse_access(v: &str) -> NpResult<Access> {
    match v {
        "user" => Ok(Access::User),
        "any" => Ok(Access::Any),
        "client" => Ok(Access::Client),
        _ => Ok(Access::Single(parse_u32(v)?)),
    }
}

/// Parse a comma-separated 9P option string over `source`.
///
/// An UNKNOWN option is ignored, matching how a 9P mount has always behaved and
/// what the mount helpers rely on. A KNOWN option with a bad value is an error:
/// the caller named something this code understands and got it wrong.
/// # C: O(len)
pub fn parse(source: &str, data: &str) -> NpResult<MountOpts> {
    let mut o = MountOpts { source: source.to_string(), ..Default::default() };
    let mut saw_access = false;
    let mut saw_negtimeout = false;

    for item in data.split(',') {
        let item = item.trim();
        if item.is_empty() { continue; }
        let (key, val) = match item.split_once('=') { Some((k, v)) => (k, v), None => (item, "") };
        match key {
            "trans" => o.trans = Trans::parse(val).ok_or(NpError::Server(22))?,
            "version" => o.version = Dialect::parse(val).ok_or(NpError::Server(22))?,
            "noextend" => o.version = Dialect::Legacy,
            "msize" => o.msize = parse_u32(val)?,
            "access" => { o.access = parse_access(val)?; saw_access = true; }
            "cache" => o.cache = parse_cache(val)?,
            "cachetag" => o.cachetag = Some(val.to_string()),
            "aname" => o.aname = val.to_string(),
            "uname" => o.uname = val.to_string(),
            "dfltuid" => o.dfltuid = parse_u32(val)?,
            "dfltgid" => o.dfltgid = parse_u32(val)?,
            "posixacl" => o.posixacl = true,
            "debug" => o.debug = parse_hex32(val)?,
            "nodevmap" => o.nodev = true,
            "directio" => o.directio = true,
            "noxattr" => o.noxattr = true,
            "ignoreqv" => o.ignoreqv = true,
            "afid" => o.afid = Some(parse_u32(val)?),
            "negtimeout" => { o.negtimeout_ms = parse_u32(val)?; saw_negtimeout = true; }
            "locktimeout" => {
                let t = parse_u32(val)?;
                if t == 0 { return Err(NpError::Server(22)); }
                o.locktimeout_secs = t;
            }
            "rfdno" => o.rfdno = Some(parse_u32(val)?),
            "wfdno" => o.wfdno = Some(parse_u32(val)?),
            "port" => {
                let p = parse_u32(val)?;
                if p == 0 || p > u32::from(u16::MAX) { return Err(NpError::Server(22)); }
                o.port = p as u16;
            }
            "privport" => o.privport = true,
            _ => {}
        }
    }

    if o.msize < limits::MIN_MSIZE { return Err(NpError::Server(22)); }
    if o.msize > i32::MAX as u32 { return Err(NpError::Server(22)); }

    // `access=client` means the CLIENT checks the permission bits, which needs
    // the numeric owners and POSIX mode only the `.L` dialect reports. Asking
    // for it on another dialect would enforce against fields that are not
    // there, so the mount falls back to server-side checking.
    if o.access == Access::Client && o.version != Dialect::DotL { o.access = Access::User; }
    // `.L` defaults to client-side checking; other dialects to server-side.
    if !saw_access && o.version == Dialect::DotL { o.access = Access::Client; }
    // POSIX ACLs are only meaningful where the client is the one deciding.
    if o.posixacl && !(o.version == Dialect::DotL && o.access == Access::Client) { o.posixacl = false; }
    // Nothing revalidates a negative name under `loose`, so one must expire on
    // its own or a file created on the server never becomes visible.
    if !saw_negtimeout && o.cache & cache_bits::LOOSE != 0 { o.negtimeout_ms = LOOSE_NEG_TIMEOUT_MS; }
    // Both descriptors are required together: a `trans=fd` mount with only one
    // can read or write but not both, and would wedge on its first reply.
    if o.trans == Trans::Fd && (o.rfdno.is_none() || o.wfdno.is_none()) {
        return Err(NpError::Server(92));
    }
    if o.source.is_empty() && o.trans != Trans::Fd { return Err(NpError::Server(22)); }
    Ok(o)
}

impl MountOpts {
    /// True when file data may live in the page cache. # C: O(1)
    pub fn caches_data(&self) -> bool { self.cache & cache_bits::FILE != 0 }
    /// True when metadata and dentries survive between lookups. # C: O(1)
    pub fn caches_meta(&self) -> bool { self.cache & cache_bits::META != 0 }
    /// True when a writable shared mapping is allowed. # C: O(1)
    pub fn allows_writeback(&self) -> bool { self.cache & cache_bits::WRITEBACK != 0 }
    /// True when cached state is used without revalidating. # C: O(1)
    pub fn is_loose(&self) -> bool { self.cache & cache_bits::LOOSE != 0 }

    /// Render the option tail a mount table shows. Secrets are not among these
    /// fields, but descriptor numbers are meaningless to a reader and omitted.
    /// # C: O(1)
    pub fn show(&self) -> String {
        let mut s = String::new();
        s.push_str("trans="); s.push_str(self.trans.as_str());
        s.push_str(",version="); s.push_str(self.version.as_str());
        s.push_str(",msize=");
        push_num(&mut s, u64::from(self.msize));
        s.push_str(",access=");
        match self.access {
            Access::User => s.push_str("user"),
            Access::Any => s.push_str("any"),
            Access::Client => s.push_str("client"),
            Access::Single(u) => push_num(&mut s, u64::from(u)),
        }
        s.push_str(",cache=");
        s.push_str(match self.cache {
            cache_modes::NONE => "none",
            cache_modes::READAHEAD => "readahead",
            cache_modes::MMAP => "mmap",
            cache_modes::LOOSE_MODE => "loose",
            cache_modes::FSCACHE_MODE => "fscache",
            _ => "none",
        });
        if !self.aname.is_empty() { s.push_str(",aname="); s.push_str(&self.aname); }
        if !self.uname.is_empty() { s.push_str(",uname="); s.push_str(&self.uname); }
        if self.posixacl { s.push_str(",posixacl"); }
        if self.nodev { s.push_str(",nodevmap"); }
        if self.directio { s.push_str(",directio"); }
        if self.noxattr { s.push_str(",noxattr"); }
        s
    }
}

fn push_num(s: &mut String, mut n: u64) {
    if n == 0 { s.push('0'); return; }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while n > 0 { i -= 1; buf[i] = b'0' + (n % 10) as u8; n /= 10; }
    for b in &buf[i..] { s.push(*b as char); }
}
