// The 9P2000 / 9P2000.u `stat` structure — the metadata carrier for every
// dialect except `.L`, and still the only way to rename or set attributes there.

use crate::err::{NpError, NpResult};
use crate::uapi::{dm, limits};
use super::{Dec, Dialect, Enc, Qid};

/// Sentinel meaning "leave this field unchanged" in a `Twstat`. Every numeric
/// field of a wstat that the caller is not deliberately setting must carry it;
/// a zero there is a REQUEST to set the field to zero and will truncate a file
/// or reset its mode.
pub const DONT_TOUCH_U16: u16 = u16::MAX;
/// 32-bit form of [`DONT_TOUCH_U16`].
pub const DONT_TOUCH_U32: u32 = u32::MAX;
/// 64-bit form of [`DONT_TOUCH_U16`].
pub const DONT_TOUCH_U64: u64 = u64::MAX;

/// A 9P2000(.u) `stat`. `size` is the byte count of everything AFTER the `size`
/// field itself — it is written by [`Wstat::encode`] from the measured body, so
/// a caller never sets it and cannot get it wrong.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wstat<'a> {
    /// Server type (the major-number analogue).
    pub ty: u16,
    /// Server subtype (the minor-number analogue).
    pub dev: u32,
    pub qid: Qid,
    /// Plan 9 mode word: `uapi::dm` type/attribute bits over the permissions.
    pub mode: u32,
    /// Last access time, whole seconds since the epoch.
    pub atime: u32,
    /// Last modification time, whole seconds since the epoch.
    pub mtime: u32,
    pub length: u64,
    pub name: &'a str,
    /// Owner NAME, not a number — the legacy dialect has no numeric ids.
    pub uid: &'a str,
    pub gid: &'a str,
    /// Name of the last modifier.
    pub muid: &'a str,
    /// `.u` extension payload: a symlink target, a device spec, or empty.
    pub extension: &'a str,
    /// `.u` numeric owner.
    pub n_uid: u32,
    /// `.u` numeric group.
    pub n_gid: u32,
    /// `.u` numeric last modifier.
    pub n_muid: u32,
}

impl<'a> Wstat<'a> {
    /// A wstat that changes NOTHING — every numeric field is the don't-touch
    /// sentinel and every string is empty. `Twstat` on a blank stat is how the
    /// legacy dialect expresses `fsync`, and a blank stat with only `name` set
    /// is how it expresses a same-directory rename. # C: O(1)
    pub fn blank() -> Self {
        Self {
            ty: DONT_TOUCH_U16, dev: DONT_TOUCH_U32,
            qid: Qid { ty: u8::MAX, version: DONT_TOUCH_U32, path: DONT_TOUCH_U64 },
            mode: DONT_TOUCH_U32, atime: DONT_TOUCH_U32, mtime: DONT_TOUCH_U32,
            length: DONT_TOUCH_U64,
            name: "", uid: "", gid: "", muid: "", extension: "",
            n_uid: DONT_TOUCH_U32, n_gid: DONT_TOUCH_U32, n_muid: DONT_TOUCH_U32,
        }
    }

    /// Byte count of the encoded body EXCLUDING the leading `size` field —
    /// exactly what goes in that field. # C: O(strings)
    pub fn body_len(&self, dialect: Dialect) -> usize {
        let fixed = 2 + 4 + limits::QID_SZ + 4 + 4 + 4 + 8;
        let strs = 2 + self.name.len() + 2 + self.uid.len()
                 + 2 + self.gid.len() + 2 + self.muid.len();
        let ext = if dialect.has_unix_ext() { 2 + self.extension.len() + 4 + 4 + 4 } else { 0 };
        fixed + strs + ext
    }

    /// Encode `size[2]` followed by the body. # C: O(strings)
    pub fn encode(&self, e: &mut Enc, dialect: Dialect) -> NpResult<()> {
        let body = self.body_len(dialect);
        if body > u16::MAX as usize { return Err(NpError::NameTooLong); }
        e.u16(body as u16)?;
        e.u16(self.ty)?; e.u32(self.dev)?; e.qid(&self.qid)?;
        e.u32(self.mode)?; e.u32(self.atime)?; e.u32(self.mtime)?; e.u64(self.length)?;
        e.string(self.name)?; e.string(self.uid)?; e.string(self.gid)?; e.string(self.muid)?;
        if dialect.has_unix_ext() {
            e.string(self.extension)?;
            e.u32(self.n_uid)?; e.u32(self.n_gid)?; e.u32(self.n_muid)?;
        }
        Ok(())
    }

    /// Decode `size[2]` plus the body. The declared `size` is not trusted as a
    /// bound on the outer buffer: the field decoders enforce their own limits,
    /// and a server that under-declares must not be able to make a later field
    /// read past the frame. # C: O(strings)
    pub fn decode(d: &mut Dec<'a>, dialect: Dialect) -> NpResult<Self> {
        let _size = d.u16()?;
        let ty = d.u16()?;
        let dev = d.u32()?;
        let qid = d.qid()?;
        let mode = d.u32()?;
        let atime = d.u32()?;
        let mtime = d.u32()?;
        let length = d.u64()?;
        let name = d.string()?;
        let uid = d.string()?;
        let gid = d.string()?;
        let muid = d.string()?;
        let (extension, n_uid, n_gid, n_muid) = if dialect.has_unix_ext() {
            (d.string()?, d.u32()?, d.u32()?, d.u32()?)
        } else {
            ("", DONT_TOUCH_U32, DONT_TOUCH_U32, DONT_TOUCH_U32)
        };
        Ok(Self { ty, dev, qid, mode, atime, mtime, length,
                  name, uid, gid, muid, extension, n_uid, n_gid, n_muid })
    }
}

/// Translate a Plan 9 mode word into a POSIX `st_mode`. `nodev` suppresses the
/// device/socket/fifo classes so a mount that distrusts the server cannot be
/// handed a character device node. # C: O(1)
pub fn p9mode_to_posix(mode: u32, dialect: Dialect, nodev: bool) -> u32 {
    /// `S_IFMT` bits, re-declared here because a Plan 9 mode word is not one.
    const S_IFDIR: u32 = 0o040000;
    const S_IFREG: u32 = 0o100000;
    const S_IFLNK: u32 = 0o120000;
    const S_IFIFO: u32 = 0o010000;
    const S_IFSOCK: u32 = 0o140000;
    const S_ISUID: u32 = 0o4000;
    const S_ISGID: u32 = 0o2000;
    const S_ISVTX: u32 = 0o1000;

    let mut out = mode & dm::PERM_MASK;
    if mode & dm::DMDIR != 0 { out |= S_IFDIR; } else { out |= S_IFREG; }
    if !dialect.has_unix_ext() { return out; }
    if mode & dm::DMSYMLINK != 0 { out = (out & !S_IFREG) | S_IFLNK; }
    if mode & dm::DMNAMEDPIPE != 0 && !nodev { out = (out & !S_IFREG) | S_IFIFO; }
    if mode & dm::DMSOCKET != 0 && !nodev { out = (out & !S_IFREG) | S_IFSOCK; }
    if mode & dm::DMSETUID != 0 { out |= S_ISUID; }
    if mode & dm::DMSETGID != 0 { out |= S_ISGID; }
    if mode & dm::DMSETVTX != 0 { out |= S_ISVTX; }
    out
}
