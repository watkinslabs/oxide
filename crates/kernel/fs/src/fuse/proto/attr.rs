// FUSE attribute + read-path operation bodies — `fuse_attr` and the structs that
// embed or accompany it: `fuse_entry_out` (LOOKUP reply), `fuse_attr_out`
// (GETATTR reply), `fuse_open_out`/`fuse_open_in` (OPEN), `fuse_getattr_in`,
// `fuse_read_in` (READ/READDIR), and the packed `fuse_dirent` stream.

extern crate alloc;
use alloc::vec::Vec;

use super::{FUSE_DIRENT_HEADER_SIZE, fuse_dirent_align, get_u32, get_u64, put_pad, put_u32, put_u64};

/// `struct fuse_attr`: `ino,size,blocks,atime,mtime,ctime,atimensec,mtimensec,
/// ctimensec,mode,nlink,uid,gid,rdev,blksize,flags`. `mode` carries the full
/// `S_IF*|perm` word. # C: O(1)
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct Attr {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atimensec: u32,
    pub mtimensec: u32,
    pub ctimensec: u32,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub blksize: u32,
}

impl Attr {
    /// Append the 88-byte attr payload (`flags` u32 = 0). # C: O(1)
    pub fn encode(&self, out: &mut Vec<u8>) {
        put_u64(out, self.ino);
        put_u64(out, self.size);
        put_u64(out, self.blocks);
        put_u64(out, self.atime);
        put_u64(out, self.mtime);
        put_u64(out, self.ctime);
        put_u32(out, self.atimensec);
        put_u32(out, self.mtimensec);
        put_u32(out, self.ctimensec);
        put_u32(out, self.mode);
        put_u32(out, self.nlink);
        put_u32(out, self.uid);
        put_u32(out, self.gid);
        put_u32(out, self.rdev);
        put_u32(out, self.blksize);
        put_u32(out, 0); // flags
    }
    /// Decode an 88-byte attr payload at byte `off` of `b`. # C: O(1)
    pub fn decode(b: &[u8], off: usize) -> Option<Attr> {
        Some(Attr {
            ino: get_u64(b, off)?, size: get_u64(b, off + 8)?, blocks: get_u64(b, off + 16)?,
            atime: get_u64(b, off + 24)?, mtime: get_u64(b, off + 32)?, ctime: get_u64(b, off + 40)?,
            atimensec: get_u32(b, off + 48)?, mtimensec: get_u32(b, off + 52)?, ctimensec: get_u32(b, off + 56)?,
            mode: get_u32(b, off + 60)?, nlink: get_u32(b, off + 64)?, uid: get_u32(b, off + 68)?,
            gid: get_u32(b, off + 72)?, rdev: get_u32(b, off + 76)?, blksize: get_u32(b, off + 80)?,
        })
    }
}

/// `struct fuse_entry_out`: `nodeid,generation,entry_valid,attr_valid,
/// entry_valid_nsec,attr_valid_nsec,attr`. LOOKUP reply. # C: O(1)
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct EntryOut {
    pub nodeid: u64,
    pub generation: u64,
    pub entry_valid: u64,
    pub attr_valid: u64,
    pub entry_valid_nsec: u32,
    pub attr_valid_nsec: u32,
    pub attr: Attr,
}

impl EntryOut {
    /// Append the 128-byte LOOKUP reply body. # C: O(1)
    pub fn encode(&self, out: &mut Vec<u8>) {
        put_u64(out, self.nodeid);
        put_u64(out, self.generation);
        put_u64(out, self.entry_valid);
        put_u64(out, self.attr_valid);
        put_u32(out, self.entry_valid_nsec);
        put_u32(out, self.attr_valid_nsec);
        self.attr.encode(out);
    }
    /// Decode a 128-byte LOOKUP reply body. # C: O(1)
    pub fn decode(b: &[u8]) -> Option<EntryOut> {
        Some(EntryOut {
            nodeid: get_u64(b, 0)?, generation: get_u64(b, 8)?, entry_valid: get_u64(b, 16)?,
            attr_valid: get_u64(b, 24)?, entry_valid_nsec: get_u32(b, 32)?, attr_valid_nsec: get_u32(b, 36)?,
            attr: Attr::decode(b, 40)?,
        })
    }
}

/// `struct fuse_attr_out`: `attr_valid,attr_valid_nsec,dummy,attr`. GETATTR
/// reply. # C: O(1)
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct AttrOut {
    pub attr_valid: u64,
    pub attr_valid_nsec: u32,
    pub attr: Attr,
}

impl AttrOut {
    /// Append the 104-byte GETATTR reply body (`dummy` u32 = 0). # C: O(1)
    pub fn encode(&self, out: &mut Vec<u8>) {
        put_u64(out, self.attr_valid);
        put_u32(out, self.attr_valid_nsec);
        put_u32(out, 0); // dummy
        self.attr.encode(out);
    }
    /// Decode a 104-byte GETATTR reply body. # C: O(1)
    pub fn decode(b: &[u8]) -> Option<AttrOut> {
        Some(AttrOut { attr_valid: get_u64(b, 0)?, attr_valid_nsec: get_u32(b, 8)?, attr: Attr::decode(b, 16)? })
    }
}

/// `struct fuse_open_out`: `fh,open_flags,padding`. OPEN/OPENDIR reply. # C: O(1)
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct OpenOut {
    pub fh: u64,
    pub open_flags: u32,
}

impl OpenOut {
    /// Append the 16-byte OPEN reply body (`padding` u32 = 0). # C: O(1)
    pub fn encode(&self, out: &mut Vec<u8>) {
        put_u64(out, self.fh);
        put_u32(out, self.open_flags);
        put_u32(out, 0); // padding
    }
    /// Decode a 16-byte OPEN reply body. # C: O(1)
    pub fn decode(b: &[u8]) -> Option<OpenOut> {
        Some(OpenOut { fh: get_u64(b, 0)?, open_flags: get_u32(b, 8)? })
    }
}

/// `struct fuse_open_in`: `flags,open_flags`. OPEN/OPENDIR request. # C: O(1)
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct OpenIn {
    pub flags: u32,
    pub open_flags: u32,
}

impl OpenIn {
    /// Append the 8-byte OPEN request body. # C: O(1)
    pub fn encode(&self, out: &mut Vec<u8>) {
        put_u32(out, self.flags);
        put_u32(out, self.open_flags);
    }
    /// Decode an 8-byte OPEN request body. # C: O(1)
    pub fn decode(b: &[u8]) -> Option<OpenIn> {
        Some(OpenIn { flags: get_u32(b, 0)?, open_flags: get_u32(b, 4)? })
    }
}

/// `struct fuse_fsync_in`: `fh,fsync_flags,padding`. FSYNC/FSYNCDIR request.
/// # C: O(1)
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct FsyncIn {
    pub fh: u64,
    pub fsync_flags: u32,
}

impl FsyncIn {
    /// Append the 16-byte FSYNC request body. # C: O(1)
    pub fn encode(&self, out: &mut Vec<u8>) {
        put_u64(out, self.fh);
        put_u32(out, self.fsync_flags);
        put_u32(out, 0); // padding
    }
    /// Decode a 16-byte FSYNC request body. # C: O(1)
    pub fn decode(b: &[u8]) -> Option<FsyncIn> {
        Some(FsyncIn { fh: get_u64(b, 0)?, fsync_flags: get_u32(b, 8)? })
    }
}

/// `struct fuse_getattr_in`: `getattr_flags,dummy,fh`. # C: O(1)
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct GetattrIn {
    pub getattr_flags: u32,
    pub fh: u64,
}

impl GetattrIn {
    /// Append the 16-byte GETATTR request body (`dummy` u32 = 0). # C: O(1)
    pub fn encode(&self, out: &mut Vec<u8>) {
        put_u32(out, self.getattr_flags);
        put_u32(out, 0); // dummy
        put_u64(out, self.fh);
    }
    /// Decode a 16-byte GETATTR request body. # C: O(1)
    pub fn decode(b: &[u8]) -> Option<GetattrIn> {
        Some(GetattrIn { getattr_flags: get_u32(b, 0)?, fh: get_u64(b, 8)? })
    }
}

/// `struct fuse_read_in`: `fh,offset,size,read_flags,lock_owner,flags,padding`.
/// READ/READDIR request. # C: O(1)
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct ReadIn {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub read_flags: u32,
    pub lock_owner: u64,
    pub flags: u32,
}

impl ReadIn {
    /// Append the 40-byte READ request body (`padding` u32 = 0). # C: O(1)
    pub fn encode(&self, out: &mut Vec<u8>) {
        put_u64(out, self.fh);
        put_u64(out, self.offset);
        put_u32(out, self.size);
        put_u32(out, self.read_flags);
        put_u64(out, self.lock_owner);
        put_u32(out, self.flags);
        put_u32(out, 0); // padding
    }
    /// Decode a 40-byte READ request body. # C: O(1)
    pub fn decode(b: &[u8]) -> Option<ReadIn> {
        Some(ReadIn {
            fh: get_u64(b, 0)?, offset: get_u64(b, 8)?, size: get_u32(b, 16)?, read_flags: get_u32(b, 20)?,
            lock_owner: get_u64(b, 24)?, flags: get_u32(b, 32)?,
        })
    }
}

/// `struct fuse_dirent` header + `name`. READDIR entries are packed as a stream
/// of these, each padded up to an 8-byte boundary. `d_type` is the `DT_*` value
/// (`st_mode >> 12`). # C: O(1)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Dirent {
    pub ino: u64,
    pub off: u64,
    pub d_type: u32,
    pub name: Vec<u8>,
}

impl Dirent {
    /// Append one padded `fuse_dirent` (`ino,off,namelen,type,name`, name padded
    /// to 8 bytes with NUL). # C: O(name)
    pub fn encode(&self, out: &mut Vec<u8>) {
        put_u64(out, self.ino);
        put_u64(out, self.off);
        put_u32(out, self.name.len() as u32);
        put_u32(out, self.d_type);
        out.extend_from_slice(&self.name);
        let padded = fuse_dirent_align(FUSE_DIRENT_HEADER_SIZE + self.name.len());
        put_pad(out, padded - (FUSE_DIRENT_HEADER_SIZE + self.name.len()));
    }
    /// Total padded on-wire length of this entry. # C: O(1)
    pub fn wire_len(&self) -> usize { fuse_dirent_align(FUSE_DIRENT_HEADER_SIZE + self.name.len()) }
}

/// Parse a packed `fuse_dirent` stream `b` back into entries (the inverse of a
/// READDIR reply body); `None` on a truncated/garbled buffer. # C: O(bytes)
pub fn decode_dirent_stream(b: &[u8]) -> Option<Vec<Dirent>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < b.len() {
        if pos + FUSE_DIRENT_HEADER_SIZE > b.len() { return None; }
        let ino = get_u64(b, pos)?;
        let off = get_u64(b, pos + 8)?;
        let namelen = get_u32(b, pos + 16)? as usize;
        let d_type = get_u32(b, pos + 20)?;
        let name_start = pos + FUSE_DIRENT_HEADER_SIZE;
        let name_end = name_start.checked_add(namelen)?;
        if name_end > b.len() { return None; }
        out.push(Dirent { ino, off, d_type, name: b[name_start..name_end].to_vec() });
        pos = name_start + fuse_dirent_align(namelen);
    }
    Some(out)
}
