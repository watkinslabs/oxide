// FUSE message framing — `fuse_in_header` (kernel→daemon request prefix),
// `fuse_out_header` (daemon→kernel reply prefix), and the INIT handshake bodies
// (`fuse_init_in` we send, `fuse_init_out` the daemon replies).

extern crate alloc;
use alloc::vec::Vec;

use super::{get_u16, get_u32, get_u64, put_pad, put_u16, put_u32, put_u64};

/// `struct fuse_in_header` (`uapi/linux/fuse.h`): `len,opcode,unique,nodeid,
/// uid,gid,pid,padding`. `len` is the TOTAL request length including this
/// header. # C: O(1)
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct InHeader {
    pub len: u32,
    pub opcode: u32,
    pub unique: u64,
    pub nodeid: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

impl InHeader {
    /// Append the 40-byte header to `out` (LE, trailing `padding` u32 = 0).
    /// # C: O(1)
    pub fn encode(&self, out: &mut Vec<u8>) {
        put_u32(out, self.len);
        put_u32(out, self.opcode);
        put_u64(out, self.unique);
        put_u64(out, self.nodeid);
        put_u32(out, self.uid);
        put_u32(out, self.gid);
        put_u32(out, self.pid);
        put_pad(out, 4);
    }
    /// Decode a 40-byte header from the front of `b`; `None` if truncated.
    /// # C: O(1)
    pub fn decode(b: &[u8]) -> Option<InHeader> {
        Some(InHeader {
            len: get_u32(b, 0)?, opcode: get_u32(b, 4)?, unique: get_u64(b, 8)?,
            nodeid: get_u64(b, 16)?, uid: get_u32(b, 24)?, gid: get_u32(b, 28)?, pid: get_u32(b, 32)?,
        })
    }
}

/// `struct fuse_out_header`: `len,error,unique`. `len` counts this header plus
/// the reply body; `error` is `-errno` (Linux) or `0`. # C: O(1)
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct OutHeader {
    pub len: u32,
    pub error: i32,
    pub unique: u64,
}

impl OutHeader {
    /// Append the 16-byte reply header to `out`. # C: O(1)
    pub fn encode(&self, out: &mut Vec<u8>) {
        put_u32(out, self.len);
        put_u32(out, self.error as u32);
        put_u64(out, self.unique);
    }
    /// Decode a 16-byte reply header from the front of `b`. # C: O(1)
    pub fn decode(b: &[u8]) -> Option<OutHeader> {
        Some(OutHeader { len: get_u32(b, 0)?, error: get_u32(b, 4)? as i32, unique: get_u64(b, 8)? })
    }
}

/// `struct fuse_init_in` (7.36+): base fields, `flags2`, and eleven reserved
/// words. The kernel sends this; the daemon replies with `InitOut`. # C: O(1)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitIn {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
    pub flags2: u32,
}

impl InitIn {
    /// Append the 64-byte extended INIT request body. # C: O(1)
    pub fn encode(&self, out: &mut Vec<u8>) {
        put_u32(out, self.major);
        put_u32(out, self.minor);
        put_u32(out, self.max_readahead);
        put_u32(out, self.flags);
        put_u32(out, self.flags2);
        put_pad(out, 4 * 11);
    }
    /// Decode a 16-byte INIT request body (test/daemon side). # C: O(1)
    pub fn decode(b: &[u8]) -> Option<InitIn> {
        Some(InitIn {
            major: get_u32(b, 0)?, minor: get_u32(b, 4)?,
            max_readahead: get_u32(b, 8)?, flags: get_u32(b, 12)?,
            flags2: get_u32(b, 16)?,
        })
    }
}

/// `struct fuse_init_out` (64 bytes): `major,minor,max_readahead,flags,
/// max_background,congestion_threshold,max_write,time_gran,max_pages,
/// map_alignment,flags2,max_stack_depth,request_timeout,unused[11]`. Fields
/// after `flags2` are currently zeroed. # C: O(1)
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct InitOut {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
    pub max_background: u16,
    pub congestion_threshold: u16,
    pub max_write: u32,
    pub time_gran: u32,
    pub max_pages: u16,
    pub map_alignment: u16,
}

impl InitOut {
    /// Append the 64-byte INIT reply body (the extension tail zeroed). # C: O(1)
    pub fn encode(&self, out: &mut Vec<u8>) {
        put_u32(out, self.major);
        put_u32(out, self.minor);
        put_u32(out, self.max_readahead);
        put_u32(out, self.flags);
        put_u16(out, self.max_background);
        put_u16(out, self.congestion_threshold);
        put_u32(out, self.max_write);
        put_u32(out, self.time_gran);
        put_u16(out, self.max_pages);
        put_u16(out, self.map_alignment);
        put_u32(out, 0); // flags2
        put_pad(out, 4 * 7); // unused[7]
    }
    /// Decode the 64-byte INIT reply body (only the fields we negotiate on).
    /// # C: O(1)
    pub fn decode(b: &[u8]) -> Option<InitOut> {
        Some(InitOut {
            major: get_u32(b, 0)?, minor: get_u32(b, 4)?, max_readahead: get_u32(b, 8)?, flags: get_u32(b, 12)?,
            max_background: get_u16(b, 16)?, congestion_threshold: get_u16(b, 18)?, max_write: get_u32(b, 20)?,
            time_gran: get_u32(b, 24)?, max_pages: get_u16(b, 28)?, map_alignment: get_u16(b, 30)?,
        })
    }
}
