// Element commands against a `BPF_MAP_TYPE_REUSEPORT_SOCKARRAY`.
//
// A value here is not bytes: it is a socket descriptor going in, and a socket
// cookie coming out. That asymmetry is the map's whole point — userspace names
// a socket it holds open, and a program later names the same slot without ever
// being handed anything it could dereference.

extern crate alloc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use super::super::uapi;
use super::super::BpfMapInode;
use super::sockarray::{self, SockHandle};
use super::super::user;

/// Descriptor width a value carries: both widths this map type accepts name
/// the same descriptor. A 64-bit value above the signed 32-bit range is not a
/// descriptor at all. # C: O(1)
pub fn fd_from_value(value: &[u8]) -> Result<i32, Errno> {
    match value.len() {
        4 => Ok(i32::from_ne_bytes(value.try_into().unwrap())),
        8 => {
            let wide = u64::from_ne_bytes(value.try_into().unwrap());
            if wide > i32::MAX as u64 { return Err(Errno::Einval); }
            Ok(wide as i32)
        }
        _ => Err(Errno::Einval),
    }
}

/// Whether a lookup can report what it found. A cookie needs the wide value;
/// a map created with the narrow one has nowhere to put it. # C: O(1)
pub fn lookup_width_ok(value_size: u32) -> Result<(), Errno> {
    if value_size == 8 { Ok(()) } else { Err(Errno::Enospc) }
}

fn array(m: &BpfMapInode) -> Result<&sockarray::SockArray, Errno> {
    m.storage.sock_array().ok_or(Errno::Einval)
}

/// `BPF_MAP_UPDATE_ELEM`: install the socket a descriptor names. # C: O(1)
pub fn update(m: &BpfMapInode, key: &[u8], value: &[u8], flags: u64) -> Result<i64, Errno> {
    let fd = fd_from_value(value)?;
    let handle: SockHandle = sockarray::sock_from_fd(fd)?;
    array(m)?.update(key, m.max_entries, handle, flags)?;
    Ok(0)
}

/// `BPF_MAP_LOOKUP_ELEM`: report the stored socket's cookie. # C: O(1)
pub fn lookup(m: &BpfMapInode, key: &[u8], value_ptr: u64) -> Result<i64, Errno> {
    lookup_width_ok(m.value_size)?;
    let handle = array(m)?.lookup(key, m.max_entries)?.ok_or(Errno::Enoent)?;
    user::write_bytes(value_ptr, &handle.cookie.to_ne_bytes())?;
    Ok(0)
}

/// `BPF_MAP_DELETE_ELEM`. # C: O(1)
pub fn delete(m: &BpfMapInode, key: &[u8]) -> Result<i64, Errno> {
    array(m)?.delete(key, m.max_entries)?;
    Ok(0)
}

/// `BPF_MAP_GET_NEXT_KEY`. # C: O(1)
pub fn next_key(m: &BpfMapInode, key: Option<&[u8]>) -> Result<Option<Vec<u8>>, Errno> {
    array(m)?.next_key(key, m.max_entries)
}

/// Whether this map holds sockets rather than bytes. # C: O(1)
pub fn holds_sockets(map_type: u32) -> bool {
    map_type == uapi::map_type::REUSEPORT_SOCKARRAY
}
