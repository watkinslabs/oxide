//! The TTY binding's ioctls and their struct codecs.
//!
//! Creating a device with any flag beyond the two a plain user may set demands
//! the network-administration capability, and the test is EQUALITY with that
//! pair rather than a subset test — a request carrying neither of them, flags
//! zero included, is privileged.

use alloc::vec::Vec;
use syscall::errno::Errno;

use crate::uapi::bt::{BdAddr, BT_CONNECTED};
use crate::uapi::rfcomm as u;
use super::dev::{DevInfo, DevList, DevReq, RfcommDev};

/// Decode `struct rfcomm_dev_req`. # C: O(1)
pub fn dev_req_from_wire(buf: &[u8]) -> Option<DevReq> {
    if buf.len() < u::RFCOMM_DEV_REQ_LEN { return None; }
    Some(DevReq {
        dev_id: i16::from_le_bytes([buf[u::DEV_REQ_ID_OFF], buf[u::DEV_REQ_ID_OFF + 1]]),
        flags: u32::from_le_bytes([buf[u::DEV_REQ_FLAGS_OFF], buf[u::DEV_REQ_FLAGS_OFF + 1],
                                   buf[u::DEV_REQ_FLAGS_OFF + 2], buf[u::DEV_REQ_FLAGS_OFF + 3]]),
        src: BdAddr::from_wire(buf, u::DEV_REQ_SRC_OFF)?,
        dst: BdAddr::from_wire(buf, u::DEV_REQ_DST_OFF)?,
        channel: buf[u::DEV_REQ_CHANNEL_OFF],
    })
}

/// Encode `struct rfcomm_dev_req`. # C: O(1)
pub fn dev_req_to_wire(req: &DevReq, buf: &mut [u8]) -> bool {
    if buf.len() < u::RFCOMM_DEV_REQ_LEN { return false; }
    buf[..u::RFCOMM_DEV_REQ_LEN].fill(0);
    buf[u::DEV_REQ_ID_OFF..u::DEV_REQ_ID_OFF + 2].copy_from_slice(&req.dev_id.to_le_bytes());
    buf[u::DEV_REQ_FLAGS_OFF..u::DEV_REQ_FLAGS_OFF + 4].copy_from_slice(&req.flags.to_le_bytes());
    if !req.src.to_wire(buf, u::DEV_REQ_SRC_OFF) { return false; }
    if !req.dst.to_wire(buf, u::DEV_REQ_DST_OFF) { return false; }
    buf[u::DEV_REQ_CHANNEL_OFF] = req.channel;
    true
}

/// Decode `struct rfcomm_dev_info`. # C: O(1)
pub fn dev_info_from_wire(buf: &[u8]) -> Option<DevInfo> {
    if buf.len() < u::RFCOMM_DEV_INFO_LEN { return None; }
    Some(DevInfo {
        id: i16::from_le_bytes([buf[u::DEV_INFO_ID_OFF], buf[u::DEV_INFO_ID_OFF + 1]]),
        flags: u32::from_le_bytes([buf[u::DEV_INFO_FLAGS_OFF], buf[u::DEV_INFO_FLAGS_OFF + 1],
                                   buf[u::DEV_INFO_FLAGS_OFF + 2], buf[u::DEV_INFO_FLAGS_OFF + 3]]),
        state: u16::from_le_bytes([buf[u::DEV_INFO_STATE_OFF], buf[u::DEV_INFO_STATE_OFF + 1]]),
        src: BdAddr::from_wire(buf, u::DEV_INFO_SRC_OFF)?,
        dst: BdAddr::from_wire(buf, u::DEV_INFO_DST_OFF)?,
        channel: buf[u::DEV_INFO_CHANNEL_OFF],
    })
}

/// Encode `struct rfcomm_dev_info`. # C: O(1)
pub fn dev_info_to_wire(di: &DevInfo, buf: &mut [u8]) -> bool {
    if buf.len() < u::RFCOMM_DEV_INFO_LEN { return false; }
    buf[..u::RFCOMM_DEV_INFO_LEN].fill(0);
    buf[u::DEV_INFO_ID_OFF..u::DEV_INFO_ID_OFF + 2].copy_from_slice(&di.id.to_le_bytes());
    buf[u::DEV_INFO_FLAGS_OFF..u::DEV_INFO_FLAGS_OFF + 4].copy_from_slice(&di.flags.to_le_bytes());
    buf[u::DEV_INFO_STATE_OFF..u::DEV_INFO_STATE_OFF + 2].copy_from_slice(&di.state.to_le_bytes());
    if !di.src.to_wire(buf, u::DEV_INFO_SRC_OFF) { return false; }
    if !di.dst.to_wire(buf, u::DEV_INFO_DST_OFF) { return false; }
    buf[u::DEV_INFO_CHANNEL_OFF] = di.channel;
    true
}

/// Encode a device-list reply: the number of entries actually reported, then
/// that many info structs. # C: O(n)
pub fn dev_list_to_wire(infos: &[DevInfo]) -> Vec<u8> {
    let mut v = alloc::vec![0u8; u::RFCOMM_DEV_LIST_HDR_LEN + infos.len() * u::RFCOMM_DEV_INFO_LEN];
    v[0..2].copy_from_slice(&(infos.len() as u16).to_le_bytes());
    for (i, di) in infos.iter().enumerate() {
        let off = u::RFCOMM_DEV_LIST_HDR_LEN + i * u::RFCOMM_DEV_INFO_LEN;
        dev_info_to_wire(di, &mut v[off..]);
    }
    v
}

/// Largest device count a list request may ask for. The reply is built in one
/// allocation, so the count is bounded by what four pages of info structs hold.
pub const DEV_LIST_MAX: u16 = ((4 * 4096) / u::RFCOMM_DEV_INFO_LEN) as u16;

/// Whether an operation carrying these flags may proceed without the
/// network-administration capability. # C: O(1)
pub fn flags_permitted(flags: u32, capable: bool) -> bool {
    flags == u::RFCOMM_NOCAP_FLAGS || capable
}

/// What a create request needs from the socket it was issued on.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CreateCtx {
    /// State of the socket the ioctl was issued on.
    pub sock_state: u8,
    /// Whether a DLC already exists for the requested address and channel.
    pub channel_busy: bool,
    /// Whether the caller holds the network-administration capability.
    pub capable: bool,
}

/// Bind a device to a DLC. Reusing the issuing socket's own DLC demands a
/// connected socket; binding a fresh one demands the channel be free. # C: O(n)
pub fn create_dev(devs: &mut DevList, req: &DevReq, ctx: CreateCtx) -> Result<i16, Errno> {
    if !flags_permitted(req.flags, ctx.capable) { return Err(Errno::Eperm); }
    let reuse = req.flags & (1 << u::RFCOMM_REUSE_DLC) != 0;
    if reuse {
        if ctx.sock_state != BT_CONNECTED { return Err(Errno::Ebadfd); }
    } else {
        if !u::channel_valid(req.channel) { return Err(Errno::Einval); }
        if ctx.channel_busy { return Err(Errno::Ebusy); }
    }
    let state = if reuse { BT_CONNECTED } else { crate::uapi::bt::BT_OPEN };
    devs.add(req, state)
}

/// Release a device. # C: O(n)
pub fn release_dev(devs: &mut DevList, req: &DevReq, capable: bool) -> Result<(), Errno> {
    let Some(dev) = devs.get(req.dev_id) else { return Err(Errno::Enodev); };
    if !flags_permitted(dev.flags, capable) { return Err(Errno::Eperm); }
    devs.release(req.dev_id)
}

/// Report up to `dev_num` devices. A request for none, or for more than one
/// reply can hold, is refused rather than clamped. # C: O(n)
pub fn get_dev_list(devs: &DevList, dev_num: u16) -> Result<Vec<DevInfo>, Errno> {
    if dev_num == 0 || dev_num > DEV_LIST_MAX { return Err(Errno::Einval); }
    Ok(devs.iter().take(dev_num as usize).map(DevInfo::of).collect())
}

/// Report one device. # C: O(n)
pub fn get_dev_info(devs: &DevList, id: i16) -> Result<DevInfo, Errno> {
    match devs.get(id) { Some(d) => Ok(DevInfo::of(d)), None => Err(Errno::Enodev) }
}

/// What an ioctl asks for, once its number is recognised.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DevIoctl { Create, Release, GetList, GetInfo }

/// Classify an ioctl number. The steal-DLC number is defined by the ABI but no
/// operation implements it, so it is refused like any unknown number rather
/// than dispatched. # C: O(1)
pub fn classify(cmd: u32) -> Result<DevIoctl, Errno> {
    match cmd {
        u::RFCOMMCREATEDEV => Ok(DevIoctl::Create),
        u::RFCOMMRELEASEDEV => Ok(DevIoctl::Release),
        u::RFCOMMGETDEVLIST => Ok(DevIoctl::GetList),
        u::RFCOMMGETDEVINFO => Ok(DevIoctl::GetInfo),
        _ => Err(Errno::Einval),
    }
}

/// The node number a device's terminal appears at. # C: O(1)
pub fn tty_minor(dev: &RfcommDev) -> u32 { u::RFCOMM_TTY_MINOR + dev.id as u32 }
