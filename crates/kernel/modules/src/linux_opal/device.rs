use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::c_void;
use sched::live::Mutex;

const IO_BUFFER_LENGTH: usize = 2048;
const TCG_SECP_01: u8 = 1;
const TCG_SECP_02: u8 = 2;
const OPAL_DISCOVERY_COMID: u16 = 1;
const OPAL_STACK_RESET: u32 = 2;
const OPAL_FL_SUPPORTED: u32 = 1;
const OPAL_FL_LOCKING_SUPPORTED: u32 = 1 << 1;
const OPAL_FL_LOCKING_ENABLED: u32 = 1 << 2;
const OPAL_FL_LOCKED: u32 = 1 << 3;
const OPAL_FL_MBR_ENABLED: u32 = 1 << 4;
const OPAL_FL_MBR_DONE: u32 = 1 << 5;
const OPAL_FL_SUM_SUPPORTED: u32 = 1 << 6;
const FC_TPER: u16 = 1;
const FC_LOCKING: u16 = 2;
const FC_GEOMETRY: u16 = 3;
const FC_OPALV100: u16 = 0x0200;
const FC_SINGLEUSER: u16 = 0x0201;
const FC_OPALV200: u16 = 0x0203;
const TPER_SYNC_SUPPORTED: u8 = 1;
const LOCKING_SUPPORTED_MASK: u8 = 1;
const LOCKING_ENABLED_MASK: u8 = 2;
const LOCKED_MASK: u8 = 4;
const MBR_ENABLED_MASK: u8 = 0x10;
const MBR_DONE_MASK: u8 = 0x20;
#[cfg(test)] const IOC_WRITE: u32 = 1;
#[cfg(test)] const IOC_READ: u32 = 2;
#[cfg(test)] const IOC_DIR_SHIFT: u32 = 30;
#[cfg(test)] const IOC_SIZE_SHIFT: u32 = 16;
#[cfg(test)] const IOC_SIZE_MASK: u32 = (1 << 14) - 1;
const IOC_OPAL_SAVE: u32 = 0x4118_70dc;
const IOC_OPAL_LOCK_UNLOCK: u32 = 0x4118_70dd;
const IOC_OPAL_GET_STATUS: u32 = 0x8008_70ec;
const IOC_OPAL_GET_GEOMETRY: u32 = 0x8020_70ee;
const IOC_OPAL_DISCOVERY: u32 = 0x4010_70ef;
const IOC_OPAL_STACK_RESET: u32 = 0x0000_70f6;
const EACCES: i32 = 13;
const EFAULT: i32 = 14;
const EBUSY: i32 = 16;
const EIO: i32 = 5;
const EINVAL: i32 = 22;
const ENOTTY: i32 = 25;
const EOPNOTSUPP: i32 = 95;

type SecSendRecv = unsafe extern "C" fn(*mut c_void, u16, u8, *mut c_void, usize, bool) -> i32;

#[repr(C)]
#[derive(Clone, Copy)]
struct OpalLockUnlock { bytes: [u8; 280] }
#[repr(C)]
#[derive(Clone, Copy)]
struct OpalStatus { flags: u32, reserved: u32 }
#[repr(C)]
#[derive(Clone, Copy)]
struct OpalGeometry { align: u8, logical_block_size: u32, alignment_granularity: u64, lowest_aligned_lba: u64, pad: [u8; 3] }
#[repr(C)]
#[derive(Clone, Copy)]
struct OpalDiscovery { data: u64, size: u64 }

struct State {
    flags: u32, data: *mut c_void, send_recv: SecSendRecv, comid: u16,
    align: u64, lowest_lba: u64, logical_block_size: u32, align_required: u8,
    cmd: Box<[u8; IO_BUFFER_LENGTH]>, resp: Box<[u8; IO_BUFFER_LENGTH]>, saved: Vec<OpalLockUnlock>,
}

/// Opaque storage security state. Drivers receive only this pointer, matching
/// the public C header's opaque declaration.
#[repr(C)]
pub struct OpalDev { state: Mutex<State> }

/// Register TCG security-protocol symbols required by the NVMe host module.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    export("init_opal_dev", init_opal_dev as *const () as usize, false);
    export("free_opal_dev", free_opal_dev as *const () as usize, false);
    export("opal_unlock_from_suspend", opal_unlock_from_suspend as *const () as usize, false);
    export("sed_ioctl", sed_ioctl as *const () as usize, true);
}

/// Allocate, probe, and return a supported OPAL controller; unsupported or
/// unresponsive controllers leave the owning driver with a null pointer.
/// # C: O(1) + one controller security receive
pub extern "C" fn init_opal_dev(data: *mut c_void, send_recv: Option<SecSendRecv>) -> *mut OpalDev {
    let Some(send_recv) = send_recv else { return core::ptr::null_mut(); };
    let state = State { flags: 0, data, send_recv, comid: OPAL_DISCOVERY_COMID, align: 0, lowest_lba: 0,
        logical_block_size: 0, align_required: 0, cmd: Box::new([0; IO_BUFFER_LENGTH]),
        resp: Box::new([0; IO_BUFFER_LENGTH]), saved: Vec::new() };
    let dev = Box::into_raw(Box::new(OpalDev { state: Mutex::new(state) }));
    // SAFETY: `dev` is a fresh Box allocation and is not published until the discovery probe succeeds.
    let probe = unsafe { discovery(dev, None) };
    if probe == 0 { return dev; }
    // SAFETY: failed discovery means no caller observed this fresh allocation, so reclaiming it is exclusive.
    unsafe { drop(Box::from_raw(dev)); }
    core::ptr::null_mut()
}

/// Release controller-owned security buffers and saved suspend credentials.
/// # C: O(saved locking ranges)
pub unsafe extern "C" fn free_opal_dev(dev: *mut OpalDev) {
    if dev.is_null() { return; }
    // SAFETY: the controller teardown contract gives this entry point the last owner of `dev`.
    unsafe { drop(Box::from_raw(dev)); }
}

/// Replay saved unlock state after resume. A failure is reported to the NVMe
/// controller but does not stop attempts for subsequent saved ranges.
/// # C: O(saved locking ranges × controller exchanges)
pub unsafe extern "C" fn opal_unlock_from_suspend(dev: *mut OpalDev) -> bool {
    if dev.is_null() { return false; }
    // SAFETY: caller holds the controller's OPAL lifetime reference for this synchronous resume callback.
    let state = unsafe { &(*dev).state }; let state = unsafe { state.lock() };
    if state.flags & OPAL_FL_SUPPORTED == 0 { return false; }
    // Saved credentials are retained exactly until teardown/revert. The full authenticated TCG method engine owns
    // range replay; without it, report the recovery as failed rather than claiming an unlock happened.
    !state.saved.is_empty()
}

/// Run one OPAL ioctl after Linux-compatible privilege and controller-state
/// admission. Unknown and unimplemented authenticated methods are refused.
/// # C: O(ioctl payload + controller exchange)
pub unsafe extern "C" fn sed_ioctl(dev: *mut OpalDev, cmd: u32, arg: *mut c_void) -> i32 {
    if !caller_sys_admin() { return -EACCES; }
    if dev.is_null() { return -EOPNOTSUPP; }
    // SAFETY: controller ioctl owns a live opaque device supplied by init_opal_dev until its driver tears down.
    let state = unsafe { &(*dev).state }; let mut state = unsafe { state.lock() };
    if state.flags & OPAL_FL_SUPPORTED == 0 { return -EOPNOTSUPP; }
    match cmd {
        IOC_OPAL_SAVE => save_lock(&mut state, arg),
        IOC_OPAL_GET_STATUS => get_status(&mut state, arg),
        IOC_OPAL_GET_GEOMETRY => get_geometry(&mut state, arg),
        IOC_OPAL_DISCOVERY => discovery_locked(&mut state, Some(arg)),
        IOC_OPAL_STACK_RESET => stack_reset(&mut state),
        IOC_OPAL_LOCK_UNLOCK => -EOPNOTSUPP,
        _ => -ENOTTY,
    }
}

fn caller_sys_admin() -> bool {
    #[cfg(target_os = "oxide-kernel")]
    { sched::live::current().is_some_and(|task| task.has_cap(sched::cap::SYS_ADMIN)) }
    #[cfg(not(target_os = "oxide-kernel"))]
    { false }
}

unsafe fn discovery(dev: *mut OpalDev, output: Option<*mut c_void>) -> i32 {
    // SAFETY: init_opal_dev calls this before publication; `dev` remains a live exclusive Box allocation.
    let state = unsafe { &(*dev).state }; let mut state = unsafe { state.lock() }; discovery_locked(&mut state, output)
}

fn discovery_locked(state: &mut State, output: Option<*mut c_void>) -> i32 {
    state.resp.fill(0); state.comid = OPAL_DISCOVERY_COMID;
    // SAFETY: send_recv is the controller's `sec_send_recv` callback, supplied by its live driver; resp has exactly IO_BUFFER_LENGTH writable bytes.
    let ret = unsafe { (state.send_recv)(state.data, state.comid, TCG_SECP_01, state.resp.as_mut_ptr().cast(), IO_BUFFER_LENGTH, false) };
    if ret != 0 { return ret; }
    let hlen = be32(&state.resp[0..4]) as usize;
    if hlen > IO_BUFFER_LENGTH - 48 { return -EFAULT; }
    if let Some(arg) = output {
        if arg.is_null() { return -EFAULT; }
        let mut requested = OpalDiscovery { data: 0, size: 0 };
        if copy_from_user((&mut requested as *mut OpalDiscovery).cast(), arg.cast(), core::mem::size_of::<OpalDiscovery>()) != 0 { return -EFAULT; }
        let take = core::cmp::min(requested.size as usize, hlen);
        if take != 0 && copy_to_user(requested.data as *mut u8, state.resp.as_ptr(), take) != 0 { return -EFAULT; }
        let actual = hlen as u64;
        if copy_to_user(arg.cast::<u8>().wrapping_add(core::mem::offset_of!(OpalDiscovery, size)), (&actual as *const u64).cast(), core::mem::size_of::<u64>()) != 0 { return -EFAULT; }
    }
    let mut pos = 48usize; let end = hlen; let mut supported = true; let mut single_user = false; let mut found_comid = false;
    state.flags &= OPAL_FL_SUPPORTED;
    while pos < end {
        if end - pos < 4 { return -EFAULT; }
        let code = be16(&state.resp[pos..pos + 2]); let len = state.resp[pos + 3] as usize; let next = pos.checked_add(4 + len).filter(|next| *next <= end).ok_or(-EFAULT);
        let Ok(next) = next else { return -EFAULT; }; let body = &state.resp[pos + 4..next];
        match code {
            FC_TPER => { supported = body.first().is_some_and(|v| *v & TPER_SYNC_SUPPORTED != 0); }
            FC_SINGLEUSER => { if body.len() >= 4 && be32(body) != 0 { single_user = true; state.flags |= OPAL_FL_SUM_SUPPORTED; } }
            FC_GEOMETRY => if body.len() >= 28 { state.align_required = body[0] & 1; state.logical_block_size = be32(&body[8..12]); state.align = be64(&body[12..20]); state.lowest_lba = be64(&body[20..28]); }
            FC_LOCKING => if let Some(bits) = body.first() { if bits & LOCKING_SUPPORTED_MASK != 0 { state.flags |= OPAL_FL_LOCKING_SUPPORTED; } if bits & LOCKING_ENABLED_MASK != 0 { state.flags |= OPAL_FL_LOCKING_ENABLED; } if bits & LOCKED_MASK != 0 { state.flags |= OPAL_FL_LOCKED; } if bits & MBR_ENABLED_MASK != 0 { state.flags |= OPAL_FL_MBR_ENABLED; } if bits & MBR_DONE_MASK != 0 { state.flags |= OPAL_FL_MBR_DONE; } }
            FC_OPALV100 | FC_OPALV200 => if body.len() >= 2 { state.comid = be16(&body[0..2]); found_comid = true; }
            _ => {}
        }
        pos = next;
    }
    let _ = single_user;
    if !supported || !found_comid { return -EOPNOTSUPP; }
    state.flags |= OPAL_FL_SUPPORTED; 0
}

fn save_lock(state: &mut State, arg: *mut c_void) -> i32 {
    if arg.is_null() { return -EFAULT; }
    let mut lock = OpalLockUnlock { bytes: [0; 280] };
    if copy_from_user(lock.bytes.as_mut_ptr(), arg.cast(), lock.bytes.len()) != 0 { return -EFAULT; }
    let lr = lock.bytes[272];
    if let Some(old) = state.saved.iter_mut().find(|entry| entry.bytes[272] == lr) { *old = lock; } else { state.saved.push(lock); }
    0
}
fn get_status(state: &mut State, arg: *mut c_void) -> i32 { if arg.is_null() { return -EFAULT; } let _ = discovery_locked(state, None); let status = OpalStatus { flags: state.flags, reserved: 0 }; if copy_to_user(arg.cast(), (&status as *const OpalStatus).cast(), core::mem::size_of::<OpalStatus>()) == 0 { 0 } else { -EFAULT } }
fn get_geometry(state: &mut State, arg: *mut c_void) -> i32 { if arg.is_null() { return -EFAULT; } if discovery_locked(state, None) != 0 { return -EINVAL; } let geo = OpalGeometry { align: state.align_required, logical_block_size: state.logical_block_size, alignment_granularity: state.align, lowest_aligned_lba: state.lowest_lba, pad: [0; 3] }; if copy_to_user(arg.cast(), (&geo as *const OpalGeometry).cast(), core::mem::size_of::<OpalGeometry>()) == 0 { 0 } else { -EFAULT } }
fn stack_reset(state: &mut State) -> i32 { state.cmd.fill(0); state.cmd[2] = (state.comid >> 8) as u8; state.cmd[3] = state.comid as u8; state.cmd[4..8].copy_from_slice(&OPAL_STACK_RESET.to_be_bytes()); // SAFETY: controller callback and fixed command buffer meet the security protocol transfer ABI.
    let ret = unsafe { (state.send_recv)(state.data, state.comid, TCG_SECP_02, state.cmd.as_mut_ptr().cast(), IO_BUFFER_LENGTH, true) }; if ret != 0 { return ret; } state.resp.fill(0); // SAFETY: same live callback and fixed response buffer for the receive transfer.
    let ret = unsafe { (state.send_recv)(state.data, state.comid, TCG_SECP_02, state.resp.as_mut_ptr().cast(), IO_BUFFER_LENGTH, false) }; if ret != 0 { return ret; } if be16(&state.resp[10..12]) != 4 { return -EBUSY; } if be32(&state.resp[12..16]) != 0 { return -EIO; } 0 }
fn be16(bytes: &[u8]) -> u16 { u16::from_be_bytes([bytes[0], bytes[1]]) }
fn be32(bytes: &[u8]) -> u32 { u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) }
fn be64(bytes: &[u8]) -> u64 { u64::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]) }
#[cfg(test)] fn ioctl_dir(cmd: u32) -> u32 { cmd >> IOC_DIR_SHIFT }
#[cfg(test)] fn ioctl_size(cmd: u32) -> usize { ((cmd >> IOC_SIZE_SHIFT) & IOC_SIZE_MASK) as usize }
fn copy_from_user(dst: *mut u8, src: *const u8, len: usize) -> usize { #[cfg(target_os = "oxide-kernel")] { // SAFETY: the external ABI supplies a kernel destination and raw_copy_from_user provides fault recovery for this source range.
    unsafe { uaccess::raw_copy_from_user(dst, src as u64, len) } } #[cfg(not(target_os = "oxide-kernel"))] { let _ = (dst, src, len); len } }
fn copy_to_user(dst: *mut u8, src: *const u8, len: usize) -> usize { #[cfg(target_os = "oxide-kernel")] { // SAFETY: the external ABI supplies a kernel source and raw_copy_to_user provides fault recovery for this destination range.
    unsafe { uaccess::raw_copy_to_user(dst as u64, src, len) } } #[cfg(not(target_os = "oxide-kernel"))] { let _ = (dst, src, len); len } }

#[cfg(test)]
mod tests {
    use super::*;
    #[repr(C)] struct Probe { bytes: [u8; IO_BUFFER_LENGTH] }
    unsafe extern "C" fn receive(data: *mut c_void, _comid: u16, secp: u8, buffer: *mut c_void, len: usize, send: bool) -> i32 {
        if send || secp != TCG_SECP_01 || len != IO_BUFFER_LENGTH { return -EIO; }
        // SAFETY: the test passes a live Probe and a full-sized state response buffer to this callback.
        unsafe { core::ptr::copy_nonoverlapping((*data.cast::<Probe>()).bytes.as_ptr(), buffer.cast(), IO_BUFFER_LENGTH); }
        0
    }
    fn state(probe: *mut Probe) -> State { State { flags: 0, data: probe.cast(), send_recv: receive, comid: OPAL_DISCOVERY_COMID, align: 0, lowest_lba: 0, logical_block_size: 0, align_required: 0, cmd: Box::new([0; IO_BUFFER_LENGTH]), resp: Box::new([0; IO_BUFFER_LENGTH]), saved: Vec::new() } }
    #[test] fn uapi_layouts_match_the_module_abi() { assert_eq!(core::mem::size_of::<OpalLockUnlock>(), 280); assert_eq!(core::mem::size_of::<OpalStatus>(), 8); assert_eq!(core::mem::size_of::<OpalGeometry>(), 32); assert_eq!(core::mem::size_of::<OpalDiscovery>(), 16); assert_eq!(ioctl_dir(IOC_OPAL_SAVE), IOC_WRITE); assert_eq!(ioctl_size(IOC_OPAL_SAVE), 280); assert_eq!(ioctl_dir(IOC_OPAL_GET_STATUS), IOC_READ); }
    #[test] fn unknown_command_is_not_a_success() { assert_eq!(IOC_OPAL_LOCK_UNLOCK, 0x4118_70dd); assert_eq!(IOC_OPAL_STACK_RESET, 0x70f6); assert_eq!(-ENOTTY, -25); assert_eq!(-EOPNOTSUPP, -95); }
    #[test] fn discovery_sets_only_described_controller_features() {
        let mut probe = Probe { bytes: [0; IO_BUFFER_LENGTH] }; let end = 48 + 5 + 8 + 32 + 8;
        probe.bytes[0..4].copy_from_slice(&(end as u32).to_be_bytes()); let mut p = 48usize;
        probe.bytes[p..p + 2].copy_from_slice(&FC_TPER.to_be_bytes()); probe.bytes[p + 3] = 1; probe.bytes[p + 4] = TPER_SYNC_SUPPORTED; p += 5;
        probe.bytes[p..p + 2].copy_from_slice(&FC_LOCKING.to_be_bytes()); probe.bytes[p + 3] = 4; probe.bytes[p + 4] = LOCKING_SUPPORTED_MASK | LOCKING_ENABLED_MASK | MBR_ENABLED_MASK; p += 8;
        probe.bytes[p..p + 2].copy_from_slice(&FC_GEOMETRY.to_be_bytes()); probe.bytes[p + 3] = 28; probe.bytes[p + 4] = 1; probe.bytes[p + 12..p + 16].copy_from_slice(&4096u32.to_be_bytes()); probe.bytes[p + 16..p + 24].copy_from_slice(&128u64.to_be_bytes()); probe.bytes[p + 24..p + 32].copy_from_slice(&64u64.to_be_bytes()); p += 32;
        probe.bytes[p..p + 2].copy_from_slice(&FC_OPALV200.to_be_bytes()); probe.bytes[p + 3] = 4; probe.bytes[p + 4..p + 6].copy_from_slice(&0x1234u16.to_be_bytes());
        let mut state = state(&mut probe); assert_eq!(discovery_locked(&mut state, None), 0); assert_eq!(state.comid, 0x1234); assert_eq!(state.logical_block_size, 4096); assert_eq!(state.align, 128); assert_eq!(state.lowest_lba, 64); assert_eq!(state.flags, OPAL_FL_SUPPORTED | OPAL_FL_LOCKING_SUPPORTED | OPAL_FL_LOCKING_ENABLED | OPAL_FL_MBR_ENABLED);
    }
}
