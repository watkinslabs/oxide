//! Control commands, plain and extended.

use alloc::sync::Arc;
use alloc::vec::Vec;
use syscall::errno::Errno;

use crate::ctrl::{access, query};
use crate::device::{FileHandle, VideoDevice};
use crate::event::Event;
use crate::uapi::ctrl_ids as cid;
use crate::uapi::layout as l;
use crate::usermem::{r32, r32i, r64i, w32, w32i, w64, w64i, wstr, zero};
use super::Ctx;

/// `VIDIOC_G_CTRL`. # C: O(log n)
pub fn g_ctrl(device: &Arc<VideoDevice>, arg: &mut [u8]) -> Result<(), Errno> {
    if arg.len() < l::CONTROL_SIZE { return Err(Errno::Einval); }
    let value = access::get_ctrl(&device.controls, r32(arg, l::CONTROL_ID))?;
    w32i(arg, l::CONTROL_VALUE, value);
    Ok(())
}

/// Raise the control-change event for `id`, and re-evaluate the active state
/// of everything clustered behind it.
///
/// A cluster's dependants going inactive is itself a change an application
/// must see: the exposure-time slider greys out the moment automatic exposure
/// is switched on, and it only does so because these events are sent.
/// # C: O(cluster * handles)
fn announce(handle: &Arc<FileHandle>, id: u32, value: i64, ctx: &dyn Ctx) {
    let device = handle.device.clone();
    let Some(desc) = device.controls.find(id).copied() else { return };
    let (sec, nsec) = ctx.now();
    if !desc.cluster.is_empty() {
        let inactive = crate::ctrl::standard::cluster_inactive(value, id);
        let add = if inactive { cid::CTRL_FLAG_INACTIVE } else { 0 };
        let remove = if inactive { 0 } else { cid::CTRL_FLAG_INACTIVE };
        for member in desc.cluster {
            device.controls.set_runtime_flags(*member, add, remove);
            let Some(m) = device.controls.find(*member).copied() else { continue };
            let mflags = device.controls.flags(*member).unwrap_or(0);
            let mvalue = device.controls.value(*member).unwrap_or(0);
            let ev = Event::control(*member, crate::uapi::flags::EVENT_CTRL_CH_FLAGS,
                                    m.ctrl_type, mvalue, mflags,
                                    m.minimum as i32, m.maximum as i32,
                                    m.step as i32, m.default_value as i32);
            for woken in device.broadcast(ev, sec, nsec, None) { let _ = woken; }
        }
    }
    let flags = device.controls.flags(id).unwrap_or(0);
    let ev = Event::control(id, crate::uapi::flags::EVENT_CTRL_CH_VALUE, desc.ctrl_type,
                            value, flags, desc.minimum as i32, desc.maximum as i32,
                            desc.step as i32, desc.default_value as i32);
    device.broadcast(ev, sec, nsec, Some(handle.id));
    ctx.wake(&device);
}

/// `VIDIOC_S_CTRL`. # C: O(log n)
pub fn s_ctrl(handle: &Arc<FileHandle>, arg: &mut [u8], ctx: &dyn Ctx) -> Result<(), Errno> {
    if arg.len() < l::CONTROL_SIZE { return Err(Errno::Einval); }
    let device = handle.device.clone();
    let id = r32(arg, l::CONTROL_ID);
    let stored = access::set_ctrl(&device.controls, id, r32i(arg, l::CONTROL_VALUE))?;
    if device.ops.control_changed(id, stored as i64) {
        crate::vb2::stream::set_error(&mut device.state.lock().queue);
    }
    announce(handle, id, stored as i64, ctx);
    w32i(arg, l::CONTROL_VALUE, stored);
    Ok(())
}

/// `VIDIOC_QUERYCTRL`. # C: O(controls)
pub fn queryctrl(device: &Arc<VideoDevice>, arg: &mut [u8]) -> Result<(), Errno> {
    if arg.len() < l::QUERYCTRL_SIZE { return Err(Errno::Einval); }
    let handler = &device.controls;
    let desc = *query::find(handler, r32(arg, l::QUERYCTRL_ID))?;
    let flags = handler.flags(desc.id).unwrap_or(desc.effective_flags());
    let (minimum, maximum, step, default_value) = query::legacy_view(&desc, flags)?;
    w32(arg, l::QUERYCTRL_ID, desc.id);
    w32(arg, l::QUERYCTRL_TYPE, desc.ctrl_type);
    wstr(arg, l::QUERYCTRL_NAME, l::QUERYCTRL_NAME_LEN, desc.name);
    w32i(arg, l::QUERYCTRL_MINIMUM, minimum);
    w32i(arg, l::QUERYCTRL_MAXIMUM, maximum);
    w32i(arg, l::QUERYCTRL_STEP, step);
    w32i(arg, l::QUERYCTRL_DEFAULT_VALUE, default_value);
    w32(arg, l::QUERYCTRL_FLAGS, flags);
    zero(arg, l::QUERYCTRL_RESERVED, l::QUERYCTRL_RESERVED_LEN);
    Ok(())
}

/// `VIDIOC_QUERY_EXT_CTRL`: the same walk, with the 64-bit range and the
/// element description the legacy structure cannot carry. # C: O(controls)
pub fn query_ext_ctrl(device: &Arc<VideoDevice>, arg: &mut [u8]) -> Result<(), Errno> {
    if arg.len() < l::QUERY_EXT_CTRL_SIZE { return Err(Errno::Einval); }
    let handler = &device.controls;
    let desc = *query::find(handler, r32(arg, l::QEC_ID))?;
    let flags = handler.flags(desc.id).unwrap_or(desc.effective_flags());
    w32(arg, l::QEC_ID, desc.id);
    w32(arg, l::QEC_TYPE, desc.ctrl_type);
    wstr(arg, l::QEC_NAME, l::QEC_NAME_LEN, desc.name);
    w64i(arg, l::QEC_MINIMUM, desc.minimum);
    w64i(arg, l::QEC_MAXIMUM, desc.maximum);
    w64(arg, l::QEC_STEP, desc.step);
    w64i(arg, l::QEC_DEFAULT_VALUE, desc.default_value);
    w32(arg, l::QEC_FLAGS, flags);
    let elem_size = if desc.is_64bit() { 8u32 } else { 4u32 };
    w32(arg, l::QEC_ELEM_SIZE, elem_size);
    w32(arg, l::QEC_ELEMS, 1);
    w32(arg, l::QEC_NR_OF_DIMS, 0);
    zero(arg, l::QEC_DIMS, l::QEC_DIMS_LEN);
    zero(arg, l::QEC_RESERVED, l::QEC_RESERVED_LEN);
    Ok(())
}

/// `VIDIOC_QUERYMENU`. # C: O(log n)
pub fn querymenu(device: &Arc<VideoDevice>, arg: &mut [u8]) -> Result<(), Errno> {
    if arg.len() < l::QUERYMENU_SIZE { return Err(Errno::Einval); }
    let id = r32(arg, l::QUERYMENU_ID);
    let index = r32(arg, l::QUERYMENU_INDEX);
    match query::query_menu(&device.controls, id, index)? {
        query::MenuEntry::Name(name) => {
            wstr(arg, l::QUERYMENU_NAME, l::QUERYMENU_NAME_LEN, name);
        }
        query::MenuEntry::Value(value) => {
            // The value shares the union with the name, so the name bytes
            // beyond the value must be cleared or a caller reading the name
            // arm sees the previous entry's text.
            zero(arg, l::QUERYMENU_NAME, l::QUERYMENU_NAME_LEN);
            w64i(arg, l::QUERYMENU_VALUE, value);
        }
    }
    w32(arg, l::QUERYMENU_RESERVED, 0);
    Ok(())
}

/// The caller's extended-control array, read out of their memory.
/// # C: O(count)
fn read_entries(arg: &[u8], ctx: &dyn Ctx) -> Result<(u32, u64, Vec<access::ExtEntry>), Errno> {
    let which = r32(arg, l::EXT_CTRLS_WHICH);
    let count = r32(arg, l::EXT_CTRLS_COUNT);
    let base = crate::usermem::r64(arg, l::EXT_CTRLS_CONTROLS);
    if count == 0 { return Ok((which, base, Vec::new())); }
    // A count that would overflow the copy is refused before any allocation:
    // the reference caps a batch, and an unbounded one is a way to make the
    // kernel allocate on a caller's word.
    if count > 1024 { return Err(Errno::Einval); }
    let mut raw = alloc::vec![0u8; l::EXT_CONTROL_SIZE * count as usize];
    ctx.user().read(base, &mut raw)?;
    let mut entries = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let e = &raw[i * l::EXT_CONTROL_SIZE..];
        entries.push(access::ExtEntry {
            id: r32(e, l::EXT_CTRL_ID),
            size: r32(e, l::EXT_CTRL_SIZE_FIELD),
            value: r64i(e, l::EXT_CTRL_VALUE),
        });
    }
    Ok((which, base, entries))
}

/// Write one entry's value back into the caller's array. # C: O(1)
fn write_entry(base: u64, index: usize, desc_64bit: bool, value: i64, ctx: &dyn Ctx)
    -> Result<(), Errno>
{
    let mut raw = [0u8; l::EXT_CONTROL_SIZE];
    let addr = base + (index * l::EXT_CONTROL_SIZE) as u64;
    ctx.user().read(addr, &mut raw)?;
    if desc_64bit { w64i(&mut raw, l::EXT_CTRL_VALUE, value); }
    else {
        // The value union is eight bytes; a 32-bit control occupies the low
        // half and the high half must be cleared, or a caller reading the
        // 64-bit arm sees whatever it had put there.
        w64(&mut raw, l::EXT_CTRL_VALUE, 0);
        w32i(&mut raw, l::EXT_CTRL_VALUE, value as i32);
    }
    ctx.user().write(addr, &raw)
}

fn set_error_idx(arg: &mut [u8], index: u32) { w32(arg, l::EXT_CTRLS_ERROR_IDX, index); }

/// `VIDIOC_G_EXT_CTRLS`. # C: O(count * log n)
pub fn g_ext_ctrls(device: &Arc<VideoDevice>, arg: &mut [u8], ctx: &dyn Ctx) -> Result<(), Errno> {
    if arg.len() < l::EXT_CONTROLS_SIZE { return Err(Errno::Einval); }
    let (which, base, entries) = read_entries(arg, ctx)?;
    access::check_which(which).inspect_err(|_| set_error_idx(arg, 0))?;
    // The error index means "this entry failed"; a batch that succeeds must
    // leave it at the count, which is how the reference says "none of them".
    set_error_idx(arg, entries.len() as u32);
    for (index, entry) in entries.iter().enumerate() {
        let value = match access::get_ext(&device.controls, which, entry.id) {
            Ok(v) => v,
            Err(e) => { set_error_idx(arg, index as u32); return Err(e); }
        };
        let is64 = device.controls.find(entry.id).map(|d| d.is_64bit()).unwrap_or(false);
        if let Err(e) = write_entry(base, index, is64, value, ctx) {
            set_error_idx(arg, index as u32);
            return Err(e);
        }
    }
    Ok(())
}

/// `VIDIOC_TRY_EXT_CTRLS`: validate a batch without applying it.
/// # C: O(count * log n)
pub fn try_ext_ctrls(device: &Arc<VideoDevice>, arg: &mut [u8], ctx: &dyn Ctx)
    -> Result<(), Errno>
{
    if arg.len() < l::EXT_CONTROLS_SIZE { return Err(Errno::Einval); }
    let (which, _base, entries) = read_entries(arg, ctx)?;
    set_error_idx(arg, entries.len() as u32);
    match access::try_ext(&device.controls, which, &entries) {
        Ok(()) => Ok(()),
        Err((index, e)) => { set_error_idx(arg, index); Err(e) }
    }
}

/// `VIDIOC_S_EXT_CTRLS`.
///
/// The whole batch is validated before the first store, so a request that
/// refuses one control leaves every other one untouched — an application
/// setting exposure and gain together must not end up with half of what it
/// asked for.
/// # C: O(count * log n)
pub fn s_ext_ctrls(handle: &Arc<FileHandle>, arg: &mut [u8], ctx: &dyn Ctx)
    -> Result<(), Errno>
{
    if arg.len() < l::EXT_CONTROLS_SIZE { return Err(Errno::Einval); }
    let device = handle.device.clone();
    let (which, base, entries) = read_entries(arg, ctx)?;
    set_error_idx(arg, entries.len() as u32);
    let changed = match access::set_ext(&device.controls, which, &entries) {
        Ok(changed) => changed,
        Err((index, e)) => { set_error_idx(arg, index); return Err(e); }
    };
    for (id, value) in changed.iter() {
        if device.ops.control_changed(*id, *value) {
            crate::vb2::stream::set_error(&mut device.state.lock().queue);
        }
        announce(handle, *id, *value, ctx);
    }
    for (index, entry) in entries.iter().enumerate() {
        let Some(stored) = device.controls.value(entry.id) else { continue };
        let is64 = device.controls.find(entry.id).map(|d| d.is_64bit()).unwrap_or(false);
        if let Err(e) = write_entry(base, index, is64, stored, ctx) {
            set_error_idx(arg, index as u32);
            return Err(e);
        }
    }
    Ok(())
}
