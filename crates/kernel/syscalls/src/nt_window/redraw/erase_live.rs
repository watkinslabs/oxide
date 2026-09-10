use super::ErasePrepared;
use alloc::sync::Arc;
use ipc::win32_window::{PaintRegion, WindowId};
use ipc::win32_gdi::{PaintBacking, Rect};
use crate::nt_window::{GUI, paint_callbacks};

/// Prepare auxiliary painting without reserving/consuming a BeginPaint session.
/// # C: O(windows + regions + client pixels); # Sleeps: yes, outside GUI/GDI
pub(crate) fn begin_for_current(hwnd: u32, redraw_token: u64) -> u64 {
    let snapshot = (|| {
        let cur = sched::live::current().filter(|c| c.is_nt_personality())?;
        let id = WindowId::from_raw(hwnd)?;
        let entries = GUI.lock(); let entry = entries.iter().find(|e| e.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
        let record = entry.state.get(id)?;
        // Shared-process resources are prepared by the sender; Send executes on the HWND owner.
        let bounds = entry.state.rect(id)?; let client = record.client_rect.unwrap_or(bounds);
        let layout = PaintBacking { width: bounds.right.checked_sub(bounds.left)?, height: bounds.bottom.checked_sub(bounds.top)?,
            client: Rect { left: client.left.checked_sub(bounds.left)?, top: client.top.checked_sub(bounds.top)?,
                right: client.right.checked_sub(bounds.left)?, bottom: client.bottom.checked_sub(bounds.top)? } };
        let damage = entry.state.erase_damage(id).ok()?;
        let local = entry.state.client_rect(id)?;
        let clipped = damage.region.clipped(local).ok()?;
        let nc = if damage.nonclient { entry.state.paint_region_to_screen(id, &damage.region).ok()? } else { PaintRegion::default() };
        Some((cur.tid as u64, bounds, client, layout, damage, clipped, nc))
    })();
    let Some((tid, bounds, client, layout, damage, clipped, nc)) = snapshot else { return super::super::resume(redraw_token, Err(())); };
    let mut prepared = ErasePrepared { hwnd, dc: 0, nc_region: 0, client_region: 0, tid, redraw_token, layout };
    let result = (|| {
        if !nc.is_empty() { prepared.nc_region = crate::nt_gdi::create_region_for_current(nc).ok()?; }
        if !clipped.is_empty() && damage.erase {
            prepared.dc=u32::try_from(crate::nt_gdi::get_dc_ex_for_current(hwnd,0,ipc::win32_gdi::DCX_USESTYLE)).ok().filter(|dc|*dc!=0)?;
            prepared.client_region = crate::nt_gdi::create_region_for_current(clipped.try_copy().ok()?).ok()?;
            crate::nt_gdi::set_paint_region_for_current(prepared.dc as u64, clipped.try_copy().ok()?).ok()?;
        }
        let cur = sched::live::current()?; let id = WindowId::from_raw(hwnd)?;
        let mut entries = GUI.lock(); let entry = entries.iter_mut().find(|e| e.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
        if entry.state.rect(id)? != bounds || entry.state.get(id)?.client_rect.unwrap_or(bounds) != client { return None; }
        entry.state.take_erase_damage_if(id, &damage).ok()?;
        Some(())
    })();
    if result.is_none() { discard_for_current(prepared); return super::super::resume(redraw_token, Err(())); }
    paint_callbacks::for_current(paint_callbacks::Resources { hwnd: hwnd as u64, dc: prepared.dc as u64,
        nc_region: prepared.nc_region as u64, erase: damage.erase, delayed: damage.delayed_erase, empty_clip: clipped.is_empty() },
        paint_callbacks::Completion::Erase(prepared))
}

/// Retain actual erased pixels, merge only delayed erase, release owned resources, then resume scan.
/// # C: O(regions + pixels + windows); # Sleeps: yes, outside GUI/GDI
pub(crate) fn finish_for_current(prepared: ErasePrepared, result: Result<bool, ()>) -> u64 {
    let Some(cur) = sched::live::current().filter(|c| c.tid as u64 == prepared.tid) else { return 0; };
    let result = result.and_then(|needed| {
        if prepared.dc != 0 {
            let region = crate::nt_gdi::region_snapshot_for_current(prepared.client_region as u64).map_err(|_| ())?;
            crate::nt_gdi::retain_erase_for_current(prepared.hwnd, prepared.dc, &region, prepared.layout).map_err(|_| ())?;
        }
        let id = WindowId::from_raw(prepared.hwnd).ok_or(())?;
        let mut entries = GUI.lock(); let entry = entries.iter_mut().find(|e| e.group.ptr_eq(&Arc::downgrade(&cur.thread_group))).ok_or(())?;
        entry.state.get(id).ok_or(())?; entry.state.finish_erase_damage(id, needed); Ok(0)
    });
    discard_for_current(prepared);
    super::super::resume(prepared.redraw_token, result)
}
/// Same-process teardown releases owned resources, including foreign-thread HWND destruction.
/// Caller holds the payload's process context; never resumes a retiring thread. # C: O(GDI objects)
pub(crate) fn discard_for_current(p: ErasePrepared) {
    if !sched::live::current().is_some_and(|c| c.is_nt_personality()) { return; }
    if p.dc != 0 { let _ = crate::nt_gdi::delete_paint_dc_current(p.dc); }
    for region in [p.nc_region, p.client_region] { if region != 0 { let _ = crate::nt_gdi::delete_region_for_current(region as u64); } }
}
