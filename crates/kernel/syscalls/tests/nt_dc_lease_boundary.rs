//! Joined GetDCEx boundary: raw-shaped request -> canonical HWND context -> GDI lease.
extern crate alloc;

use ipc::win32_gdi::{DcLeaseRequest, GdiError, GdiManager, DCX_INTERSECTRGN, DCX_PARENTCLIP};
use ipc::win32_window::{PaintRegion, WindowId, WindowManager, WindowRect};

#[path = "../src/nt_wine_window/dc_raw.rs"]
mod dc_raw;

const WS_VISIBLE: u32 = 0x1000_0000;

fn rect(left: i32, top: i32, right: i32, bottom: i32) -> WindowRect { WindowRect { left, top, right, bottom } }

fn raw_get_dc_ex(state: &WindowManager, args: [u64; 3]) -> Option<(ipc::win32_window::DcLeaseContext, u32)> {
    let mut result = None;
    let status = dc_raw::route(dc_raw::GET_DC_EX, &args, |request| match request {
        dc_raw::Request::Acquire { hwnd, region, flags } => {
            let Some(hwnd) = WindowId::from_raw(hwnd) else { return 0; };
            result = state.dc_lease_context(hwnd, flags).ok().map(|context| (context, region));
            u64::from(result.is_some())
        }
        dc_raw::Request::Release { .. } => 0,
    });
    (status == Some(1)).then_some(result).flatten()
}

#[test]
fn raw_getdcex_parent_clip_reaches_parent_backing_and_negative_origin_pixels() {
    let mut windows = WindowManager::new();
    let parent = windows.create(7, None, 0).unwrap();
    let child = windows.create(7, Some(parent), 0).unwrap();
    windows.set_window_styles(parent, WS_VISIBLE, 0).unwrap();
    windows.set_window_styles(child, WS_VISIBLE, 0).unwrap();
    windows.set_rect(parent, rect(0, 0, 10, 10)).unwrap();
    windows.set_rect(child, rect(-2, -2, 6, 6)).unwrap();
    windows.show(7, parent, true).unwrap();
    windows.show(7, child, true).unwrap();

    let (context, region) = raw_get_dc_ex(&windows, [child.raw() as u64, 0, DCX_PARENTCLIP as u64]).unwrap();
    assert_eq!(region, 0);
    assert_eq!(context.backing_hwnd, parent.raw());
    assert_eq!(context.origin, (-2, -2));
    assert_eq!(context.screen_origin, (-2, -2));
    assert_eq!((context.backing_width, context.backing_height), (10, 10));

    let mut gdi = GdiManager::new();
    let backing = gdi.acquire_window_dc(parent.raw(), 10, 10).unwrap();
    let dc = gdi.acquire_dc_lease(DcLeaseRequest { hwnd: child.raw(), backing_hwnd: context.backing_hwnd,
        backing, origin: context.origin, screen_origin: context.screen_origin,
        width: context.logical_width, height: context.logical_height, visible: context.visible,
        flags: context.flags, owner: context.owner, clip_handle: 0 }).unwrap();

    assert_eq!(gdi.dc_pixel_target(dc, 0, 0).unwrap(), None);
    assert_eq!(gdi.dc_pixel_target(dc, 2, 2).unwrap(), Some((backing, 0)));
    gdi.write_dc_pixel(dc, 0, 0, 0xdeadbe).unwrap();
    gdi.write_dc_pixel(dc, 2, 2, 0x112233).unwrap();
    assert_eq!(gdi.dc_pixel_target(dc, 9, 9).unwrap(), Some((backing, 77)));
    gdi.release_dc_lease(dc).unwrap();
}

#[test]
fn raw_getdcex_hidden_and_zero_surface_do_not_admit_visible_pixels() {
    let mut windows = WindowManager::new();
    let hwnd = windows.create(7, None, 0).unwrap();
    windows.set_window_styles(hwnd, WS_VISIBLE, 0).unwrap();
    windows.set_rect(hwnd, rect(0, 0, 0, 0)).unwrap();
    let (context, region) = raw_get_dc_ex(&windows, [hwnd.raw() as u64, 0, 0]).unwrap();
    assert_eq!(region, 0);
    assert!(context.visible.is_empty());
    assert_eq!((context.logical_width, context.logical_height), (0, 0));

    let mut gdi = GdiManager::new();
    let backing = gdi.acquire_window_dc(hwnd.raw(), context.backing_width, context.backing_height).unwrap();
    let dc = gdi.acquire_dc_lease(DcLeaseRequest {
        hwnd: hwnd.raw(), backing_hwnd: context.backing_hwnd, backing,
        origin: context.origin, screen_origin: context.screen_origin,
        width: context.logical_width, height: context.logical_height,
        visible: context.visible, flags: context.flags, owner: context.owner, clip_handle: 0,
    }).unwrap();
    assert_eq!(gdi.text_metrics(dc).unwrap().height, 16);
    assert_eq!(gdi.dc_pixel_target(dc, 0, 0).unwrap(), None);
    assert!(gdi.dc_raster_clip(dc).unwrap().is_empty());
    assert_eq!(gdi.dc_backing_surface(dc).unwrap().2, &[]);
    gdi.release_dc_lease(dc).unwrap();
}

#[test]
fn raw_getdcex_top_level_siblings_are_not_clipped_by_window_context() {
    let mut windows = WindowManager::new();
    let first = windows.create(7, None, 0).unwrap();
    let second = windows.create(7, None, 0).unwrap();
    for hwnd in [first, second] {
        windows.set_window_styles(hwnd, WS_VISIBLE, 0).unwrap();
        windows.set_rect(hwnd, rect(0, 0, 8, 8)).unwrap();
        windows.show(7, hwnd, true).unwrap();
    }
    let (context, region) = raw_get_dc_ex(&windows, [first.raw() as u64, 0, 1]).unwrap();
    assert_eq!(region, 0);
    assert_eq!(context.visible, PaintRegion::from_rect(rect(0, 0, 8, 8)).unwrap());
}

#[test]
fn raw_getdcex_parent_clip_consumes_screen_hrgn_and_releases_it_after_cached_lease() {
    let mut windows = WindowManager::new();
    let parent = windows.create(7, None, 0).unwrap();
    let child = windows.create(7, Some(parent), 0).unwrap();
    windows.set_window_styles(parent, WS_VISIBLE, 0).unwrap();
    windows.set_window_styles(child, WS_VISIBLE, 0).unwrap();
    windows.set_rect(parent, rect(0, 0, 10, 10)).unwrap();
    windows.set_rect(child, rect(-2, -2, 6, 6)).unwrap();
    windows.show(7, parent, true).unwrap();
    windows.show(7, child, true).unwrap();
    let mut gdi = GdiManager::new();
    let backing = gdi.acquire_window_dc(parent.raw(), 10, 10).unwrap();
    let region = gdi.create_region(PaintRegion::from_rect(rect(0, 0, 5, 5)).unwrap()).unwrap();
    let (context, routed_region) = raw_get_dc_ex(&windows, [child.raw() as u64, region as u64, (DCX_PARENTCLIP | DCX_INTERSECTRGN) as u64]).unwrap();
    assert_eq!(routed_region, region);
    let dc = gdi.acquire_dc_lease(DcLeaseRequest { hwnd: child.raw(), backing_hwnd: parent.raw(), backing,
        origin: context.origin, screen_origin: context.screen_origin, width: context.logical_width,
        height: context.logical_height, visible: context.visible, flags: context.flags | DCX_INTERSECTRGN,
        owner: context.owner, clip_handle: routed_region }).unwrap();

    assert_eq!(gdi.dc_pixel_target(dc, 2, 2).unwrap(), Some((backing, 0)));
    assert_eq!(gdi.dc_pixel_target(dc, 7, 2).unwrap(), None);
    assert!(gdi.region_snapshot(region).is_ok());
    gdi.release_dc_lease(dc).unwrap();
    assert_eq!(gdi.region_snapshot(region), Err(GdiError::NoSuchObject));
}
