use super::*;
use syscall::nt_compositor::Rect as MRect;

fn mon(x: i32, y: i32, w: u32, h: u32) -> Monitor { Monitor { monitor: MRect { x, y, width: w, height: h }, workarea: MRect { x, y: y + 30, width: w, height: h - 30 } } }
const R: Rect = Rect { left: 10, top: 10, right: 110, bottom: 60 };

#[test]
fn handles_are_one_based_snapshot_positions() {
    let m = [mon(0, 0, 1024, 768), mon(1024, 0, 800, 600)];
    assert_eq!(monitor_for_handle(0, &m), None);
    assert_eq!(monitor_for_handle(2, &m).map(|(i, _)| i), Some(1));
    assert_eq!(monitor_for_handle(3, &m), None);
}

#[test]
fn the_largest_intersection_wins_then_primary_then_nearest() {
    let m = [mon(0, 0, 1024, 768), mon(1024, 0, 800, 600)];
    assert_eq!(monitor_from_rect(Rect { left: 1000, top: 0, right: 1100, bottom: 50 }, 0, &m, Some(0)), 2);
    let off = Rect { left: 5000, top: 5000, right: 5010, bottom: 5010 };
    assert_eq!(monitor_from_rect(off, 0, &m, Some(0)), 0);
    assert_eq!(monitor_from_rect(off, MONITOR_DEFAULTTOPRIMARY, &m, Some(0)), 1);
    assert_eq!(monitor_from_rect(off, MONITOR_DEFAULTTONEAREST, &m, Some(0)), 2);
    assert_eq!(monitor_from_rect(Rect { left: 5, top: 5, right: 5, bottom: 5 }, 0, &m, None), 1);
}

#[test]
fn monitor_info_reports_work_area_primary_flag_and_device_name() {
    let m = [mon(0, 0, 1024, 768)];
    assert_eq!(monitor_info(1, 39, &m, Some(0)), None);
    let bytes = monitor_info(1, MONITORINFO_BYTES as u32, &m, Some(0)).unwrap();
    assert_eq!(bytes.len(), MONITORINFO_BYTES);
    assert_eq!(Rect::decode(&bytes[4..20]), Some(Rect { left: 0, top: 0, right: 1024, bottom: 768 }));
    assert_eq!(Rect::decode(&bytes[20..36]), Some(Rect { left: 0, top: 30, right: 1024, bottom: 768 }));
    assert_eq!(u32::from_le_bytes(bytes[36..40].try_into().unwrap()), MONITORINFOF_PRIMARY);
    let ex = monitor_info(1, MONITORINFOEXW_BYTES as u32, &m, None).unwrap();
    assert_eq!(ex.len(), MONITORINFOEXW_BYTES);
    assert_eq!(u32::from_le_bytes(ex[36..40].try_into().unwrap()), 0);
    let name: alloc::vec::Vec<u16> = ex[40..].chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|u| *u != 0).collect();
    assert_eq!(alloc::string::String::from_utf16(&name).unwrap(), "\\\\.\\DISPLAY1");
    assert_eq!(monitor_info(2, MONITORINFO_BYTES as u32, &m, Some(0)), None);
}

#[test]
fn the_virtual_screen_is_the_union_of_monitors() {
    assert_eq!(virtual_screen_rect(&[]), None);
    assert_eq!(virtual_screen_rect(&[mon(0, 0, 1024, 768), mon(1024, -100, 800, 600)]), Some(Rect { left: 0, top: -100, right: 1824, bottom: 768 }));
}

#[test]
fn adjusting_grows_the_frame_by_the_nonclient_metrics() {
    let metric = |index: i32| match index { SM_CYCAPTION => 20, SM_CXFRAME => 4, SM_CXDLGFRAME => 3, SM_CYMENU => 20, SM_CXEDGE => 2, SM_CYEDGE => 2, SM_CYSMCAPTION => 16, SM_CXPADDEDBORDER => 4, _ => 0 };
    let overlapped = AdjustParams { style: WS_CAPTION | WS_THICKFRAME, ex_style: 0, menu: true, dpi: 96 };
    assert_eq!(adjust_window_rect(R, overlapped, metric), Rect { left: 2, top: -38, right: 118, bottom: 68 });
    let plain = AdjustParams { style: 0, ex_style: 0, menu: false, dpi: 96 };
    assert_eq!(adjust_window_rect(R, plain, metric), R);
    let edge = AdjustParams { style: 0, ex_style: WS_EX_CLIENTEDGE, menu: false, dpi: 96 };
    assert_eq!(adjust_window_rect(R, edge, metric), Rect { left: 8, top: 8, right: 112, bottom: 62 });
    assert_eq!(AdjustParams::decode(&[1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 96, 0, 0, 0]), Some(AdjustParams { style: 1, ex_style: 2, menu: true, dpi: 96 }));
}
