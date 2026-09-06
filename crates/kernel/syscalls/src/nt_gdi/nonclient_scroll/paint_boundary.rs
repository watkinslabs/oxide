//! Child of the ordinary paint boundary harness; production Begin/EndPaint stay unchanged.
use super::*;
use ipc::win32_gdi::{PaintBacking, ScrollColors, ScrollDrawOutcome, ScrollMetrics, ScrollPart};
use ipc::win32_window::{ScrollState, SB_VERT};

#[path = "../nonclient_scroll.rs"]
mod scroll_adapter;

#[path = "../paint_frame.rs"]
mod paint_frame;

const OUTER: Rect = Rect { left: 0, top: 0, right: 4, bottom: 4 };
const CLIENT: Rect = Rect { left: 1, top: 1, right: 3, bottom: 4 };
const LAYOUT: PaintBacking = PaintBacking { width: 4, height: 4, client: CLIENT };
const OLD: u32 = 0x123456;
const NEW: u32 = 0xabcdef;

fn retaining_gdi(service: NtService, args: SyscallArgs) -> u64 {
    if service != NtService::PresentGdiWindowRegion { return gdi(service, args); }
    let mut state = STATE.lock().unwrap();
    let damage = Rect { left: args.a2 as i32, top: args.a3 as i32, right: args.a4 as i32, bottom: args.a5 as i32 };
    assert_eq!(damage, Rect { left: 0, top: 1, right: 1, bottom: 2 });
    let region = state.windows.paint_region(state.window).unwrap();
    let frame = paint_frame::capture_region(&mut state.gdi, args.a0 as u32, args.a1 as u32, &region, LAYOUT).unwrap();
    let backing = state.gdi.window_dc(args.a0 as u32).unwrap();
    assert_ne!(backing, args.a1 as u32);
    // The submitted image must be the retained surface, not the fresh paint DC.
    let pixels = state.gdi.pixels(backing).unwrap();
    assert_eq!(pixels[0], OLD);
    assert_eq!(pixels[2 * 4 + 1], NEW);
    let word = |index: usize| u32::from_le_bytes(frame.payload[16 + index * 4..20 + index * 4].try_into().unwrap());
    assert_eq!(word(0), OLD | 0xff000000);
    assert_eq!(word(9), NEW | 0xff000000);
    state.presents += 1;
    STATUS_SUCCESS
}

#[test]
fn end_paint_retains_offset_damage_then_nonclient_keeps_every_client_pixel() {
    let _serial = TEST_LOCK.lock().unwrap();
    *STATE.lock().unwrap() = State::new(region(0, 1, 1, 2));
    let backing = {
        let mut state = STATE.lock().unwrap();
        state.seed_layout = Some(LAYOUT);
        let backing = state.gdi.acquire_window_dc(HWND as u32, 4, 4).unwrap();
        state.gdi.fill_rect(backing, OUTER, OLD).unwrap();
        backing
    };
    let mut args = [0; 17]; args[0] = HWND; args[1] = PS;
    let paint = production::begin_paint(&args, native, retaining_gdi);
    assert_ne!(paint, 0);
    {
        let mut state = STATE.lock().unwrap();
        state.gdi.fill_rect(paint as u32, OUTER, NEW).unwrap();
        // Seed precedes drawing; old client pixels survive outside admitted damage.
        assert_eq!(state.seed_calls, 1);
        assert_eq!(state.gdi.pixels(paint as u32).unwrap()[0], OLD);
    }
    assert_eq!(production::end_paint(&args, native, retaining_gdi), 1);
    let mut state = STATE.lock().unwrap();
    assert!(!state.gdi.contains_object(paint as u32));
    assert_eq!(state.gdi.window_dc(HWND as u32), Some(backing));
    let before = state.gdi.pixels(backing).unwrap().to_vec();
    for (index, pixel) in before.iter().enumerate() { assert_eq!(*pixel, if index == 9 { NEW } else { OLD }); }
    let colors = ScrollColors { face: 1, highlight: 2, light: 3, shadow: 4, dark_shadow: 5, text: 6, window: 7, track: 8 };
    let context = scroll_adapter::NonclientScrollContext { window: region(0, 0, 4, 4), client: CLIENT,
        style: 0x0020_0000, ex_style: 0, metrics: ScrollMetrics { arrow_size: 1, dpi: 96 }, colors, pressed: ScrollPart::None };
    let scroll = ScrollState { visible: true, max: 99, page: 10, ..ScrollState::new() };
    assert_eq!(scroll_adapter::render(&mut state.gdi, HWND as u32, SB_VERT, scroll, context),
        Ok((backing, ScrollDrawOutcome::Painted(Rect { left: 3, top: 1, right: 4, bottom: 4 }))));
    let after = state.gdi.pixels(backing).unwrap();
    for y in 0..4 { for x in 0..4 {
        assert_eq!(after[y * 4 + x], if x == 3 && y >= 1 { colors.track } else { before[y * 4 + x] });
    } }
    assert_eq!((state.presents, state.deletes), (1, 1));
}

#[test]
fn production_seed_preserves_transparent_and_app_clipped_pixels_inside_damage() {
    let _serial = TEST_LOCK.lock().unwrap();
    *STATE.lock().unwrap() = State::new(region(0, 0, 2, 3));
    let backing = {
        let mut state = STATE.lock().unwrap(); state.seed_layout = Some(LAYOUT);
        let dc = state.gdi.acquire_window_dc(HWND as u32, 4, 4).unwrap();
        state.gdi.fill_rect(dc, OUTER, OLD).unwrap(); dc
    };
    let capture = |service, args: SyscallArgs| {
        if service != NtService::PresentGdiWindowRegion { return gdi(service, args); }
        let mut state = STATE.lock().unwrap();
        let region = state.windows.paint_region(state.window).unwrap();
        let frame = paint_frame::capture_region(&mut state.gdi, args.a0 as u32, args.a1 as u32, &region, LAYOUT).unwrap();
        let word = |index: usize| u32::from_le_bytes(frame.payload[16 + index * 4..20 + index * 4].try_into().unwrap());
        assert_eq!(word(5), NEW | 0xff000000);
        assert_eq!(word(6), OLD | 0xff000000);
        state.presents += 1; STATUS_SUCCESS
    };
    let mut args = [0; 17]; args[0] = HWND; args[1] = PS;
    let paint = production::begin_paint(&args, native, capture);
    assert_ne!(paint, 0);
    {
        let mut state = STATE.lock().unwrap();
        assert_eq!(state.seed_calls, 1);
        // Transparent glyph coverage must use seeded pixels, not transparent black.
        state.gdi.blend_pixels(paint as u32, 1, 0, 1, 1, &[0x00ffffff]).unwrap();
        state.gdi.intersect_clip_rect(paint as u32, Rect { left: 0, top: 0, right: 1, bottom: 1 }).unwrap();
        state.gdi.fill_rect(paint as u32, OUTER, NEW).unwrap();
    }
    assert_eq!(production::end_paint(&args, native, capture), 1);
    let state = STATE.lock().unwrap();
    for (index, pixel) in state.gdi.pixels(backing).unwrap().iter().enumerate() {
        assert_eq!(*pixel, if index == 5 { NEW } else { OLD });
    }
    assert!(!state.gdi.contains_object(paint as u32));
}

#[test]
fn production_exact_paint_clip_and_capture_preserve_hole_even_with_poisoned_source_gap() {
    let _serial = TEST_LOCK.lock().unwrap();
    let mut initial = State::new(region(0, 0, 0, 0));
    initial.region = Some(region(0, 0, 4, 4));
    initial.windows.invalidate(initial.window, Some(region(0, 0, 1, 4))).unwrap();
    initial.windows.invalidate(initial.window, Some(region(3, 0, 4, 4))).unwrap();
    let backing = initial.gdi.acquire_window_dc(HWND as u32, 4, 4).unwrap();
    initial.gdi.fill_rect(backing, OUTER, OLD).unwrap();
    *STATE.lock().unwrap() = initial;
    let capture = |service, args: SyscallArgs| {
        if service != NtService::PresentGdiWindowRegion { return gdi(service, args); }
        let mut state = STATE.lock().unwrap();
        let coverage = state.windows.paint_region(state.window).unwrap();
        assert_eq!(coverage.rects().len(), 2);
        let frame = paint_frame::capture_region(&mut state.gdi, args.a0 as u32, args.a1 as u32, &coverage,
            PaintBacking { width: 4, height: 4, client: OUTER }).unwrap();
        for index in 0..16 {
            let pixel = u32::from_le_bytes(frame.payload[16 + index * 4..20 + index * 4].try_into().unwrap());
            assert_eq!(pixel, (if index % 4 == 0 || index % 4 == 3 { NEW } else { OLD }) | 0xff000000);
        }
        state.presents += 1; STATUS_SUCCESS
    };
    let mut args = [0; 17]; args[0] = HWND; args[1] = PS;
    let paint = production::begin_paint(&args, native, capture);
    assert_ne!(paint, 0);
    {
        let mut state = STATE.lock().unwrap();
        state.gdi.fill_rect(paint as u32, OUTER, NEW).unwrap();
        for index in 0..16 {
            assert_eq!(state.gdi.pixels(paint as u32).unwrap()[index], if index % 4 == 0 || index % 4 == 3 { NEW } else { OLD });
        }
        // Deliberately make source holes differ: exact capture must not trust the enclosing box.
        state.gdi.set_paint_clip(paint as u32, OUTER).unwrap();
        state.gdi.fill_rect(paint as u32, Rect { left: 1, top: 0, right: 3, bottom: 4 }, 0xff00ff).unwrap();
    }
    assert_eq!(production::end_paint(&args, native, capture), 1);
    let state = STATE.lock().unwrap();
    assert!(!state.gdi.contains_object(paint as u32));
    for index in 0..16 { assert_eq!(state.gdi.pixels(backing).unwrap()[index], if index % 4 == 0 || index % 4 == 3 { NEW } else { OLD }); }
}
