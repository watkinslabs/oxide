use super::*;
use crate::win32_window::WindowError;

fn frame(width: i32, height: i32) -> CursorFrame {
    CursorFrame { width, height, hotspot_x: 1, hotspot_y: 2, color: 0x11, mask: 0x22, alpha: 0x33 }
}

fn still(frames: &[CursorFrame]) -> CursorIconDesc<'_> {
    CursorIconDesc { delay: 0, num_steps: 0, num_frames: 1, frames, frame_seq: &[], frame_rates: &[], flags: 0, rsrc: 0 }
}

#[test]
fn an_empty_object_is_filled_once_and_a_second_fill_is_refused() {
    let mut icons = CursorIcons::new();
    let handle = icons.alloc(true).unwrap();
    assert!(handle >= OEM_CURSOR_BASE);
    assert_eq!(icons.set_data(handle, &[], None, None, &still(&[frame(32, 32)])), Ok(()));
    assert_eq!(icons.set_data(handle, &[], None, None, &still(&[frame(16, 16)])), Err(WindowError::InvalidParent));
}

#[test]
fn an_icon_reports_its_stacked_mask_height_and_its_hotspot() {
    let mut icons = CursorIcons::new();
    let handle = icons.alloc(true).unwrap();
    icons.set_data(handle, &[], None, None, &still(&[frame(32, 24)])).unwrap();
    assert_eq!(icons.icon_size(handle, 0), Some((32, 48)));
    assert_eq!(icons.icon_info(handle), Some(IconInfo { is_icon: true, hotspot_x: 1, hotspot_y: 2, color: 0x11, mask: 0x22 }));
    assert_eq!(icons.icon_size(handle, 3), Some((32, 48)));
}

#[test]
fn a_static_object_reports_one_endless_frame() {
    let mut icons = CursorIcons::new();
    let handle = icons.alloc(false).unwrap();
    icons.set_data(handle, &[], None, None, &still(&[frame(32, 32)])).unwrap();
    assert_eq!(icons.frame_info(handle, 0), Some(FrameInfo { cursor: handle, rate_jiffies: 0, num_steps: 1 }));
}

#[test]
fn an_animated_object_owns_one_child_per_step_with_its_own_rate() {
    let mut icons = CursorIcons::new();
    let handle = icons.alloc(false).unwrap();
    let frames = [frame(32, 32), frame(16, 16)];
    let desc = CursorIconDesc { delay: 5, num_steps: 3, num_frames: 2, frames: &frames,
        frame_seq: &[1, 0, 1], frame_rates: &[7, 8, 9], flags: 0, rsrc: 0 };
    icons.set_data(handle, &[], None, None, &desc).unwrap();
    let first = icons.frame_info(handle, 0).unwrap();
    assert_eq!(first.num_steps, 3);
    assert_eq!(first.rate_jiffies, 7);
    assert_ne!(first.cursor, handle);
    assert_eq!(icons.frame_info(handle, 2).unwrap().rate_jiffies, 9);
    assert_eq!(icons.frame(handle, 0).unwrap().width, 16);
    assert_eq!(icons.frame(handle, 1).unwrap().width, 32);
    assert_eq!(icons.frame_info(handle, 3), None);
}

#[test]
fn a_sequence_entry_past_the_frame_list_names_the_last_frame() {
    let mut icons = CursorIcons::new();
    let handle = icons.alloc(false).unwrap();
    let frames = [frame(32, 32), frame(8, 8)];
    let desc = CursorIconDesc { delay: 1, num_steps: 1, num_frames: 2, frames: &frames,
        frame_seq: &[9], frame_rates: &[], flags: 0, rsrc: 0 };
    icons.set_data(handle, &[], None, None, &desc).unwrap();
    assert_eq!(icons.frame(handle, 0).unwrap().width, 8);
}

#[test]
fn a_shared_object_is_found_by_module_and_resource_and_survives_destroy() {
    let mut icons = CursorIcons::new();
    let handle = icons.alloc(true).unwrap();
    let module = [b'u' as u16, b'2' as u16];
    let frames = [frame(32, 32)];
    let desc = CursorIconDesc { flags: LR_SHARED, rsrc: 0x40, ..still(&frames) };
    icons.set_data(handle, &module, None, Some(7), &desc).unwrap();
    assert_eq!(icons.find_existing(&module, 0x40), Some(handle));
    assert_eq!(icons.find_existing(&module, 0x41), None);
    assert_eq!(icons.find_existing(&[], 0x40), None);
    assert!(icons.destroy(handle));
    assert!(icons.contains(handle));
    assert_eq!(icons.resource(handle).map(|(module, _, id)| (module.len(), id)), Some((2, Some(7))));
}

#[test]
fn destroying_an_unshared_animated_object_frees_every_step_child() {
    let mut icons = CursorIcons::new();
    let handle = icons.alloc(false).unwrap();
    let frames = [frame(32, 32), frame(16, 16)];
    let desc = CursorIconDesc { delay: 1, num_steps: 2, num_frames: 2, frames: &frames,
        frame_seq: &[0, 1], frame_rates: &[], flags: 0, rsrc: 0 };
    icons.set_data(handle, &[], None, None, &desc).unwrap();
    let child = icons.frame_info(handle, 1).unwrap().cursor;
    assert!(icons.destroy(handle));
    assert!(!icons.contains(handle));
    assert!(!icons.contains(child));
}

#[test]
fn the_client_parameter_round_trips_and_an_unknown_handle_answers_zero() {
    let mut icons = CursorIcons::new();
    let handle = icons.alloc(true).unwrap();
    assert_eq!(icons.set_param(handle, 0xabc), 0);
    assert_eq!(icons.param(handle), 0xabc);
    assert_eq!(icons.param(0xdead), 0);
    assert_eq!(icons.set_param(0xdead, 1), 0);
}
