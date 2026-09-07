//! A frame carries one sub-rectangle; the surface it belongs to is here.
use super::*;
use crate::Rect;

fn frame(damage: Rect, pixels: Vec<u32>) -> Frame {
    Frame::new(4, 3, (damage.right - damage.left) as u32, pixels, damage).unwrap()
}

#[test]
fn a_sub_rectangle_lands_at_its_own_origin_and_leaves_the_rest_alone() {
    let mut surface = Retained::new(4, 3).unwrap();
    surface.apply(&frame(Rect { left: 0, top: 0, right: 4, bottom: 3 }, vec![0xff00_0011; 12])).unwrap();
    surface.apply(&frame(Rect { left: 1, top: 1, right: 3, bottom: 3 }, vec![1, 2, 3, 4])).unwrap();
    assert_eq!(surface.run(0, 0, 4).unwrap(), &[0xff00_0011; 4]);
    assert_eq!(surface.run(1, 0, 4).unwrap(), &[0xff00_0011, 1, 2, 0xff00_0011]);
    assert_eq!(surface.run(2, 0, 4).unwrap(), &[0xff00_0011, 3, 4, 0xff00_0011]);
}

#[test]
fn a_padded_stride_carries_whole_rows_and_only_the_damaged_run_is_taken() {
    let mut surface = Retained::new(4, 3).unwrap();
    let padded = Frame::new(4, 3, 3, vec![1, 2, 0xdead, 3, 4, 0xbeef], Rect { left: 2, top: 0, right: 4, bottom: 2 }).unwrap();
    surface.apply(&padded).unwrap();
    assert_eq!(surface.run(0, 2, 2).unwrap(), &[1, 2]);
    assert_eq!(surface.run(1, 2, 2).unwrap(), &[3, 4]);
}

#[test]
fn a_frame_for_another_extent_and_a_run_off_the_surface_are_refused() {
    let mut surface = Retained::new(4, 3).unwrap();
    let other = Frame::new(5, 3, 5, vec![0; 15], Rect { left: 0, top: 0, right: 5, bottom: 3 }).unwrap();
    assert!(matches!(surface.apply(&other), Err(TransportError::InvalidFrame)));
    assert!(surface.run(2, 3, 2).is_none());
    assert!(surface.run(3, 0, 1).is_none());
    assert!(Retained::new(0, 3).is_err());
}
