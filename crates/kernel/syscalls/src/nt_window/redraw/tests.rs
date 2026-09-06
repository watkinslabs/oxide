use super::*;

#[test]
fn redraw_queue_tokens_are_bounded_owned_and_nested() {
    let mut queue = Queue::new();
    let root = WindowId::from_raw(1).unwrap();
    let first = queue.admit(7, root, PaintChildren::All).unwrap();
    let nested = queue.admit(7, root, PaintChildren::None).unwrap();
    assert_ne!(first, nested);
    assert!(queue.scan(8, first).is_none());
    assert!(!queue.advance(8, first, root));
    assert!(!queue.finish(8, first));
    assert!(queue.advance(7, first, root));
    assert_eq!(queue.scan(7, nested).unwrap().after, None);
    assert!(queue.finish(7, nested));
    assert_eq!(queue.scan(7, first).unwrap().after, Some(root));
    for _ in 1..MAX_REDRAWS { queue.admit(7, root, PaintChildren::All).unwrap(); }
    assert!(queue.admit(7, root, PaintChildren::All).is_none());
    queue.cancel_thread(7);
    assert!(queue.pending.is_empty());
    queue.admit(7, root, PaintChildren::All).unwrap();
    queue.cancel_window(root);
    assert!(queue.pending.is_empty());
}

#[test]
fn redraw_flags_admit_erase_and_region_mutation_without_dropping_child_mode() {
    assert_eq!(mode(0, 0, 0x180), Some(PaintChildren::All));
    assert_eq!(mode(0, 0, 0x1c0), Some(PaintChildren::None));
    assert_eq!(mode(0, 0, 0x100), Some(PaintChildren::Default));
    for flags in [0, 0x181, 0x300, 0x85, 0x428, 0x1f] { assert!(mode(1,0,flags).is_some()); }
    assert!(mode(0,1,0x180).is_some());
    for (rect, region, flags) in [(0, 0, 0x200), (1, 0, 0x285)] {
        assert!(mode(rect, region, flags).is_some());
    }
}

#[test]
fn immediate_erase_completion_is_driven_iteratively_not_recursive() {
    let mut q=Queue::new();let id=WindowId::from_raw(1).unwrap();let token=q.admit(7,id,PaintChildren::All).unwrap();
    assert!(!q.defer_if_driving(7,token,Ok(0)));q.drive_erase(7,token);
    assert!(!q.defer_if_driving(8,token,Ok(0)));assert!(q.defer_if_driving(7,token,Ok(0)));
    assert_eq!(q.end_drive(7,token),Some(Ok(0)));assert_eq!(q.end_drive(7,token),None);
}

#[test]
fn hrgn_snapshot_precedes_and_suppresses_rect_usercopy() {
    let region=ipc::win32_window::PaintRegion::default();
    assert_eq!(read_region(u64::MAX,7,|_,_|unreachable!(),|h|{assert_eq!(h,7);Ok(region)}),Ok(Some(ipc::win32_window::PaintRegion::default())));
    assert!(read_region(1,7,|_,_|unreachable!(),|_|Err(())).is_err());
}

#[test]
fn raw_rect_copy_ordering_empty_and_overflow_are_checked_before_owner() {
    assert_eq!(read_rect(0, |_,_|unreachable!()), Ok(None));
    assert!(read_rect(u64::MAX, |_,_|unreachable!()).is_err());
    assert!(read_rect(1, |_,_|Err(())).is_err());
    let region=read_rect(1, |out,_| { for (i,value) in [8i32,9,2,3].iter().enumerate() {out[i*4..i*4+4].copy_from_slice(&value.to_le_bytes());}Ok(()) }).unwrap().unwrap();
    assert_eq!(region.bounds(),Some(ipc::win32_window::WindowRect{left:2,top:3,right:8,bottom:9}));
    assert!(read_rect(1, |out,_| {out.fill(0);Ok(())}).unwrap().unwrap().is_empty());
}
