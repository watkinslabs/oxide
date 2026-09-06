use super::*;
use syscall::nt_compositor::{Opcode, Record, Rect};

fn decoded_monitor(workarea: Rect) -> Monitor {
    let monitor = Rect { x: -1200, y: 0, width: 1200, height: 900 };
    let mut payload = 1u32.to_le_bytes().to_vec();
    payload.extend_from_slice(&monitor.encode().unwrap());
    payload.extend_from_slice(&workarea.encode().unwrap());
    Record::new(Opcode::Monitors, 1, 0, payload).unwrap().monitors().unwrap()[0]
}

#[test]
fn desktop_workarea_updates_replace_old_placement_without_scanout_fallback() {
    let first = decoded_monitor(Rect { x: -1200, y: 30, width: 1200, height: 870 });
    let second = decoded_monitor(Rect { x: -1170, y: 0, width: 1170, height: 840 });
    let startup = Defaults { position: Some((10, 20)), size: Some((300, 400)), work_area: None };
    let a = with_monitor(startup, Some(first));
    assert_eq!(a.work_area, Some(super::super::geometry::Rect { left: -1200, top: 30, right: 0, bottom: 900 }));
    let b = with_monitor(a, Some(second));
    assert_eq!(b.work_area, Some(super::super::geometry::Rect { left: -1170, top: 0, right: 0, bottom: 840 }));
    assert_eq!(b.position, startup.position); assert_eq!(b.size, startup.size);
    assert_eq!(with_monitor(b, None).work_area, None);
}

#[test]
fn empty_monitor_record_invalidates_workarea_instead_of_retaining_it() {
    let first = decoded_monitor(Rect { x: -1200, y: 30, width: 1200, height: 870 });
    let prior = with_monitor(Defaults::default(), Some(first));
    let empty = Record::new(Opcode::Monitors, 2, 0, 0u32.to_le_bytes().to_vec()).unwrap();
    let monitors = empty.monitors().unwrap();
    assert_eq!(with_monitor(prior, monitors.first().copied()).work_area, None);
}

#[test]
fn malformed_desktop_record_cannot_supply_a_workarea() {
    let monitor = Rect { x: 0, y: 0, width: 1200, height: 900 };
    let outside = Rect { x: 0, y: 30, width: 1201, height: 870 };
    let mut payload = 1u32.to_le_bytes().to_vec();
    payload.extend_from_slice(&monitor.encode().unwrap());
    payload.extend_from_slice(&outside.encode().unwrap());
    assert!(Record::new(Opcode::Monitors, 1, 0, payload).is_err());
    assert_eq!(with_monitor(Defaults::default(), None).work_area, None);
}

#[test]
fn production_default_query_consumes_each_desktop_update_and_disconnect() {
    let first = decoded_monitor(Rect { x: -1200, y: 30, width: 1200, height: 870 });
    let second = decoded_monitor(Rect { x: -1170, y: 0, width: 1170, height: 840 });
    let mut snapshots = [Some(vec![first]), Some(vec![second]), None, Some(vec![])].into_iter();
    for expected in [Some((-1200, 30)), Some((-1170, 0)), None, None] {
        let d = read_defaults(0x1000, |p| { assert_eq!(p, 0x1020); Some(0x9000) },
            |p| { assert_eq!(p, 0x90a4); Some(0) }, || snapshots.next().unwrap());
        assert_eq!(d.work_area.map(|r| (r.left, r.top)), expected);
    }
    assert_eq!(snapshots.next(), None);
}

#[test]
fn invalid_startup_does_not_get_replaced_with_desktop_defaults() {
    let d = read_defaults(0x1000, |_| None, |_| panic!("invalid PEB"), || panic!("invalid startup"));
    assert_eq!(d.work_area, None); assert_eq!(d.position, None); assert_eq!(d.size, None);
}
