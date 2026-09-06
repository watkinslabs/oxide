use super::*;
use syscall::nt_compositor::{Opcode, Record, Rect};

fn snapshot(monitor: Rect, workarea: Rect) -> Vec<Monitor> {
    let mut payload = 1u32.to_le_bytes().to_vec();
    payload.extend_from_slice(&monitor.encode().unwrap());
    payload.extend_from_slice(&workarea.encode().unwrap());
    Record::new(Opcode::Monitors, 1, 0, payload).unwrap().monitors().unwrap()
}

#[test]
fn metrics_follow_replaced_desktop_snapshot_not_workarea_dimensions() {
    let a = snapshot(Rect { x: 0, y: 0, width: 1600, height: 900 },
        Rect { x: 30, y: 40, width: 1570, height: 860 });
    let b = snapshot(Rect { x: 0, y: 0, width: 1280, height: 720 },
        Rect { x: 0, y: 60, width: 1280, height: 660 });
    for (snapshot, expected) in [(&a, (1600, 900)), (&b, (1280, 720))] {
        assert_eq!(from_snapshot(0, snapshot.first().copied(), snapshot), expected.0);
        assert_eq!(from_snapshot(1, snapshot.first().copied(), snapshot), expected.1);
    }
    assert_eq!(from_snapshot(0, a.first().copied(), &[]), 0);
    assert_eq!(from_snapshot(1, None, &[]), 0);
}

#[test]
fn virtual_bounds_use_all_monitors_and_do_not_infer_primary_from_first() {
    let mut monitors = snapshot(Rect { x: -1200, y: -100, width: 1200, height: 900 },
        Rect { x: -1200, y: -70, width: 1200, height: 870 });
    let right = snapshot(Rect { x: 0, y: 0, width: 1600, height: 900 },
        Rect { x: 0, y: 30, width: 1600, height: 870 });
    monitors.extend_from_slice(&right);
    let primary = Some(monitors[1]);
    assert_eq!(from_snapshot(0, primary, &monitors), 1600);
    assert_eq!(from_snapshot(76, primary, &monitors) as i64, -1200);
    assert_eq!(from_snapshot(77, primary, &monitors) as i64, -100);
    assert_eq!(from_snapshot(78, primary, &monitors), 2800);
    assert_eq!(from_snapshot(79, primary, &monitors), 1000);
    assert_eq!(from_snapshot(80, primary, &monitors), 2);
    assert_eq!(from_snapshot(0, None, &monitors), 0);
    assert_eq!(from_snapshot(0x7fff00000001, primary, &monitors), 900);
}

#[test]
fn unavailable_or_unknown_metrics_are_zero_not_ntstatus_or_fixed_sizes() {
    for index in [0, 1, 76, 77, 78, 79, 80, u64::MAX] {
        assert_eq!(from_snapshot(index, None, &[]), 0);
    }
    let m = snapshot(Rect { x: 0, y: 0, width: 800, height: 600 },
        Rect { x: 0, y: 30, width: 800, height: 570 });
    assert_eq!(from_snapshot(u64::MAX, Some(m[0]), &m), 0);
}

#[test]
fn query_fetches_new_connection_snapshot_on_each_call_and_handles_disconnect() {
    let a = snapshot(Rect { x: 0, y: 0, width: 1600, height: 900 },
        Rect { x: 0, y: 30, width: 1600, height: 870 });
    let b = snapshot(Rect { x: 0, y: 0, width: 1280, height: 720 },
        Rect { x: 0, y: 60, width: 1280, height: 660 });
    let mut states = [Some(a), Some(b), None, Some(Vec::new())].into_iter();
    for expected in [1600, 1280, 0, 0] {
        assert_eq!(query(0, || states.next().unwrap()), expected);
    }
    assert_eq!(states.next(), None);
}

#[test]
fn primary_is_not_invented_when_protocol_does_not_identify_one() {
    let a = snapshot(Rect { x: 0, y: 0, width: 800, height: 600 },
        Rect { x: 0, y: 30, width: 800, height: 570 });
    assert_eq!(primary(&a), Some(a[0]));
    assert_eq!(primary(&[]), None);
    assert_eq!(primary(&[a[0], a[0]]), None);
}
