use super::*;
use super::super::*;

#[test]
fn exact_fresh_dc_is_required_before_consuming_session() {
    let mut manager = WindowManager::new();
    let id = manager.create(9, None, 0x1234).unwrap();
    let damage = Some(WindowRect { left: 1, top: 2, right: 8, bottom: 9 });
    manager.set_rect(id, WindowRect { left: 0, top: 0, right: 10, bottom: 10 }).unwrap();
    manager.invalidate(id, damage).unwrap();
    assert_eq!(manager.begin_paint(id), Ok(damage));
    assert_eq!(manager.bind_paint_dc(id, 0), Err(PaintSessionError::InvalidDc));
    assert_eq!(manager.bind_paint_dc(id, 41), Ok(PaintSession { damage, dc: 41, region: PaintRegion::from_rect(damage.unwrap()).unwrap(), erase: false, nonclient: false, delayed_erase: false }));
    assert_eq!(manager.validate_paint_session(id, 42), Err(PaintSessionError::DcMismatch));
    assert_eq!(manager.validate_paint_session(id, 41).unwrap().damage, damage);
    assert_eq!(manager.paint_session(id).unwrap().dc, 41);
    assert_eq!(manager.end_paint_session(id, 41).unwrap().damage, damage);
}

#[test]
fn bind_requires_existing_reservation_and_validation_keeps_it_active() {
    let mut manager = WindowManager::new();
    let id = manager.create(9, None, 0x1234).unwrap();
    assert_eq!(manager.bind_paint_dc(id, 41), Err(PaintSessionError::NotActive));
    manager.begin_paint(id).unwrap();
    manager.bind_paint_dc(id, 41).unwrap();
    assert_eq!(manager.validate_paint_session(id, 41), Ok(PaintSession { damage: None, dc: 41, region: PaintRegion::default(), erase: false, nonclient: false, delayed_erase: false }));
    assert_eq!(manager.paint_session(id), Ok(PaintSession { damage: None, dc: 41, region: PaintRegion::default(), erase: false, nonclient: false, delayed_erase: false }));
}

#[test]
fn destruction_consumes_only_the_selected_window_session() {
    let mut manager = WindowManager::new();
    let first = manager.create(9, None, 0x1234).unwrap();
    let second = manager.create(9, None, 0x1234).unwrap();
    manager.begin_paint(first).unwrap();
    manager.begin_paint(second).unwrap();
    manager.bind_paint_dc(first, 41).unwrap();
    manager.bind_paint_dc(second, 42).unwrap();
    assert_eq!(manager.remove_paint_session(first).unwrap().dc, 41);
    assert_eq!(manager.paint_session(second).unwrap().dc, 42);
}

#[test]
fn allocation_failure_does_not_bind_or_destroy_exact_region() {
    let region=PaintRegion::from_rect(WindowRect{left:1,top:2,right:3,bottom:4}).unwrap();
    let mut session=PaintSession{damage:region.bounds(),dc:0,region,erase:true,nonclient:true,delayed_erase:true};
    let before=session.try_copy().unwrap();
    assert_eq!(session.bind_with(41, |_|Err(WindowError::NoMemory)),Err(PaintSessionError::NoMemory));
    assert_eq!(session,before);
    assert_eq!(session.copy_with(|_|Err(WindowError::NoMemory)),Err(PaintSessionError::NoMemory));
    assert_eq!(session,before);
    assert_eq!(session.bind_with(0, |_|unreachable!("invalid DC must precede allocation")),Err(PaintSessionError::InvalidDc));
    assert_eq!(session.validate_dc(41),Err(PaintSessionError::Unbound));
    session.bind_with(41,PaintRegion::try_copy).unwrap();
    assert_eq!(session.bind_with(42, |_|unreachable!("active reservation must precede allocation")),Err(PaintSessionError::Active));
    assert_eq!(session.validate_dc(42),Err(PaintSessionError::DcMismatch));
}
