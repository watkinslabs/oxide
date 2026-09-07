use super::*;

#[test]
fn a_job_call_reports_the_driver_result_only_for_a_resolvable_context() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(10, 10).unwrap();
    assert_eq!(gdi.print_job_result(dc, JOB_RESULT), JOB_RESULT);
    assert_eq!(gdi.print_job_result(dc, START_PAGE_RESULT), START_PAGE_RESULT);
    assert_eq!(gdi.print_job_result(99, START_PAGE_RESULT), SP_ERROR);
}

#[test]
fn the_null_driver_starts_pages_but_reports_no_job_identifier() {
    assert_eq!(START_PAGE_RESULT, 1);
    assert_eq!(JOB_RESULT, 0);
    assert_eq!(SP_ERROR, -1);
    assert_eq!(INIT_SPOOL_RESULT, 1);
    assert_eq!(SPOOL_MESSAGE_RESULT, 0);
}

#[test]
fn a_device_escape_is_understood_by_no_driver_whatever_the_context() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(10, 10).unwrap();
    assert_eq!(gdi.ext_escape(dc), EXT_ESCAPE_RESULT);
    assert_eq!(gdi.ext_escape(99), EXT_ESCAPE_RESULT);
}

#[test]
fn a_device_mode_reset_is_refused_by_every_driver_and_leaves_the_context_alone() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(10, 10).unwrap();
    let before = gdi.dc_attr(dc).unwrap();
    assert_eq!(gdi.reset_device_mode(dc), Ok(false));
    assert_eq!(gdi.dc_attr(dc).unwrap(), before);
    assert_eq!(gdi.reset_device_mode(99), Err(GdiError::NoSuchObject));
}
