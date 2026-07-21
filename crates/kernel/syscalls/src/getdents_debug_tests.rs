#[test]
fn getdents_trace_is_feature_gated_and_staged_after_range_validation() {
    let source = include_str!("217_getdents64.rs");
    let validation = source.find("validate_user_buf_writable").unwrap();
    let stage = source.find("GETDENTS_STAGE_VALIDATED").unwrap();
    let enter = source.find("GETDENTS_STAGE_READDIR_ENTER").unwrap();
    let exit = source.find("GETDENTS_STAGE_READDIR_EXIT").unwrap();
    let done = source.find("GETDENTS_STAGE_COPYOUT_DONE").unwrap();
    assert!(validation < stage);
    assert!(stage < enter && enter < exit && exit < done);
    assert!(source.contains("#[cfg(feature = \"debug-getdents\")]\nfn trace_getdents"));
    for field in ["tid=", "fd=", "mnt=", "ino=", "path=", "fpos=", "count=", "result="] {
        assert!(source.contains(field));
    }
}
