#[test]
fn getdents_detail_trace_is_feature_gated_and_base_uses_task_state() {
    let source = include_str!("217_getdents64.rs");
    let validation = source.find("validate_user_buf_writable").unwrap();
    let stage = source.find("GETDENTS_STAGE_VALIDATED").unwrap();
    let enter = source.find("GETDENTS_STAGE_READDIR_ENTER").unwrap();
    let exit = source.find("GETDENTS_STAGE_READDIR_EXIT").unwrap();
    let done = source.find("GETDENTS_STAGE_COPYOUT_DONE").unwrap();
    assert!(validation < stage);
    assert!(stage < enter && enter < exit && exit < done);
    assert!(source.contains("#[cfg(feature = \"debug-getdents-detail\")]\nfn trace_getdents"));
    assert!(source.contains("sched::diag::getdents_begin"));
    assert!(source.contains("sched::diag::getdents_clear(cur);"));
    for field in ["tid=", "fd=", "mnt=", "ino=", "path=", "fpos=", "count=", "result="] {
        assert!(source.contains(field));
    }
}
