//! Explicit build-boundary gate; no rootfs or guest execution.
#[test]
#[ignore = "builds the real compositor; run explicitly with a private CARGO_TARGET_DIR"]
fn actual_probe_build_returns_cargo_selected_artifact() {
    struct Restore(std::path::PathBuf);
    impl Drop for Restore { fn drop(&mut self) { std::env::set_current_dir(&self.0).unwrap(); } }
    let _restore = Restore(std::env::current_dir().unwrap());
    std::env::set_current_dir(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
    assert!(std::env::var_os("CARGO_TARGET_DIR").is_some(), "private build target required");
    let expected = super::target_dir(super::super::PROBE_WORKSPACE).unwrap()
        .join("x86_64-unknown-linux-gnu/release/windows-compositor");
    let actual = super::super::probe_cargo_bin("x86_64", "windows-compositor", "windows-compositor").unwrap();
    assert_eq!(actual, expected, "staging must select this build, not the default-cache artifact");
    assert!(actual.is_file());
}
