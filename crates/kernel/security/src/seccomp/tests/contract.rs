#[test]
fn the_security_contract_describes_the_live_seccomp_filter_surface() {
    let spec = include_str!("../../../../../../docs/27-security.md");
    assert!(spec.lines().any(|line| {
        line == "pub fn seccomp_set_filter(prog:&[SockFilter]) -> KR<()>;"
    }));
    assert!(!spec.contains("phase 23"), "live BPF must not be documented as deferred");
    assert!(spec.contains("Seccomp classic-BPF filter eval"));
}
