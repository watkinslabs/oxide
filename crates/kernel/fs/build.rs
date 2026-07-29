fn main() {
    // Shape tests path-include syscall sources, so rustc resolves their cfgs
    // in this package. These are expected foreign values, not selectable fs
    // features: registering them only with check-cfg keeps the lint precise
    // without letting `cargo --all-features` enable syscall trace code here.
    println!(
        "cargo::rustc-check-cfg=cfg(feature, values(\
         \"debug-atexit\", \"debug-session\", \"debug-stderr\", \
         \"debug-syscall\", \"debug-udevdb\"))"
    );
}
