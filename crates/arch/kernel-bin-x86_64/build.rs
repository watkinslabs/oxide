// build.rs — wires the x86_64 linker script into the binary stage.
// Only emits the link-arg for the kernel target; host builds (e.g.
// `cargo check` on the workspace) skip the linker script entirely.

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    if !target.contains("oxide-kernel") { return; }

    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let script = format!("{manifest}/../../../link/x86_64-kernel.ld");
    println!("cargo:rustc-link-arg=-T{script}");
    println!("cargo:rustc-link-arg=-no-pie");
    println!("cargo:rerun-if-changed={script}");
}
