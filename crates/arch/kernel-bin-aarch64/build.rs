// build.rs — wires the aarch64 linker script into the binary stage.

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    if !target.contains("oxide-kernel") { return; }

    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let script = format!("{manifest}/../../../link/aarch64-kernel.ld");
    println!("cargo:rustc-link-arg=-T{script}");
    println!("cargo:rustc-link-arg=-no-pie");
    println!("cargo:rerun-if-changed={script}");
}
