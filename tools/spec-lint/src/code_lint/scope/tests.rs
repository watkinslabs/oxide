use super::*;

fn mask(src: &str) -> Vec<bool> {
    let lines: Vec<&str> = src.lines().collect();
    cfg_test_mask(&lines)
}

#[test]
fn a_multi_line_cfg_test_module_is_covered_end_to_end() {
    let src = "\
fn kernel_fn() {}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn t() { panic!(\"expected {x}\"); }
}
fn after() {}";
    let m = mask(src);
    assert!(!m[0], "kernel code before the block");
    assert!(m[1] && m[2] && m[5] && m[6], "attribute through closing brace");
    assert!(!m[7], "kernel code after the block");
}

#[test]
fn an_inner_cfg_test_covers_the_whole_file() {
    assert!(mask("#![cfg(test)]\nfn a() {}\nfn b() {}").iter().all(|b| *b));
}

#[test]
fn a_file_with_no_test_cfg_is_all_kernel() {
    assert!(mask("fn a() {}\nfn b() {}").iter().all(|b| !*b));
}

#[test]
fn cfg_test_on_a_semicolon_item_covers_only_that_item() {
    let m = mask("#[cfg(test)]\nuse std::vec::Vec;\nfn kernel() {}");
    assert!(m[0] && m[1]);
    assert!(!m[2]);
}

#[test]
fn not_oxide_kernel_is_off_kernel_too() {
    let lines = ["#[cfg(not(target_os = \"oxide-kernel\"))]", "extern crate std;", "fn kernel() {}"];
    let m = non_kernel_mask(&lines);
    assert!(m[0] && m[1]);
    assert!(!m[2], "the gate covers one item, not the rest of the file");
}

// `crates/kernel/syscalls/src/054_setsockopt/main.rs` is a syscall SLOT module,
// not a crate root; demanding `#![no_std]` from it was a false positive.
#[test]
fn crate_root_requires_src_and_a_manifest() {
    let dir = std::env::temp_dir().join(format!("spec-lint-scope-{}", std::process::id()));
    let krate = dir.join("crates/kernel/syscalls");
    std::fs::create_dir_all(krate.join("src/054_setsockopt")).unwrap();
    std::fs::write(krate.join("Cargo.toml"), "[package]\nname=\"syscalls\"\n").unwrap();
    assert!(is_crate_root(&krate.join("src/lib.rs")));
    assert!(!is_crate_root(&krate.join("src/054_setsockopt/main.rs")));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn child_modules_of_a_named_file_live_in_its_own_directory() {
    let p = PathBuf::from("crates/kernel/sysfs/src/bus.rs");
    assert_eq!(child_mod_dir(&p).unwrap(), PathBuf::from("crates/kernel/sysfs/src/bus"));
    let l = PathBuf::from("crates/kernel/sysfs/src/lib.rs");
    assert_eq!(child_mod_dir(&l).unwrap(), PathBuf::from("crates/kernel/sysfs/src"));
}

#[test]
fn a_crate_only_ever_dev_depended_on_is_dev_only() {
    let dir = std::env::temp_dir().join(format!("spec-lint-devonly-{}", std::process::id()));
    for (p, toml) in [
        ("conformance", "[package]\nname = \"conformance\"\n"),
        ("vfs", "[package]\nname = \"vfs\"\n\n[dependencies]\nsched = { path = \"../sched\" }\n\n[dev-dependencies]\nconformance = { path = \"../conformance\" }\n"),
        ("sched", "[package]\nname = \"sched\"\n"),
    ] {
        let d = dir.join("crates").join(p);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("Cargo.toml"), toml).unwrap();
    }
    let out = dev_only_crate_dirs(&dir);
    assert!(out.contains(&dir.join("crates/conformance")));
    assert!(!out.contains(&dir.join("crates/sched")), "a runtime dependency is never dev-only");
    assert!(!out.contains(&dir.join("crates/vfs")));
    std::fs::remove_dir_all(&dir).ok();
}
