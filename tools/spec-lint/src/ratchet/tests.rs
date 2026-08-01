use super::*;

fn c(pairs: &[(&str, &str, usize)]) -> Counts {
    pairs.iter().map(|(u, r, n)| ((u.to_string(), r.to_string()), *n)).collect()
}

#[test]
fn roundtrip_render_load() {
    let dir = std::env::temp_dir().join(format!("spec-lint-ratchet-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let p = dir.join("baseline.tsv");
    let counts = c(&[("crates/shared/kalloc", "code/klog-ungated", 71), ("kernel", "code/safety-missing", 3)]);
    fs::write(&p, render(&counts)).unwrap();
    assert_eq!(load(&p), counts);
    assert_eq!(total(&counts), 74);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn load_ignores_comments_and_junk() {
    let dir = std::env::temp_dir().join(format!("spec-lint-ratchet-junk-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let p = dir.join("b.tsv");
    fs::write(&p, "# comment\n\nkernel\tcode/no-std\t2\nbroken line\nkernel\tcode/panic-fmt\tNaN\n").unwrap();
    assert_eq!(load(&p), c(&[("kernel", "code/no-std", 2)]));
    fs::remove_dir_all(&dir).ok();
}

// The ratchet's whole point: a new finding in a unit that already has many.
#[test]
fn growth_in_a_busy_unit_is_a_regression() {
    let base = c(&[("kernel", "code/safety-missing", 500)]);
    let cur = c(&[("kernel", "code/safety-missing", 501)]);
    assert_eq!(regressions(&cur, &base).len(), 1);
    assert_eq!(regressions(&base, &base).len(), 0);
}

#[test]
fn a_new_unit_with_findings_is_a_regression() {
    let base = c(&[("kernel", "code/no-std", 1)]);
    let cur = c(&[("kernel", "code/no-std", 1), ("crates/net", "code/no-std", 1)]);
    assert_eq!(regressions(&cur, &base).len(), 1);
}

#[test]
fn shrinking_is_not_a_regression() {
    let base = c(&[("kernel", "code/panic-fmt", 9)]);
    let cur = c(&[("kernel", "code/panic-fmt", 2)]);
    assert_eq!(regressions(&cur, &base).len(), 0);
}

// A fix in one rule must not pay for a new violation of another in the same unit.
#[test]
fn a_fix_elsewhere_does_not_offset_a_new_violation() {
    let base = c(&[("kernel", "code/panic-fmt", 9), ("kernel", "code/no-std", 0)]);
    let cur = c(&[("kernel", "code/panic-fmt", 2), ("kernel", "code/no-std", 1)]);
    assert_eq!(regressions(&cur, &base).len(), 1);
}

#[test]
fn update_never_raises_without_the_flag() {
    let dir = std::env::temp_dir().join(format!("spec-lint-ratchet-up-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let p = dir.join(BASELINE_REL);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(&p, render(&c(&[("kernel", "code/panic-fmt", 5)]))).unwrap();

    let grown = c(&[("kernel", "code/panic-fmt", 6)]);
    assert!(matches!(check(&dir, &grown, true, false), Outcome::Fail));
    assert_eq!(load(&p), c(&[("kernel", "code/panic-fmt", 5)]), "refused update must not touch the file");

    assert!(matches!(check(&dir, &grown, true, true), Outcome::Pass));
    assert_eq!(load(&p), c(&[("kernel", "code/panic-fmt", 6)]));

    let shrunk = c(&[("kernel", "code/panic-fmt", 1)]);
    assert!(matches!(check(&dir, &shrunk, true, false), Outcome::Pass));
    assert_eq!(load(&p), c(&[("kernel", "code/panic-fmt", 1)]));
    fs::remove_dir_all(&dir).ok();
}

// A burndown that does not tighten leaves its gains unlocked: the fixed
// findings could be reintroduced and the gate would still be green. So slack
// below the baseline is a failure with a fix-it command, not a note.
#[test]
fn slack_below_the_baseline_fails_until_it_is_tightened() {
    let dir = std::env::temp_dir().join(format!("spec-lint-ratchet-slack-{}", std::process::id()));
    let p = dir.join(BASELINE_REL);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(&p, render(&c(&[("kernel", "code/safety-missing", 500)]))).unwrap();

    let fixed_some = c(&[("kernel", "code/safety-missing", 380)]);
    assert!(matches!(check(&dir, &fixed_some, false, false), Outcome::Fail),
            "379 fixed-but-unlocked findings is exactly the state this catches");

    assert!(matches!(check(&dir, &fixed_some, true, false), Outcome::Pass));
    assert!(matches!(check(&dir, &fixed_some, false, false), Outcome::Pass),
            "green again once the tightened baseline is committed");
    assert_eq!(load(&p), fixed_some);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_key_that_reaches_zero_leaves_the_baseline() {
    let dir = std::env::temp_dir().join(format!("spec-lint-ratchet-zero-{}", std::process::id()));
    let p = dir.join(BASELINE_REL);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(&p, render(&c(&[("kernel", "code/no-std", 2), ("crates/net", "code/no-std", 1)]))).unwrap();
    let cur = c(&[("crates/net", "code/no-std", 1)]);
    assert!(matches!(check(&dir, &cur, true, false), Outcome::Pass));
    assert_eq!(load(&p), cur, "a fixed key is deleted, so it can never come back for free");
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn unit_is_the_owning_crate_directory() {
    let dir = std::env::temp_dir().join(format!("spec-lint-ratchet-unit-{}", std::process::id()));
    let krate = dir.join("crates/shared/kalloc");
    fs::create_dir_all(krate.join("src/holes")).unwrap();
    fs::write(krate.join("Cargo.toml"), "[package]\nname=\"kalloc\"\n").unwrap();
    // Splitting a file (docs/08§7) moves it WITHIN the crate: same unit, so the
    // baseline key survives the split that the 500-line cap forces.
    assert_eq!(unit_of(&dir, &krate.join("src/lib.rs")), "crates/shared/kalloc");
    assert_eq!(unit_of(&dir, &krate.join("src/holes/free_ip.rs")), "crates/shared/kalloc");
    // No Cargo.toml above it: falls back to the top-level directory.
    assert_eq!(unit_of(&dir, &dir.join("docs/16-vfs.md")), "docs");
    fs::remove_dir_all(&dir).ok();
}
