//! binfmt_misc inode-number stability.
//!
//! Ungated on purpose: `binfmt_misc.rs` carries no target gate, so these run on
//! the host. A rule's `d_ino` must be the same number in every `getdents` page
//! and in every `stat`, or a caller correlating entries across pages reads one
//! rule as two files.

use super::*;

/// A registration line: `:name:M::magic::interpreter:flags`. # C: O(len)
fn rule_line(name: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(b':');
    v.extend_from_slice(name.as_bytes());
    v.extend_from_slice(b":M::\x7fELF::/usr/bin/interp:OC\n");
    v
}

/// Collects everything `iterate` emits. # C: O(N)
struct Collect { seen: Vec<(String, u64)> }
impl vfs::DirEmit for Collect {
    fn emit(&mut self, name: &str, ino: u64, _t: FileType, next_pos: u64) -> bool {
        self.seen.push((name.to_string(), ino));
        let _ = next_pos;
        true
    }
}

/// Root inode over a fresh state with `names` registered. # C: O(N)
fn root_with(names: &[&str]) -> (Arc<State>, InodeRef) {
    let state = State::new();
    for n in names { state.register(&rule_line(n)).expect("register"); }
    let root = make_binfmt_root(Arc::clone(&state), NEXT_INO.alloc());
    (state, root)
}

/// Every `(name, d_ino)` the directory emits from cookie 0. # C: O(N log N)
fn readdir(root: &InodeRef) -> Vec<(String, u64)> {
    let mut c = Collect { seen: Vec::new() };
    let mut ctx = DirContext::new(0, &mut c);
    BinfmtRootFileOps.iterate(root, &mut ctx).expect("iterate");
    c.seen
}

#[test]
fn repeated_lookup_of_a_rule_returns_one_ino() {
    let (_s, root) = root_with(&["qemu-arm"]);
    let a = root.lookup("qemu-arm").expect("first lookup").ino();
    let b = root.lookup("qemu-arm").expect("second lookup").ino();
    assert_eq!(a, b);
}

#[test]
fn repeated_lookup_of_control_files_returns_one_ino() {
    let (_s, root) = root_with(&[]);
    for n in [BINFMT_STATUS, BINFMT_REGISTER] {
        let a = root.lookup(n).expect("first lookup").ino();
        let b = root.lookup(n).expect("second lookup").ino();
        assert_eq!(a, b, "{n} minted a fresh ino");
    }
}

#[test]
fn readdir_d_ino_matches_lookup_ino() {
    let (_s, root) = root_with(&["qemu-arm", "jar"]);
    for (name, d_ino) in readdir(&root) {
        let want = root.lookup(&name).expect("lookup emitted name").ino();
        assert_eq!(d_ino, want, "{name}: d_ino disagrees with stat");
    }
}

#[test]
fn readdir_repeats_the_same_ino_across_passes() {
    let (_s, root) = root_with(&["qemu-arm", "jar", "python3"]);
    assert_eq!(readdir(&root), readdir(&root));
}

#[test]
fn distinct_rules_get_distinct_inos() {
    let (_s, root) = root_with(&["qemu-arm", "jar", "python3"]);
    let mut inos: Vec<u64> = readdir(&root).into_iter().map(|(_, i)| i).collect();
    assert_eq!(inos.len(), 5);
    inos.sort_unstable();
    let n = inos.len();
    inos.dedup();
    assert_eq!(inos.len(), n, "two binfmt_misc entries share an ino");
}

#[test]
fn every_ino_stays_inside_the_reserved_region() {
    let (_s, root) = root_with(&["qemu-arm", "jar"]);
    for (name, ino) in readdir(&root) {
        assert!(vfs::pseudo_ino::BINFMT_MISC.contains(ino), "{name} left the region");
    }
}

#[test]
fn re_registering_a_name_is_eexist_and_keeps_the_ino() {
    let (state, root) = root_with(&["qemu-arm"]);
    let before = root.lookup("qemu-arm").expect("lookup").ino();
    assert_eq!(state.register(&rule_line("qemu-arm")), Err(VfsError::Eexist));
    assert_eq!(root.lookup("qemu-arm").expect("lookup").ino(), before);
}

#[test]
fn unregistering_drops_the_rule_from_readdir() {
    let (state, root) = root_with(&["qemu-arm", "jar"]);
    state.rules.lock().remove("jar");
    let names: Vec<String> = readdir(&root).into_iter().map(|(n, _)| n).collect();
    assert!(!names.iter().any(|n| n == "jar"));
    assert!(names.iter().any(|n| n == "qemu-arm"));
}
