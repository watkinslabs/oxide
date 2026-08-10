use alloc::string::String;
use alloc::vec::Vec;

use super::{virt_like, Fdt};
use crate::header::DtbError;
use crate::of_tree::{export_tree, OfEntry};
use crate::uapi::OF_ROOT_DIR;

const KSET: &str = "/sys/firmware/devicetree";

fn collect(blob: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    export_tree(blob, KSET, |e| out.push(String::from(e.path()))).expect("export");
    out
}

#[test]
fn root_node_directory_is_named_base() {
    let paths = collect(&virt_like());
    assert_eq!(paths[0], alloc::format!("{KSET}/{OF_ROOT_DIR}"));
}

#[test]
fn nodes_and_properties_land_under_their_parent_in_order() {
    let paths = collect(&virt_like());
    let base = alloc::format!("{KSET}/base");
    assert!(paths.contains(&alloc::format!("{base}/chosen/bootargs")));
    assert!(paths.contains(&alloc::format!("{base}/memory@40000000/reg")));
    assert!(paths.contains(&alloc::format!("{base}/cpus/cpu@1/reg")));
    assert!(paths.contains(&alloc::format!("{base}/pl011@9000000/compatible")));
    // A parent directory is always emitted before anything inside it, so a
    // consumer can register entries in the order they arrive.
    for (i, p) in paths.iter().enumerate() {
        if let Some((parent, _)) = p.rsplit_once('/') {
            if parent == KSET { continue; }
            assert!(paths[..i].iter().any(|q| q == parent), "{p} arrived before {parent}");
        }
    }
}

#[test]
fn property_bodies_are_the_raw_big_endian_bytes() {
    let blob = virt_like();
    let mut reg: Option<Vec<u8>> = None;
    export_tree(&blob, KSET, |e| {
        if let OfEntry::Prop { path, data, .. } = &e {
            if path.ends_with("/memory@40000000/reg") { reg = Some(Vec::from(*data)); }
        }
    }).expect("export");
    let mut want = Vec::new();
    want.extend_from_slice(&0x4000_0000u64.to_be_bytes());
    want.extend_from_slice(&0x8000_0000u64.to_be_bytes());
    assert_eq!(reg.as_deref(), Some(&want[..]));
}

#[test]
fn duplicate_sibling_names_are_disambiguated_with_a_hash_suffix() {
    // Two identically-named children plus a property colliding with a child
    // directory: nodes and properties share one namespace inside a directory.
    let blob = Fdt::new().begin("")
        .prop_u32("dup", 1)
        .begin("dup").end()
        .begin("kid").end()
        .begin("kid").end()
        .end().finish();
    let paths = collect(&blob);
    let base = alloc::format!("{KSET}/base");
    assert!(paths.contains(&alloc::format!("{base}/dup")));
    assert!(paths.contains(&alloc::format!("{base}/dup#1")));
    assert!(paths.contains(&alloc::format!("{base}/kid")));
    assert!(paths.contains(&alloc::format!("{base}/kid#1")));
    // Every emitted path is unique — the point of the suffix.
    let mut sorted = paths.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), paths.len(), "export must not emit a path twice");
}

#[test]
fn identical_names_under_different_parents_do_not_collide() {
    let blob = Fdt::new().begin("")
        .begin("a").prop_u32("reg", 0).end()
        .begin("b").prop_u32("reg", 0).end()
        .end().finish();
    let paths = collect(&blob);
    let base = alloc::format!("{KSET}/base");
    assert!(paths.contains(&alloc::format!("{base}/a/reg")));
    assert!(paths.contains(&alloc::format!("{base}/b/reg")));
    assert!(!paths.iter().any(|p| p.contains('#')), "different parents are different namespaces");
}

#[test]
fn security_prefixed_properties_are_marked_secure() {
    let blob = Fdt::new().begin("")
        .prop("security-key", b"hunter2")
        .prop("compatible", b"acme\0")
        .end().finish();
    let mut secure = Vec::new();
    let mut plain = Vec::new();
    export_tree(&blob, KSET, |e| {
        if let OfEntry::Prop { path, secure: s, .. } = &e {
            if *s { secure.push(String::from(path.as_str())); } else { plain.push(String::from(path.as_str())); }
        }
    }).expect("export");
    assert_eq!(secure.len(), 1);
    assert!(secure[0].ends_with("/security-key"));
    assert_eq!(plain.len(), 1);
    assert!(plain[0].ends_with("/compatible"));
}

#[test]
fn a_name_that_would_escape_its_directory_is_rejected() {
    for bad in ["../etc", "a/b", ".", ".."] {
        let blob = Fdt::new().begin("").begin(bad).end().end().finish();
        assert_eq!(export_tree(&blob, KSET, |_| {}).err(), Some(DtbError::Inval), "{bad}");
    }
}

#[test]
fn a_non_utf8_property_name_is_rejected() {
    let mut blob = Fdt::new().begin("").prop("ab", b"\0").end().finish();
    // Corrupt the strings-block byte that spells the property name.
    let n = blob.len();
    blob[n - 3] = 0xff;
    assert_eq!(export_tree(&blob, KSET, |_| {}).err(), Some(DtbError::Inval));
}

#[test]
fn a_malformed_blob_is_an_error_not_a_partial_tree() {
    assert!(export_tree(b"not an fdt at all, really not", KSET, |_| {}).is_err());
}

/// The whole point of the export: every property in the blob reaches a file.
/// A walker that dropped a subtree would still produce a plausible-looking
/// tree, so count against the walk itself.
#[test]
fn every_node_and_property_in_the_blob_is_exported() {
    use crate::walk::{walk, Event, Flow};
    let blob = virt_like();
    let (mut nodes, mut props) = (0usize, 0usize);
    walk(&blob, |ev| {
        match ev { Event::BeginNode { .. } => nodes += 1, Event::Prop { .. } => props += 1, _ => {} }
        Flow::Continue
    }).expect("walk");
    let (mut dirs, mut files) = (0usize, 0usize);
    export_tree(&blob, KSET, |e| match e {
        OfEntry::Dir { .. } => dirs += 1,
        OfEntry::Prop { .. } => files += 1,
    }).expect("export");
    assert_eq!((dirs, files), (nodes, props));
}
