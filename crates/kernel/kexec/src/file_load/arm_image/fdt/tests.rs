// Tree provenance: a synthetic tree that exercises every token, and real
// vendor device trees from the image tree's aarch64 module set.

use super::*;
use alloc::vec;

fn sample() -> Fdt {
    let mut root = Node::new(b"");
    root.props.push(Prop { name: b"#address-cells".to_vec(), val: 2u32.to_be_bytes().to_vec() });
    root.props.push(Prop { name: b"model".to_vec(), val: b"oxide,test\0".to_vec() });

    let mut chosen = Node::new(b"chosen");
    chosen.props.push(Prop { name: b"bootargs".to_vec(), val: b"console=ttyAMA0\0".to_vec() });
    // A zero-length property: the empty-marker form, and the one a naive
    // emitter turns into a property with a stray value.
    chosen.props.push(Prop { name: b"empty-marker".to_vec(), val: Vec::new() });

    let mut mem = Node::new(b"memory@40000000");
    mem.props.push(Prop { name: b"device_type".to_vec(), val: b"memory\0".to_vec() });
    // A value whose length is not a multiple of four, so the emitter's padding
    // is exercised rather than accidentally satisfied.
    mem.props.push(Prop { name: b"odd".to_vec(), val: vec![1, 2, 3, 4, 5] });
    let mut sub = Node::new(b"sub");
    sub.props.push(Prop { name: b"model".to_vec(), val: b"shared-name\0".to_vec() });
    mem.children.push(sub);

    root.children.push(chosen);
    root.children.push(mem);
    Fdt { boot_cpuid_phys: 3, rsv: vec![(0x4000_0000, 0x10_0000), (0x8000_0000, 0x2000)], root }
}

#[test]
fn a_tree_survives_a_flatten_and_a_parse_unchanged() {
    let t = sample();
    let blob = t.to_blob();
    assert_eq!(parse(&blob).expect("our own output parses"), t);
}

#[test]
fn the_emitted_header_carries_the_offsets_the_blob_actually_uses() {
    // The failure this catches: a size or offset field computed from the
    // wrong block. Nothing in a self-round-trip notices, because the parser
    // makes the same mistake in reverse.
    let blob = sample().to_blob();
    let g = |at: usize| u32::from_be_bytes([blob[at], blob[at + 1], blob[at + 2], blob[at + 3]]);
    assert_eq!(g(OFF_MAGIC), FDT_MAGIC);
    assert_eq!(g(OFF_TOTALSIZE) as usize, blob.len());
    assert_eq!(g(OFF_VERSION), FDT_VERSION);
    assert_eq!(g(OFF_LAST_COMP_VERSION), FDT_LAST_COMP_VERSION);
    assert_eq!(g(OFF_BOOT_CPUID_PHYS), 3);
    let off_struct = g(OFF_DT_STRUCT) as usize;
    let size_struct = g(OFF_SIZE_DT_STRUCT) as usize;
    let off_strings = g(OFF_DT_STRINGS) as usize;
    let size_strings = g(OFF_SIZE_DT_STRINGS) as usize;
    assert_eq!(off_struct % FDT_TOKEN_ALIGN, 0);
    assert_eq!(g(OFF_MEM_RSVMAP) as usize % FDT_RSV_ALIGN, 0);
    assert_eq!(off_struct + size_struct, off_strings);
    assert_eq!(off_strings + size_strings, blob.len());
    // The struct block ends with the end token and nothing after it.
    let last = off_struct + size_struct - 4;
    assert_eq!(u32::from_be_bytes([blob[last], blob[last + 1], blob[last + 2], blob[last + 3]]),
               FDT_END);
    // The string table is a run of NUL-terminated names.
    assert_eq!(blob[blob.len() - 1], 0);
}

#[test]
fn a_name_used_by_two_nodes_is_stored_once_and_both_offsets_resolve() {
    // Interning is where a string table goes wrong: two properties named
    // `model` in different nodes must resolve to the same bytes, and a table
    // that appended a second copy still parses — so only the SIZE reveals it.
    let blob = sample().to_blob();
    let t = parse(&blob).expect("parses");
    assert_eq!(t.root.prop(b"model"), Some(&b"oxide,test\0"[..]));
    let sub = t.node(b"/memory@40000000/sub").expect("nested node");
    assert_eq!(sub.prop(b"model"), Some(&b"shared-name\0"[..]));
    let off_strings = u32::from_be_bytes([blob[OFF_DT_STRINGS], blob[OFF_DT_STRINGS + 1],
                                          blob[OFF_DT_STRINGS + 2], blob[OFF_DT_STRINGS + 3]])
                      as usize;
    let size = u32::from_be_bytes([blob[OFF_SIZE_DT_STRINGS], blob[OFF_SIZE_DT_STRINGS + 1],
                                   blob[OFF_SIZE_DT_STRINGS + 2], blob[OFF_SIZE_DT_STRINGS + 3]])
               as usize;
    let table = &blob[off_strings..off_strings + size];
    let copies = table.split(|&c| c == 0).filter(|n| *n == b"model").count();
    assert_eq!(copies, 1, "the string table holds `model` twice");
}

#[test]
fn the_reservation_block_keeps_every_entry_and_is_terminated() {
    let t = sample();
    let blob = t.to_blob();
    let back = parse(&blob).expect("parses");
    assert_eq!(back.rsv, t.rsv);
    // Only the ALL-ZERO entry terminates. An entry with a zero size, or one
    // at address zero, is a real reservation; a parser that stops on either
    // field alone silently truncates the block and hands the new kernel
    // memory somebody else owns.
    let mut odd = sample();
    odd.rsv = vec![(0x1000, 0), (0, 0x1000), (0x2000, 0x1000)];
    assert_eq!(parse(&odd.to_blob()).expect("parses").rsv, odd.rsv);
    // And an empty block round-trips as empty.
    let mut none = sample();
    none.rsv = Vec::new();
    assert!(parse(&none.to_blob()).expect("parses").rsv.is_empty());
}

#[test]
fn a_blob_that_is_not_a_tree_is_refused_rather_than_half_decoded() {
    let good = sample().to_blob();
    assert_eq!(parse(&[]).err(), Some(Error::Inval));
    assert_eq!(parse(&good[..FDT_HEADER_SIZE - 1]).err(), Some(Error::Inval));
    let mut bad = good.clone();
    bad[0] ^= 0xff;
    assert_eq!(parse(&bad).err(), Some(Error::Inval));
    // A totalsize larger than the buffer describes bytes that are not there.
    let mut short = good.clone();
    let big = (good.len() as u32 + 4096).to_be_bytes();
    short[OFF_TOTALSIZE..OFF_TOTALSIZE + 4].copy_from_slice(&big);
    assert_eq!(parse(&short).err(), Some(Error::Inval));
    // A compatibility version from the future.
    let mut future = good.clone();
    future[OFF_LAST_COMP_VERSION..OFF_LAST_COMP_VERSION + 4]
        .copy_from_slice(&(FDT_LAST_COMP_VERSION + 1).to_be_bytes());
    assert_eq!(parse(&future).err(), Some(Error::Inval));
}

#[test]
fn path_lookup_finds_nested_nodes_and_creates_missing_ones() {
    let mut t = sample();
    assert!(t.node(b"/chosen").is_some());
    assert!(t.node(b"/memory@40000000/sub").is_some());
    assert!(t.node(b"/nope").is_none());
    assert!(t.node(b"/").is_some());
    t.node_or_add(b"/chosen").set_prop_u64(b"x", 7);
    assert_eq!(t.node(b"/chosen").unwrap().prop(b"x"), Some(&7u64.to_be_bytes()[..]));
    // A path whose node does not exist is created, not silently written into
    // the root — the reference adds `/chosen` when a tree has none.
    t.node_or_add(b"/fresh").set_prop_empty(b"m");
    assert!(t.node(b"/fresh").unwrap().prop(b"m").is_some());
    assert!(t.root.prop(b"m").is_none());
}

#[test]
fn deleting_a_property_reports_whether_one_was_there() {
    let mut t = sample();
    let c = t.node_or_add(b"/chosen");
    assert!(c.del_prop(b"bootargs"));
    assert!(!c.del_prop(b"bootargs"));
    assert!(c.prop(b"bootargs").is_none());
}

#[test]
fn a_reservation_is_dropped_only_on_an_exact_match() {
    let mut t = sample();
    assert!(!t.del_mem_rsv(0x4000_0000, 0x10_0001));
    assert!(!t.del_mem_rsv(0x4000_0001, 0x10_0000));
    assert!(t.del_mem_rsv(0x4000_0000, 0x10_0000));
    assert_eq!(t.rsv.len(), 1);
}

// ---------------------------------------------------------------------------
// Real vendor device trees.

const DTB_DIR: &str =
    "/home/nd/oxide/images/build/lite-aarch64-root/lib/modules/6.19.14-108.fc42.aarch64/dtb";

/// Up to `n` real `.dtb` files, in a stable order.
fn vendor_dtbs(n: usize) -> Vec<(std::string::String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut dirs = vec![std::path::PathBuf::from(DTB_DIR)];
    while let Some(d) = dirs.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        let mut entries: Vec<_> = rd.filter_map(|e| e.ok()).map(|e| e.path()).collect();
        entries.sort();
        for p in entries {
            if out.len() >= n { return out; }
            if p.is_dir() { dirs.push(p); continue; }
            if p.extension().and_then(|e| e.to_str()) != Some("dtb") { continue; }
            if let Ok(b) = std::fs::read(&p) {
                out.push((alloc::format!("{}", p.display()), b));
            }
        }
    }
    out
}

#[test]
fn real_vendor_device_trees_survive_a_decode_and_a_re_flatten() {
    let dtbs = vendor_dtbs(24);
    if dtbs.is_empty() {
        std::eprintln!("skipped: no vendor .dtb under {DTB_DIR}");
        return;
    }
    for (name, blob) in &dtbs {
        let t = parse(blob).unwrap_or_else(|e| std::panic!("{name}: {e:?}"));
        let again = t.to_blob();
        let back = parse(&again).unwrap_or_else(|e| std::panic!("{name} re-parse: {e:?}"));
        // Every node, every property, every value, every reservation, and the
        // boot CPU — the whole tree, not merely a blob that parses.
        assert_eq!(back, t, "{name} changed across a re-flatten");
        // A real tree has a root with children and at least one property.
        assert!(!t.root.children.is_empty(), "{name} has an empty root");
    }
    std::eprintln!("re-flattened {} real device trees", dtbs.len());
}

#[test]
fn a_real_vendor_tree_can_be_edited_and_still_reads_back() {
    let dtbs = vendor_dtbs(1);
    let Some((name, blob)) = dtbs.first() else {
        std::eprintln!("skipped: no vendor .dtb under {DTB_DIR}");
        return;
    };
    let mut t = parse(blob).expect("a vendor tree parses");
    t.node_or_add(b"/chosen").set_prop_string(b"bootargs", b"root=/dev/vda1 ro");
    t.add_mem_rsv(0x8000_0000, 0x10_0000);
    let back = parse(&t.to_blob()).unwrap_or_else(|e| std::panic!("{name}: {e:?}"));
    assert_eq!(back.node(b"/chosen").and_then(|c| c.prop(b"bootargs")),
               Some(&b"root=/dev/vda1 ro\0"[..]));
    assert!(back.rsv.contains(&(0x8000_0000, 0x10_0000)));
}
