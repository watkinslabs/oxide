use super::*;
use crate::name::FileName;
use crate::record::Reference;
use crate::upcase::{self};
use alloc::vec::Vec;
use syscall::errno::Errno;

fn fname(name: &str) -> FileName {
    FileName {
        parent: Reference { number: 5, sequence: 1 },
        create_time: 0, modify_time: 0, change_time: 0, access_time: 0,
        alloc_size: 0, data_size: 0,
        attributes: FILE_ATTRIBUTE_ARCHIVE,
        namespace: FILE_NAME_POSIX,
        units: name.encode_utf16().collect(),
    }
}

/// A node holding `names`, each pointing at a record of its own, optionally
/// with a child pointer on the end entry.
fn node(names: &[&str], children: &[Option<u64>], last_child: Option<u64>) -> Vec<u8> {
    let mut entries: Vec<Vec<u8>> = Vec::new();
    for (i, name) in names.iter().enumerate() {
        let key = crate::name::write_filename(&fname(name));
        let child = children.get(i).copied().flatten();
        entries.push(entry::build(&Reference { number: 30 + i as u64, sequence: 1 }, &key, child));
    }
    let last = entry::build_last(last_child);
    let body: usize = entries.iter().map(|e| e.len()).sum::<usize>() + last.len();
    let flags = if children.iter().any(|c| c.is_some()) || last_child.is_some() {
        INDEX_HDR_HAS_SUBNODES
    } else { 0 };
    crate::volume::dirops::insert::rebuild_node(&entries, &last, 0,
                                                (SIZEOF_IHDR + body) as u32, flags).unwrap()
}

/// A tree of nodes in memory, for the walk to descend.
struct Tree {
    root: Vec<u8>,
    blocks: alloc::vec::Vec<(u64, Vec<u8>)>,
}

impl walk::NodeSource for Tree {
    fn root(&self) -> Result<(Vec<u8>, usize, NodeHeader), Errno> {
        let h = node_header(&self.root, 0).ok_or(Errno::Eio)?;
        Ok((self.root.clone(), 0, h))
    }
    fn block(&self, vbn: u64) -> Result<(Vec<u8>, usize, NodeHeader), Errno> {
        let (_, bytes) = self.blocks.iter().find(|(n, _)| *n == vbn).ok_or(Errno::Eio)?;
        let h = node_header(bytes, 0).ok_or(Errno::Eio)?;
        Ok((bytes.clone(), 0, h))
    }
    fn indexed_type(&self) -> u32 { ATTR_NAME }
}

#[test]
fn a_nodes_entries_decode_in_order() {
    let bytes = node(&["alpha", "beta", "gamma"], &[], None);
    let header = node_header(&bytes, 0).unwrap();
    let entries = entry::entries(&bytes, 0, &header, ATTR_NAME);
    let names: Vec<_> = entries.iter().filter_map(|e| e.name()).map(|f| f.name()).collect();
    assert_eq!(names, alloc::vec!["alpha", "beta", "gamma"]);
    assert!(entries.last().unwrap().is_last());
}

#[test]
fn the_child_pointer_is_the_entrys_last_eight_bytes() {
    // Not a field at a fixed offset: reading it there gives a key's
    // characters as a block number.
    let key = crate::name::write_filename(&fname("child"));
    let built = entry::build(&Reference { number: 9, sequence: 1 }, &key, Some(0x1234));
    let parsed = entry::parse(&built, 0, ATTR_NAME).unwrap();
    assert_eq!(parsed.child, Some(0x1234));
    assert!(parsed.has_child());
    assert_eq!(parsed.name().unwrap().name(), "child");
    let at = usize::from(parsed.size) - 8;
    assert_eq!(&built[at..at + 8], &0x1234u64.to_le_bytes());
}

#[test]
fn an_entry_without_a_child_reads_none() {
    let key = crate::name::write_filename(&fname("leaf"));
    let built = entry::build(&Reference { number: 9, sequence: 1 }, &key, None);
    assert_eq!(entry::parse(&built, 0, ATTR_NAME).unwrap().child, None);
}

#[test]
fn the_end_entry_has_no_key() {
    let built = entry::build_last(None);
    let parsed = entry::parse(&built, 0, ATTR_NAME).unwrap();
    assert!(parsed.is_last());
    assert!(parsed.name().is_none());
}

#[test]
fn a_walk_of_the_whole_tree_visits_a_childs_keys_before_its_parents() {
    // A child holds the keys that sort BEFORE its parent entry; emitting the
    // parent first lists a directory out of order.
    let tree = Tree {
        root: node(&["mango"], &[Some(1)], Some(2)),
        blocks: alloc::vec![
            (1, node(&["apple", "banana"], &[], None)),
            (2, node(&["pear", "quince"], &[], None)),
        ],
    };
    let names: Vec<_> = walk::walk_all(&tree).unwrap().iter()
        .filter_map(|e| e.name()).map(|f| f.name()).collect();
    assert_eq!(names, alloc::vec!["apple", "banana", "mango", "pear", "quince"]);
}

#[test]
fn a_descent_finds_a_name_in_a_child_the_root_does_not_hold() {
    // Scanning the root alone finds the handful of names that fit there.
    let tree = Tree {
        root: node(&["mango"], &[Some(1)], Some(2)),
        blocks: alloc::vec![
            (1, node(&["apple", "banana"], &[], None)),
            (2, node(&["pear", "quince"], &[], None)),
        ],
    };
    let t = upcase::builtin();
    for name in ["apple", "banana", "mango", "pear", "quince"] {
        let units: Vec<u16> = name.encode_utf16().collect();
        let hit = walk::find(&tree, &units, &t).unwrap();
        assert_eq!(hit.expect(name).name().unwrap().name(), name);
    }
    let missing: Vec<u16> = "zebra".encode_utf16().collect();
    assert!(walk::find(&tree, &missing, &t).unwrap().is_none());
}

#[test]
fn a_descent_is_case_insensitive_through_the_table() {
    let tree = Tree { root: node(&["Readme.TXT"], &[], None), blocks: alloc::vec![] };
    let t = upcase::builtin();
    let units: Vec<u16> = "readme.txt".encode_utf16().collect();
    assert!(walk::find(&tree, &units, &t).unwrap().is_some());
}

#[test]
fn a_cycle_in_the_child_pointers_is_reported_rather_than_followed() {
    let tree = Tree {
        root: node(&[], &[], Some(1)),
        blocks: alloc::vec![(1, node(&[], &[], Some(1)))],
    };
    let t = upcase::builtin();
    let units: Vec<u16> = "x".encode_utf16().collect();
    assert!(walk::find(&tree, &units, &t).is_err());
    assert!(walk::walk_all(&tree).is_err());
}

#[test]
fn an_insertion_position_keeps_the_node_ordered() {
    let bytes = node(&["banana", "mango"], &[], None);
    let header = node_header(&bytes, 0).unwrap();
    let entries = entry::entries(&bytes, 0, &header, ATTR_NAME);
    let t = upcase::builtin();
    let at = |n: &str| walk::insert_position(&entries, &n.encode_utf16().collect::<Vec<u16>>(), &t);
    assert_eq!(at("apple"), 0);
    assert_eq!(at("cherry"), 1);
    assert_eq!(at("zebra"), 2);
}

#[test]
fn an_index_root_decodes() {
    let data = crate::volume::dirops::insert::empty_index_root(4096, 4096);
    let root = parse_root(&data).unwrap();
    assert_eq!(root.indexed_type, ATTR_NAME);
    assert_eq!(root.collation, COLLATION_FILENAME);
    assert_eq!(root.block_size, 4096);
    assert_eq!(root.block_clst, 1);
    assert!(!root.header.has_subnodes());
}

#[test]
fn an_index_block_must_claim_the_number_it_was_read_as() {
    // A block whose number is not the one requested is a stale copy, and
    // reading it lists another directory's names.
    let bytes = format_block(4096, 3);
    assert!(parse_block(&bytes, 3).is_some());
    assert!(parse_block(&bytes, 4).is_none());
}

#[test]
fn a_block_without_the_index_signature_is_refused() {
    let mut bytes = format_block(4096, 0);
    bytes[REC_OFF_SIGN] = b'F';
    assert!(parse_block(&bytes, 0).is_none());
}

#[test]
fn a_node_whose_used_length_passes_its_bytes_is_refused() {
    let mut bytes = node(&["a"], &[], None);
    bytes[IHDR_OFF_USED..IHDR_OFF_USED + 4].copy_from_slice(&9999u32.to_le_bytes());
    assert!(node_header(&bytes, 0).is_none());
}

#[test]
fn a_node_whose_entries_begin_inside_its_own_header_is_refused() {
    let mut bytes = node(&["a"], &[], None);
    bytes[IHDR_OFF_DE_OFF..IHDR_OFF_DE_OFF + 4].copy_from_slice(&4u32.to_le_bytes());
    assert!(node_header(&bytes, 0).is_none());
}
