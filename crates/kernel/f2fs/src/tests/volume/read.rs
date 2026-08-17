//! Reading a file's bytes, through every path a file can take.

use super::*;
use crate::volume::map::Mapped;
use alloc::vec;
use alloc::vec::Vec;

/// A block of `len` bytes whose contents identify it.
fn filled(byte: u8, len: usize) -> Vec<u8> { vec![byte; len] }

#[test]
fn an_inline_file_reads_its_own_inode_block() {
    let mut b = test_image::with_root();
    nodes::add_inline_file(&mut b, 4, b"hello inline");
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    assert!(i.inline_data());
    assert_eq!(v.read_whole(&i, 4).unwrap(), b"hello inline".to_vec());
}

#[test]
fn an_inline_file_reads_from_an_offset() {
    let mut b = test_image::with_root();
    nodes::add_inline_file(&mut b, 4, b"abcdefgh");
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    let mut buf = [0u8; 4];
    assert_eq!(v.read_file(&i, 4, 3, &mut buf).unwrap(), 4);
    assert_eq!(&buf, b"defg");
}

#[test]
fn a_read_stops_at_the_files_size() {
    let mut b = test_image::with_root();
    nodes::add_inline_file(&mut b, 4, b"abc");
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    let mut buf = [0xFFu8; 16];
    assert_eq!(v.read_file(&i, 4, 0, &mut buf).unwrap(), 3);
    assert_eq!(&buf[..3], b"abc");
    assert_eq!(buf[3], 0xFF);
}

#[test]
fn a_read_past_the_end_returns_nothing() {
    let mut b = test_image::with_root();
    nodes::add_inline_file(&mut b, 4, b"abc");
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    assert_eq!(v.read_file(&i, 4, 3, &mut [0u8; 8]).unwrap(), 0);
    assert_eq!(v.read_file(&i, 4, 99, &mut [0u8; 8]).unwrap(), 0);
}

#[test]
fn an_inline_file_that_has_never_been_written_reads_as_zeroes() {
    // The flag saying the data is inline and the flag saying data EXISTS are
    // separate; the region otherwise holds the address array's old bytes.
    let mut b = test_image::with_root();
    let mut s = nodes::Spec::file(4);
    s.size = 8;
    s.inline |= INLINE_DATA;
    let mut block = nodes::inode_block(&s);
    let at = s.addr_base() + INLINE_RESERVED_SIZE * 4;
    block[at..at + 8].fill(0xAB);
    nodes::place_inode(&mut b, &s, block, 1);
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    assert_eq!(v.read_whole(&i, 4).unwrap(), vec![0u8; 8]);
}

#[test]
fn a_one_block_file_reads_through_the_inodes_own_address_array() {
    let mut b = test_image::with_root();
    let data = filled(0xA5, BLKSIZE);
    nodes::add_sparse_file(&mut b, 4, BLKSIZE as u64, &[(0, data.clone())]);
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    assert!(!i.inline_data());
    assert_eq!(v.read_whole(&i, 4).unwrap(), data);
}

#[test]
fn a_multi_block_file_reads_its_blocks_in_order() {
    let mut b = test_image::with_root();
    let blocks: Vec<(u64, Vec<u8>)> =
        (0..4u64).map(|i| (i, filled(i as u8 + 1, BLKSIZE))).collect();
    nodes::add_sparse_file(&mut b, 4, 4 * BLKSIZE as u64, &blocks);
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    let all = v.read_whole(&i, 4).unwrap();
    for (n, _) in &blocks {
        let at = *n as usize * BLKSIZE;
        assert_eq!(all[at], *n as u8 + 1, "block {n}");
    }
}

#[test]
fn a_read_spanning_a_block_boundary_joins_the_two() {
    let mut b = test_image::with_root();
    let blocks = vec![(0u64, filled(1, BLKSIZE)), (1u64, filled(2, BLKSIZE))];
    nodes::add_sparse_file(&mut b, 4, 2 * BLKSIZE as u64, &blocks);
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    let mut buf = [0u8; 4];
    assert_eq!(v.read_file(&i, 4, BLKSIZE as u64 - 2, &mut buf).unwrap(), 4);
    assert_eq!(buf, [1, 1, 2, 2]);
}

#[test]
fn a_hole_reads_as_zeroes_rather_than_as_block_zero() {
    let mut b = test_image::with_root();
    let blocks = vec![(1u64, filled(9, BLKSIZE))];
    nodes::add_sparse_file(&mut b, 4, 2 * BLKSIZE as u64, &blocks);
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    let all = v.read_whole(&i, 4).unwrap();
    assert_eq!(&all[..BLKSIZE], &vec![0u8; BLKSIZE][..]);
    assert_eq!(all[BLKSIZE], 9);
}

#[test]
fn a_reserved_address_reads_as_a_hole_too() {
    let mut b = test_image::with_root();
    let s = nodes::add_sparse_file(&mut b, 4, BLKSIZE as u64, &[]);
    let at = s.addr_base();
    nodes::patch_inode(&mut b, 4, |blk| blk[at..at + 4].copy_from_slice(&NEW_ADDR.to_le_bytes()));
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    assert_eq!(v.map_block(&i, 4, 0).unwrap(), Mapped::Hole);
    assert_eq!(v.read_whole(&i, 4).unwrap(), vec![0u8; BLKSIZE]);
}

#[test]
fn a_block_index_reaching_the_first_direct_node_resolves() {
    // The boundary of the inode's own array: this is the direct node's slot
    // zero, and an off-by-one reads the inode's last address instead.
    let mut b = test_image::with_root();
    let apb = nodes::Spec::file(4).addrs_per_inode() as u64;
    let blocks = vec![(apb, filled(0x11, BLKSIZE))];
    nodes::add_sparse_file(&mut b, 4, (apb + 1) * BLKSIZE as u64, &blocks);
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    assert!(matches!(v.map_block(&i, 4, apb).unwrap(), Mapped::At(_)));
    assert_eq!(v.map_block(&i, 4, apb - 1).unwrap(), Mapped::Hole);
    let mut buf = [0u8; 1];
    v.read_file(&i, 4, apb * BLKSIZE as u64, &mut buf).unwrap();
    assert_eq!(buf[0], 0x11);
}

#[test]
fn the_last_address_inside_the_inode_and_the_first_outside_are_different_blocks() {
    let mut b = test_image::with_root();
    let apb = nodes::Spec::file(4).addrs_per_inode() as u64;
    let blocks = vec![(apb - 1, filled(0x22, BLKSIZE)), (apb, filled(0x33, BLKSIZE))];
    nodes::add_sparse_file(&mut b, 4, (apb + 1) * BLKSIZE as u64, &blocks);
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    let a = v.map_block(&i, 4, apb - 1).unwrap();
    let c = v.map_block(&i, 4, apb).unwrap();
    assert_ne!(a, c);
    let mut buf = [0u8; 1];
    v.read_file(&i, 4, (apb - 1) * BLKSIZE as u64, &mut buf).unwrap();
    assert_eq!(buf[0], 0x22);
    v.read_file(&i, 4, apb * BLKSIZE as u64, &mut buf).unwrap();
    assert_eq!(buf[0], 0x33);
}

#[test]
fn a_block_index_reaching_the_second_direct_node_resolves() {
    let mut b = test_image::with_root();
    let apb = nodes::Spec::file(4).addrs_per_inode() as u64;
    let index = apb + DEF_ADDRS_PER_BLOCK as u64;
    nodes::add_sparse_file(&mut b, 4, (index + 1) * BLKSIZE as u64,
                           &[(index, filled(0x44, BLKSIZE))]);
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    let mut buf = [0u8; 1];
    v.read_file(&i, 4, index * BLKSIZE as u64, &mut buf).unwrap();
    assert_eq!(buf[0], 0x44);
}

#[test]
fn a_block_index_reaching_an_indirect_node_resolves() {
    let mut b = test_image::with_root();
    let apb = nodes::Spec::file(4).addrs_per_inode() as u64;
    let index = apb + 2 * DEF_ADDRS_PER_BLOCK as u64;
    nodes::add_sparse_file(&mut b, 4, (index + 1) * BLKSIZE as u64,
                           &[(index, filled(0x55, BLKSIZE))]);
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    let mut buf = [0u8; 1];
    v.read_file(&i, 4, index * BLKSIZE as u64, &mut buf).unwrap();
    assert_eq!(buf[0], 0x55);
}

#[test]
fn a_block_index_reaching_the_second_indirect_node_resolves() {
    let mut b = test_image::with_root();
    let apb = nodes::Spec::file(4).addrs_per_inode() as u64;
    let direct = DEF_ADDRS_PER_BLOCK as u64;
    let index = apb + 2 * direct + direct * NIDS_PER_BLOCK as u64;
    nodes::add_sparse_file(&mut b, 4, (index + 1) * BLKSIZE as u64,
                           &[(index, filled(0x66, BLKSIZE))]);
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    let mut buf = [0u8; 1];
    v.read_file(&i, 4, index * BLKSIZE as u64, &mut buf).unwrap();
    assert_eq!(buf[0], 0x66);
}

#[test]
fn a_block_index_reaching_the_double_indirect_node_resolves() {
    let mut b = test_image::with_root();
    let apb = nodes::Spec::file(4).addrs_per_inode() as u64;
    let direct = DEF_ADDRS_PER_BLOCK as u64;
    let dptrs = NIDS_PER_BLOCK as u64;
    let index = apb + 2 * direct + 2 * direct * dptrs;
    nodes::add_sparse_file(&mut b, 4, (index + 1) * BLKSIZE as u64,
                           &[(index, filled(0x77, BLKSIZE))]);
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    let mut buf = [0u8; 1];
    v.read_file(&i, 4, index * BLKSIZE as u64, &mut buf).unwrap();
    assert_eq!(buf[0], 0x77);
}

#[test]
fn an_unallocated_indirect_node_makes_every_block_under_it_a_hole() {
    let mut b = test_image::with_root();
    let apb = nodes::Spec::file(4).addrs_per_inode() as u64;
    let index = apb + 2 * DEF_ADDRS_PER_BLOCK as u64;
    nodes::add_sparse_file(&mut b, 4, (index + 1) * BLKSIZE as u64, &[]);
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    assert_eq!(v.map_block(&i, 4, index).unwrap(), Mapped::Hole);
}

#[test]
fn a_block_index_past_what_the_format_can_address_is_refused() {
    let mut b = test_image::with_root();
    nodes::add_sparse_file(&mut b, 4, BLKSIZE as u64, &[(0, filled(1, BLKSIZE))]);
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    let past = crate::node::path::max_block(i.addrs_per_inode());
    assert_eq!(v.map_block(&i, 4, past).err(), Some(Errno::Efbig));
}

#[test]
fn a_stored_address_outside_the_main_area_is_refused() {
    let mut b = test_image::with_root();
    let s = nodes::add_sparse_file(&mut b, 4, BLKSIZE as u64, &[(0, filled(1, BLKSIZE))]);
    let at = s.addr_base();
    nodes::patch_inode(&mut b, 4, |blk| blk[at..at + 4].copy_from_slice(&1u32.to_le_bytes()));
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    assert_eq!(v.map_block(&i, 4, 0).err(), Some(Errno::Eio));
}

#[test]
fn a_cluster_sentinel_on_a_file_with_no_valid_cluster_width_is_an_error() {
    // The sentinel says "a compressed cluster starts here", but this inode
    // carries no cluster geometry at all — its width is zero, which the
    // format does not admit. Reading the following blocks as if they were a
    // cluster would hand a codec whatever happened to be there.
    let mut b = test_image::with_root();
    let s = nodes::add_sparse_file(&mut b, 4, BLKSIZE as u64, &[]);
    let at = s.addr_base();
    nodes::patch_inode(&mut b, 4,
        |blk| blk[at..at + 4].copy_from_slice(&COMPRESS_ADDR.to_le_bytes()));
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    assert_eq!(v.map_block(&i, 4, 0).unwrap(), Mapped::Compressed);
    assert_eq!(v.read_whole(&i, 4).err(), Some(Errno::Eio));
}

#[test]
fn a_zstd_cluster_whose_bytes_are_not_a_frame_reports_a_read_error() {
    // The codec exists, so a cluster it refuses says the stored bytes are
    // wrong — not that the operation is unsupported, which would be a claim
    // about this build rather than about the volume.
    let mut b = test_image::with_root();
    let mut s = nodes::Spec::file(4);
    s.flags = crate::flags::F2FS_COMPR_FL;
    // One cluster's worth, so the read reaches the sentinel at all.
    s.size = 4 * BLKSIZE as u64;
    // The cluster's one image block: a well-formed header naming 64 bytes of
    // codec output, and 64 bytes that are not a frame. An EMPTY cluster would
    // read as zeroes and prove nothing.
    let mut img = filled(0xFF, BLKSIZE);
    img[..4].copy_from_slice(&64u32.to_le_bytes());
    img[4..8].copy_from_slice(&0u32.to_le_bytes());
    let s = nodes::add_sparse_with(&mut b, s, &[(1, img)]);
    let at = s.addr_base();
    let algo = crate::compress::Algorithm::Zstd.stored();
    nodes::patch_inode(&mut b, 4, |blk| {
        blk[at..at + 4].copy_from_slice(&COMPRESS_ADDR.to_le_bytes());
        blk[I_COMPRESS_ALGORITHM] = algo;
        blk[I_LOG_CLUSTER_SIZE] = 2;
    });
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    assert_eq!(i.compress_algorithm, algo);
    assert_eq!(v.read_whole(&i, 4).err(), Some(Errno::Eio));
}

#[test]
fn a_short_symbolic_link_reads_its_target() {
    let mut b = test_image::with_root();
    nodes::add_symlink(&mut b, 4, b"/usr/bin/target");
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    assert_eq!(crate::mode::file_type(i.mode), vfs::FileType::Symlink);
    assert_eq!(v.read_link(&i, 4).unwrap(), b"/usr/bin/target".to_vec());
}

#[test]
fn a_links_target_stops_at_a_stored_terminator() {
    let mut b = test_image::with_root();
    let mut s = nodes::Spec::file(4);
    s.mode = crate::mode::S_IFLNK | 0o777;
    s.size = 8;
    s.inline |= INLINE_DATA | DATA_EXIST;
    let mut block = nodes::inode_block(&s);
    let at = s.addr_base() + 4;
    block[at..at + 8].copy_from_slice(b"/tmp/x\0!");
    nodes::place_inode(&mut b, &s, block, 1);
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    assert_eq!(v.read_link(&i, 4).unwrap(), b"/tmp/x".to_vec());
}

#[test]
fn an_empty_link_target_is_an_error_rather_than_an_empty_path() {
    let mut b = test_image::with_root();
    nodes::add_symlink(&mut b, 4, b"");
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    assert_eq!(v.read_link(&i, 4).err(), Some(Errno::Eio));
}

#[test]
fn a_special_file_carries_its_device_number_in_the_address_array() {
    let mut b = test_image::with_root();
    let wide = vfs::getattr::encode_dev(10, 512);
    let s = nodes::add_special(&mut b, 4, crate::mode::S_IFCHR | 0o600, wide);
    let v = b.mount().unwrap();
    let (i, node) = v.read_inode_ref(4).unwrap();
    assert_eq!(crate::mode::file_type(i.mode), vfs::FileType::CharDev);
    assert_eq!(crate::mode::rdev(s.addr_base(), &node.block), wide);
}

#[test]
fn a_file_whose_size_exceeds_what_one_read_will_assemble_is_refused() {
    let mut b = test_image::with_root();
    let mut s = nodes::Spec::file(4);
    s.size = crate::limits::MAX_IO_BYTES as u64 + 1;
    nodes::add_sparse_with(&mut b, s, &[]);
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    assert_eq!(v.read_whole(&i, 4).err(), Some(Errno::Efbig));
}
