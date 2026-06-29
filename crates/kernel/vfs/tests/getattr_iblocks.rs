//! inode-D20: `generic_fillattr` reports the inode's stored `i_blocks` verbatim
//! (Linux `stat->blocks = inode->i_blocks`), falling back to the size-rounded
//! estimate ONLY when `i_blocks == 0`.
//!
//! Fails-before: `generic_fillattr` ALWAYS called `blocks_for(size, bsize)`,
//! discarding a backend's real `i_blocks` — so a sparse file (few blocks, large
//! size) over-reported `st_blocks`, and a file with preallocation past EOF
//! under-reported it. This pins the stored-blocks pass-through.

use vfs::{FileType, InodeBuilder, default_file_ops, default_inode_ops, generic_fillattr,
          mk_mode, IDENTITY};

// A sparse file: 1 MiB logical size but only 8 sectors actually allocated.
// The stored i_blocks (8) must win over the size estimate (1 MiB / 4 KiB blocks).
#[test]
fn stored_i_blocks_reported_verbatim() {
    let i = InodeBuilder::new(1, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops())
        .size(1 << 20).blocks(8).build();
    let st = generic_fillattr(&i, &IDENTITY, None);
    assert_eq!(st.blocks, 8, "stored i_blocks reported, not the size estimate");
}

// i_blocks == 0 falls back to the size-rounded estimate (a 1-byte file on the
// 4096 default block = 8 sectors), preserving the pseudo-fs behaviour.
#[test]
fn zero_i_blocks_estimates_from_size() {
    let i = InodeBuilder::new(1, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops())
        .size(1).build();
    let st = generic_fillattr(&i, &IDENTITY, None);
    assert_eq!(st.blocks, 4096 / 512, "1-byte file rounds up to one 4 KiB block");
}
