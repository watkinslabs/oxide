// ext4 read-only driver per Linux ext4 disk format.
//
// Phase 6 minimum: superblock parse + inode-table walk + path
// lookup against extent-encoded directories. Write/journaling
// (`docs/17` Phase 7b) ride later.
//
// Hosted-testable: pure on-disk-format parsers take `&[u8]`.
// Block-device I/O lives behind the `BlockDevice` trait that
// callers in the kernel side will plug in (the `block` crate's
// `MemDisk` is enough to hosted-test against synthetic images).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

// Any non-kernel (host) build is for tests/tooling — pull std so the
// transaction gate's per-thread `ctx_id` works under plain `cargo test`
// (CI runs `cargo test --workspace` with no `hosted` feature). The real
// kernel target stays `no_std`.
#[cfg(not(target_os = "oxide-kernel"))]
extern crate std;

pub mod superblock;
pub use superblock::{Superblock, EXT4_SUPER_MAGIC, SuperblockError};

pub mod inode;
pub use inode::{Inode, InodeError, ExtentHeader, Extent,
                S_IFMT, S_IFREG, S_IFDIR, S_IFLNK,
                EXT4_EXT_MAGIC, parse_extent_header, parse_inline_extent};

pub mod dir;
pub use dir::{DirEntry, DirError, next_entry, iter_active, lookup,
              DT_UNKNOWN, DT_REG, DT_DIR, DT_LNK};

pub mod gdt;
pub use gdt::{GroupDesc, GdtError, desc_size_for, parse_descriptor, locate_inode};

pub mod csum;
mod layout;

pub mod htree;
pub use htree::EXT4_INDEX_FL;

pub mod mount;
pub use mount::{Mount, MountError, MountState, MountStateGuard};

pub mod balloc;
pub use balloc::{find_first_clear, group_first_block};

pub mod extent_rw;
pub use extent_rw::EXTENT_LEN_MAX;

pub mod ialloc;

pub mod xattr;

pub mod journal;

pub mod quota;

// Host-compilable so the verify-left resolution harness
// (tests/walk_image.rs) can drive the real ext4 Inode impls via
// `set_test_mount`. The boot path mounts a real virtio-blk disk via
// `init_from_dev` (serial `oxide-root`); no embedded image.
pub mod rootfs;
/// D8: flush every dirty ext4 frame store (the `msync(2)` durability path).
pub use rootfs::flush_all_dirty;
pub use rootfs::commit_rootfs_journal;
pub use journal::ExtentLogReader;
pub mod jbd2;
pub use crate::jbd2::StagedBlock;
