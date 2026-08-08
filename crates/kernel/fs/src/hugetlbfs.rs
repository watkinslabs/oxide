// hugetlbfs — the filesystem whose pages ARE huge pages (`16§2`, `11§5`).
//
// Module manifest:
//   `uapi`       owns the magic and the fixed inode numbers.
//   `limits`     owns the defaults and the inode-number counter.
//   `params`     owns the mount parameter table `mount(2)`/`fsconfig(2)` admit
//                keys against.
//   `mount_opts` owns option PARSING and validation — pure, hosted-tested.
//   `accounting` owns one mount's enforced state: its granule, its subpool,
//                its inode ceiling, and its root ownership.
//   `fs`         owns the `FileSystem`/`SuperOps` instance.
//   `inode`      owns inode-number allocation and the icache route.
//   `file`       owns the per-file huge-page store and the file/inode ops.
//   `mapping`    owns the `AddressSpaceOps` a mapping of such a file faults on.
//   `dir`        owns directory state and the namespace mutators.
//   `internal`   owns the kernel-private mount `memfd_create(MFD_HUGETLB)` and
//                `mmap(MAP_HUGETLB)` build their files on.
//   `register`   owns publishing the type to the mount registry.
//   `tests`      owns the hosted unit tests.

mod uapi;
mod limits;
mod params;
mod mount_opts;
mod accounting;
mod fs;
mod inode;
mod file;
mod mapping;
mod dir;
mod internal;
mod register;
#[cfg(test)]
mod tests;

pub use uapi::HUGETLBFS_MAGIC;
pub use params::HUGETLBFS_PARAMS;
pub use fs::HugetlbfsFs;
pub use internal::{hugetlb_file_setup, HugetlbSetupError};
pub use file::reserve_mapping;
pub use register::register;
