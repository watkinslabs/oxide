//! superblock-D25: typed `s_fs_info` backend-private state slot. `set_fs_info`
//! installs a concrete `Arc<T>` (Linux `fill_super` setting `sb->s_fs_info`) and
//! `fs_info_as::<T>()` reads it back downcast; a wrong-type downcast yields
//! `None`. The `for_backend`/`new` placeholder is the `()` unit (no private
//! state). Mirrors `inode.private::<T>()`.

use std::sync::Arc;

use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{KResult, VfsError};

struct TType;
impl FileSystemType for TType {
    fn name(&self) -> &str { "tfsinfofs" }
    fn mount(&self, _s: &str, _o: &str) -> KResult<Arc<SuperBlock>> { Err(VfsError::Einval) }
}
struct TOps;
impl SuperOps for TOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
}
fn build() -> Arc<SuperBlock> {
    SuperBlock::new(Arc::new(TType), Arc::new(TOps), 0xF515, 0x42, 4096, "tfsinfofs".into(), Arc::new(()))
}

/// Concrete backend private state hung off the superblock.
struct MyFsInfo { generation: u64, label: String }
/// A DIFFERENT private type — must not downcast out of an `MyFsInfo` slot.
struct OtherInfo;

#[test]
fn fs_info_typed_round_trip() {
    let sb = build();

    // Placeholder before fill_super: the `()` unit, no concrete state present.
    assert!(sb.fs_info_as::<MyFsInfo>().is_none(), "fresh SB has no typed private state");
    assert!(sb.fs_info().downcast_ref::<()>().is_some(), "placeholder is the unit ()");

    // fill_super installs the backend state.
    sb.set_fs_info(Arc::new(MyFsInfo { generation: 7, label: "rootfs".into() }));

    // Round-trip: read it back downcast to the same concrete type.
    let got = sb.fs_info_as::<MyFsInfo>().expect("typed read-back after set_fs_info");
    assert_eq!(got.generation, 7);
    assert_eq!(got.label, "rootfs");

    // Wrong type downcasts to None (does not alias the stored MyFsInfo).
    assert!(sb.fs_info_as::<OtherInfo>().is_none(), "wrong-type downcast is None");
    assert!(sb.fs_info_as::<()>().is_none(), "placeholder type gone after install");

    // Replaceable in place (Linux can re-point s_fs_info); no SB rebuild.
    sb.set_fs_info(Arc::new(MyFsInfo { generation: 99, label: "remount".into() }));
    assert_eq!(sb.fs_info_as::<MyFsInfo>().unwrap().generation, 99, "set_fs_info replaces the slot");
}

#[test]
fn fs_info_shares_one_allocation() {
    let sb = build();
    let info = Arc::new(MyFsInfo { generation: 1, label: "x".into() });
    sb.set_fs_info(info.clone());
    let a = sb.fs_info_as::<MyFsInfo>().unwrap();
    let b = sb.fs_info_as::<MyFsInfo>().unwrap();
    // Both reads and the original handle are the SAME allocation (counted ref).
    assert!(Arc::ptr_eq(&a, &b), "two reads return the same Arc allocation");
    assert!(Arc::ptr_eq(&a, &info), "read-back aliases the installed Arc");
}
