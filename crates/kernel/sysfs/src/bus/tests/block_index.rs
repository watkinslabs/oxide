use super::*;

#[test]
fn sys_dev_block_indexes_block_registry_disks() {
    let dev: Arc<dyn block::BlockDevice> = block::MemDisk::<sync::TaskList>::new(512, 8);
    let disk_index = block::registry::register("sysfsblkindex0", dev);
    assert_ne!(disk_index, 0);
    let disk = block::registry::by_index(disk_index).expect("published disk");
    let (major, minor) = (disk.number.major, disk.number.minor);

    let index = make_sys_dev_index_inode(DevIndexKind::Block);
    let link = index
        .lookup(&alloc::format!("{}:{}", major, minor))
        .expect("block dev index link");
    assert_eq!(
        link.readlink().expect("readlink"),
        b"../../devices/virtual/block/sysfsblkindex0".to_vec()
    );

    assert!(block::registry::unregister("sysfsblkindex0"));
    assert_eq!(
        index.lookup(&alloc::format!("{}:{}", major, minor)).err(),
        Some(VfsError::Enoent)
    );
}
