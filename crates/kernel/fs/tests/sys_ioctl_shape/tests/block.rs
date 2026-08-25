use super::*;

#[test]
fn block_discard_family_is_handled_before_enotty_fallback() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let (file, disk) = mk_block_file("vdblkdiscard", OpenFlags::O_RDWR, 8);
    let mut range = [0u64, 512u64];
    write_disk(disk.as_ref(), 0, 2, 0xA5);

    assert_eq!(blk::handle_blk_ioctl(&file, uapi::BLKDISCARD, range.as_mut_ptr() as u64), Some(0));
    let after_discard = read_disk(disk.as_ref(), 0, 2);
    assert!(after_discard[..512].iter().all(|&b| b == 0));
    assert!(after_discard[512..].iter().all(|&b| b == 0xA5));

    range = [512, 512];
    assert_eq!(blk::handle_blk_ioctl(&file, uapi::BLKZEROOUT, range.as_mut_ptr() as u64), Some(0));
    let after_zeroout = read_disk(disk.as_ref(), 0, 2);
    assert!(after_zeroout.iter().all(|&b| b == 0));

    let mut zeroes: u32 = u32::MAX;
    assert_eq!(blk::handle_blk_ioctl(&file, uapi::BLKDISCARDZEROES, &mut zeroes as *mut u32 as u64), Some(0));
    assert_eq!(zeroes, 0);
    block::registry::unregister("vdblkdiscard");
    reset();
}

#[test]
fn block_discard_family_matches_linux_admission_order() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let (ro_file, _disk) = mk_block_file("vdblkrodiscard", OpenFlags::O_RDONLY, 8);
    let mut range = [0u64, 512u64];

    assert_eq!(blk::handle_blk_ioctl(&ro_file, uapi::BLKDISCARD, range.as_mut_ptr() as u64),
        Some(-(Errno::Ebadf.as_i32() as i64)));
    assert_eq!(userbuf::READABLE_CALLS.load(Ordering::SeqCst), 1,
        "BLKDISCARD copies the range before the write-open gate");

    userbuf::reset();
    assert_eq!(blk::handle_blk_ioctl(&ro_file, uapi::BLKZEROOUT, range.as_mut_ptr() as u64),
        Some(-(Errno::Ebadf.as_i32() as i64)));
    assert_eq!(userbuf::READABLE_CALLS.load(Ordering::SeqCst), 0,
        "BLKZEROOUT checks write-open before copying the range");

    userbuf::reset();
    let (rw_file, _disk2) = mk_block_file("vdblksecure", OpenFlags::O_RDWR, 8);
    assert_eq!(blk::handle_blk_ioctl(&rw_file, uapi::BLKSECDISCARD, range.as_mut_ptr() as u64),
        Some(-(Errno::Eopnotsupp.as_i32() as i64)));
    assert_eq!(userbuf::READABLE_CALLS.load(Ordering::SeqCst), 0,
        "unsupported BLKSECDISCARD reports capability absence before usercopy");
    block::registry::unregister("vdblkrodiscard");
    block::registry::unregister("vdblksecure");
    reset();
}

#[test]
fn block_zeroout_uses_logical_block_alignment_not_only_abi_sector_alignment() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let (file, _disk) = mk_block_file_with_block_size("vdblkzero4k", OpenFlags::O_RDWR,
        TEST_FOUR_KIB_BLOCK_BYTES, TEST_FOUR_KIB_BLOCK_COUNT);
    let mut range = [MISALIGNED_ZEROOUT_BYTES, LOGICAL_BLOCK_ZEROOUT_BYTES];
    assert_eq!(blk::handle_blk_ioctl(&file, uapi::BLKZEROOUT, range.as_mut_ptr() as u64),
        Some(-(Errno::Einval.as_i32() as i64)));
    range = [0, LOGICAL_BLOCK_ZEROOUT_BYTES];
    assert_eq!(blk::handle_blk_ioctl(&file, uapi::BLKZEROOUT, range.as_mut_ptr() as u64), Some(0));
    block::registry::unregister("vdblkzero4k");
    reset();
}

#[test]
fn block_geometry_ioctls_still_report_registered_disk_shape() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let (file, _disk) = mk_block_file("vdblkgeometry", OpenFlags::O_RDONLY, 8);
    let mut bytes: u64 = 0;
    let mut sectors: u64 = 0;
    let mut logical: u32 = 0;
    let mut soft: u32 = 0;
    let mut readonly: u32 = u32::MAX;

    assert_eq!(blk::handle_blk_ioctl(&file, uapi::BLKGETSIZE64, &mut bytes as *mut u64 as u64), Some(0));
    assert_eq!(blk::handle_blk_ioctl(&file, uapi::BLKGETSIZE, &mut sectors as *mut u64 as u64), Some(0));
    assert_eq!(blk::handle_blk_ioctl(&file, uapi::BLKSSZGET, &mut logical as *mut u32 as u64), Some(0));
    assert_eq!(blk::handle_blk_ioctl(&file, uapi::BLKBSZGET, &mut soft as *mut u32 as u64), Some(0));
    assert_eq!(blk::handle_blk_ioctl(&file, uapi::BLKROGET, &mut readonly as *mut u32 as u64), Some(0));

    assert_eq!(bytes, 4096);
    assert_eq!(sectors, 8);
    assert_eq!(logical, 512);
    assert_eq!(soft, 512);
    assert_eq!(readonly, 0);
    block::registry::unregister("vdblkgeometry");
    reset();
}

