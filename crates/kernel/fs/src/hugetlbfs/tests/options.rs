use alloc::string::ToString;

use pmm::hugetlb::HugePageSize;
use vfs::VfsError;

use crate::hugetlbfs::HugetlbfsFs;

#[test]
fn a_mount_with_no_options_takes_the_reference_defaults() {
    let fs = HugetlbfsFs::from_mount_data("").expect("default mount");
    let root = fs.root_inode();
    assert_eq!(root.perm(), Some(0o755));
    assert_eq!(root.uid(), Some(0));
    assert_eq!(root.gid(), Some(0));
}

#[test]
fn mode_uid_and_gid_reach_the_root_inode() {
    let fs = HugetlbfsFs::from_mount_data("mode=1777,uid=1000,gid=1001").expect("mount");
    let root = fs.root_inode();
    assert_eq!(root.perm(), Some(0o1777));
    assert_eq!(root.uid(), Some(1000));
    assert_eq!(root.gid(), Some(1001));
}

#[test]
fn a_mount_option_string_that_names_an_unknown_key_fails_the_mount() {
    assert_eq!(HugetlbfsFs::from_mount_data("noswap").err(), Some(VfsError::Einval));
}

#[test]
fn a_minimum_larger_than_the_maximum_fails_the_mount() {
    assert_eq!(HugetlbfsFs::from_mount_data("size=2M,min_size=8M").err(), Some(VfsError::Einval));
}

#[test]
fn a_pagesize_the_pool_does_not_serve_fails_the_mount() {
    assert_eq!(HugetlbfsFs::from_mount_data("pagesize=4k").err(), Some(VfsError::Einval));
}

#[test]
fn the_block_size_a_mount_reports_is_its_huge_page() {
    use vfs::fs::FileSystem;
    let d = HugetlbfsFs::from_mount_data("").expect("mount");
    assert_eq!(d.block_size() as u64, HugePageSize::Huge2M.bytes());
    let g = HugetlbfsFs::from_mount_data("pagesize=1G").expect("mount");
    assert_eq!(g.block_size() as u64, HugePageSize::Huge1G.bytes());
}

#[test]
fn statfs_reports_the_mounts_size_ceiling_in_huge_pages() {
    use vfs::fs::FileSystem;
    let fs = HugetlbfsFs::from_mount_data("size=8M").expect("mount");
    let st = fs.super_ops().expect("super_ops").statfs().expect("statfs");
    assert_eq!(st.f_bsize as u64, HugePageSize::Huge2M.bytes());
    assert_eq!(st.f_blocks, 4, "8 MiB is four 2 MiB pages");
    assert_eq!(st.f_bfree, 4);
    assert_eq!(st.f_type, crate::hugetlbfs::HUGETLBFS_MAGIC);
}

#[test]
fn a_mount_with_no_size_ceiling_reports_no_block_total() {
    use vfs::fs::FileSystem;
    let fs = HugetlbfsFs::from_mount_data("").expect("mount");
    let st = fs.super_ops().expect("super_ops").statfs().expect("statfs");
    assert_eq!((st.f_blocks, st.f_bfree, st.f_bavail), (0, 0, 0));
}

#[test]
fn show_options_always_names_the_page_size() {
    use vfs::fs::FileSystem;
    assert_eq!(HugetlbfsFs::from_mount_data("").unwrap().show_options(), ",pagesize=2M".to_string());
    assert_eq!(HugetlbfsFs::from_mount_data("pagesize=1G").unwrap().show_options(),
               ",pagesize=1024M".to_string());
}

#[test]
fn show_options_names_only_what_differs_from_the_defaults() {
    use vfs::fs::FileSystem;
    let fs = HugetlbfsFs::from_mount_data("uid=7,mode=1777,size=4M,nr_inodes=9").unwrap();
    let s = fs.show_options();
    assert!(s.contains(",uid=7"), "{s}");
    assert!(s.contains(",mode=1777"), "{s}");
    assert!(s.contains(",nr_inodes=9"), "{s}");
    assert!(s.contains(",size=4194304"), "{s}");
    assert!(!s.contains("gid="), "an unchanged gid must not be reported: {s}");
}

#[test]
fn nr_inodes_is_enforced_when_files_are_created() {
    use vfs::CreateCtx;
    // The root inode itself takes one of the two slots, leaving one file.
    let fs = HugetlbfsFs::from_mount_data("nr_inodes=2").expect("mount");
    let root = fs.root_inode();
    assert!(root.create_child("a", 0o644, &CreateCtx::root()).is_ok());
    assert_eq!(root.create_child("b", 0o644, &CreateCtx::root()).err(), Some(VfsError::Enospc));
}

#[test]
fn a_file_on_a_hugetlbfs_mount_reports_its_mounts_granule() {
    use vfs::CreateCtx;
    for (opt, want) in [("", HugePageSize::Huge2M), ("pagesize=1G", HugePageSize::Huge1G)] {
        let fs = HugetlbfsFs::from_mount_data(opt).expect("mount");
        let f = fs.root_inode().create_child("f", 0o644, &CreateCtx::root()).expect("create");
        assert_eq!(f.huge_page_size(), want.bytes(), "opt {opt}");
    }
}

#[test]
fn a_hugetlbfs_file_refuses_a_write_because_the_only_way_in_is_a_mapping() {
    use vfs::CreateCtx;
    let fs = HugetlbfsFs::from_mount_data("").expect("mount");
    let f = fs.root_inode().create_child("f", 0o644, &CreateCtx::root()).expect("create");
    assert_eq!(f.write(0, b"x").err(), Some(VfsError::Einval));
}

#[test]
fn a_truncate_to_a_partial_huge_page_is_refused() {
    use vfs::CreateCtx;
    let fs = HugetlbfsFs::from_mount_data("").expect("mount");
    let f = fs.root_inode().create_child("f", 0o644, &CreateCtx::root()).expect("create");
    assert_eq!(f.truncate(4096).err(), Some(VfsError::Einval));
    assert!(f.truncate(HugePageSize::Huge2M.bytes()).is_ok());
    assert!(f.truncate(0).is_ok());
}

#[test]
fn a_mapping_at_an_offset_that_is_not_a_whole_huge_page_is_refused() {
    use vfs::CreateCtx;
    let fs = HugetlbfsFs::from_mount_data("").expect("mount");
    let f = fs.root_inode().create_child("f", 0o644, &CreateCtx::root()).expect("create");
    assert_eq!(crate::hugetlbfs::reserve_mapping(&f, 4096, HugePageSize::Huge2M.bytes()).err(),
               Some(VfsError::Einval));
}

#[test]
fn a_mapping_past_the_mounts_size_ceiling_is_refused_with_enomem() {
    use vfs::CreateCtx;
    let hb = HugePageSize::Huge2M.bytes();
    let fs = HugetlbfsFs::from_mount_data("size=4M").expect("mount");
    let f = fs.root_inode().create_child("f", 0o644, &CreateCtx::root()).expect("create");
    // Three pages against a two-page mount: the mount's own ceiling refuses it
    // before the global pool is ever consulted, and nothing is charged.
    assert_eq!(crate::hugetlbfs::reserve_mapping(&f, 0, 3 * hb).err(), Some(VfsError::Enomem));
    let st = {
        use vfs::fs::FileSystem;
        fs.super_ops().unwrap().statfs().unwrap()
    };
    assert_eq!(st.f_bfree, 2, "a refused mapping must not consume the mount's pages");
}

#[test]
fn a_mapping_is_refused_when_the_pool_holds_no_huge_pages() {
    use vfs::CreateCtx;
    // Nothing has sized the pool, so there is nothing to promise. The
    // reference answers `ENOMEM` from `hugetlb_reserve_pages` for exactly this
    // — a mapping learns at `mmap` that the memory does not exist, rather than
    // at a fault it cannot handle.
    let hb = HugePageSize::Huge2M.bytes();
    let fs = HugetlbfsFs::from_mount_data("").expect("mount");
    let f = fs.root_inode().create_child("f", 0o644, &CreateCtx::root()).expect("create");
    assert_eq!(crate::hugetlbfs::reserve_mapping(&f, 0, hb).err(), Some(VfsError::Enomem));
    assert_eq!(f.size(), 0, "a refused mapping must not grow the file");
}

#[test]
fn a_zero_length_mapping_reserves_nothing_and_is_allowed() {
    use vfs::CreateCtx;
    let fs = HugetlbfsFs::from_mount_data("").expect("mount");
    let f = fs.root_inode().create_child("f", 0o644, &CreateCtx::root()).expect("create");
    assert!(crate::hugetlbfs::reserve_mapping(&f, 0, 0).is_ok());
}

#[test]
fn a_hole_in_a_hugetlbfs_file_reads_as_zero() {
    use vfs::CreateCtx;
    let hb = HugePageSize::Huge2M.bytes();
    let fs = HugetlbfsFs::from_mount_data("").expect("mount");
    let f = fs.root_inode().create_child("f", 0o644, &CreateCtx::root()).expect("create");
    f.truncate(hb).expect("truncate to one huge page");
    let mut buf = [0xAAu8; 64];
    let n = f.read(0, &mut buf).expect("read");
    assert_eq!(n, 64);
    assert!(buf.iter().all(|&b| b == 0), "an unallocated page reads as zero");
}

#[test]
fn a_truncate_moves_the_files_size() {
    use vfs::CreateCtx;
    let hb = HugePageSize::Huge2M.bytes();
    let fs = HugetlbfsFs::from_mount_data("").expect("mount");
    let f = fs.root_inode().create_child("f", 0o644, &CreateCtx::root()).expect("create");
    f.truncate(4 * hb).expect("grow");
    assert_eq!(f.size(), 4 * hb);
    f.truncate(hb).expect("shrink");
    assert_eq!(f.size(), hb);
}

#[test]
fn a_read_past_the_end_of_the_file_returns_nothing() {
    use vfs::CreateCtx;
    let fs = HugetlbfsFs::from_mount_data("").expect("mount");
    let f = fs.root_inode().create_child("f", 0o644, &CreateCtx::root()).expect("create");
    let mut buf = [0u8; 8];
    assert_eq!(f.read(0, &mut buf).expect("read"), 0);
}

#[test]
fn a_directory_on_a_hugetlbfs_mount_holds_files() {
    use vfs::CreateCtx;
    let fs = HugetlbfsFs::from_mount_data("").expect("mount");
    let root = fs.root_inode();
    let d = root.mkdir("sub", 0o755, &CreateCtx::root()).expect("mkdir");
    d.create_child("f", 0o600, &CreateCtx::root()).expect("create");
    assert!(d.lookup("f").is_ok());
    assert_eq!(root.lookup("nope").err(), Some(VfsError::Enoent));
}

#[test]
fn an_anonymous_huge_page_file_reports_the_huge_size_as_its_block_size() {
    // The kernel-private mount carries no superblock, and a program reading
    // `st_blksize` off an `MFD_HUGETLB` file must still learn the unit it has
    // to align to.
    let inode = crate::hugetlbfs::hugetlb_file_setup(0, 0, 0o600, 0, 0).expect("setup");
    assert_eq!(inode.blksize() as u64, HugePageSize::Huge2M.bytes());
    assert_eq!(inode.huge_page_size(), HugePageSize::Huge2M.bytes());
}

#[test]
fn an_anonymous_huge_page_file_can_name_the_gigantic_granule() {
    let inode = crate::hugetlbfs::hugetlb_file_setup(
        0, HugePageSize::Huge1G.shift(), 0o600, 0, 0).expect("setup");
    assert_eq!(inode.blksize() as u64, HugePageSize::Huge1G.bytes());
}

#[test]
fn a_size_log_no_pool_serves_is_refused_by_the_internal_mount() {
    assert_eq!(crate::hugetlbfs::hugetlb_file_setup(0, 16, 0o600, 0, 0).err(),
               Some(crate::hugetlbfs::HugetlbSetupError::NoSuchSize));
}
