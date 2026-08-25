use super::*;

#[test]
fn the_merged_root_shows_both_layers() {
    let (l, up, lo) = image();
    mkfile(&lo, "from-image", b"x");
    mkfile(&up, "from-writes", b"y");
    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    assert_eq!(names(&fs.root_inode()), vec!["from-image", "from-writes"]);
}

#[test]
fn a_lower_file_reads_through() {
    let (l, _up, lo) = image();
    mkfile(&lo, "f", b"image contents");
    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    let f = fs.root_inode().lookup("f").unwrap();
    let mut buf = [0u8; 32];
    let n = f.read(0, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"image contents");
}

#[test]
fn repeated_lookup_returns_the_cached_overlay_inode() {
    let (l, _up, lo) = image();
    mkfile(&lo, "f", b"image contents");
    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    let first = fs.root_inode().lookup("f").unwrap();
    let second = fs.root_inode().lookup("f").unwrap();
    assert!(Arc::ptr_eq(&first, &second), "one real object has one overlay inode");
}

#[test]
fn pure_upper_lookup_returns_the_cached_overlay_inode() {
    let (l, up, _lo) = image();
    mkfile(&up, "f", b"upper");
    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    let first = fs.root_inode().lookup("f").unwrap();
    let second = fs.root_inode().lookup("f").unwrap();
    assert!(Arc::ptr_eq(&first, &second), "a pure upper object has one inode");
}

#[test]
fn nfs_export_round_trips_a_lower_handle_through_origin_state() {
    let (l, _up, lo) = image();
    mkfile(&lo, "f", b"lower");
    let fs = OverlayFs::open("lowerdir=/lower,upperdir=/upper,workdir=/work,nfs_export=on",
                             &l.resolve(), true).unwrap();
    let original = fs.root_inode().lookup("f").unwrap();
    let ops = fs.super_ops().unwrap();
    let mut bytes = vec![0u8; ops.export_fid_len(false, false) as usize];
    let (len, ty) = ops.export_encode_fh_raw(&original, None, &mut bytes);
    assert_eq!(ty, crate::uapi::OVERLAY_FILEID_V1);
    bytes.truncate(len as usize);
    let fid = ops.export_decode_fh_raw(&bytes, ty).unwrap();
    let sb = lo.i_sb().unwrap();
    let reopened = ops.fh_to_dentry_raw(&sb, &fid).unwrap();
    let mut data = [0u8; 8];
    let n = reopened.read(0, &mut data).unwrap();
    assert_eq!(&data[..n], b"lower");
}

#[test]
fn nfs_export_round_trips_a_pure_upper_handle() {
    let (l, up, _lo) = image();
    mkfile(&up, "f", b"upper");
    let fs = OverlayFs::open("lowerdir=/lower,upperdir=/upper,workdir=/work,nfs_export=on",
                             &l.resolve(), true).unwrap();
    let original = fs.root_inode().lookup("f").unwrap();
    let ops = fs.super_ops().unwrap();
    let mut bytes = vec![0u8; ops.export_fid_len(false, false) as usize];
    let (len, ty) = ops.export_encode_fh_raw(&original, None, &mut bytes);
    bytes.truncate(len as usize);
    assert!(crate::fh::decode(&bytes).unwrap().is_upper);
    let fid = ops.export_decode_fh_raw(&bytes, ty).unwrap();
    let sb = up.i_sb().unwrap();
    let reopened = ops.fh_to_dentry_raw(&sb, &fid).unwrap();
    let mut data = [0u8; 8];
    let n = reopened.read(0, &mut data).unwrap();
    assert_eq!(&data[..n], b"upper");
}

#[test]
fn nfs_export_rejects_connectable_overlay_handles() {
    let (l, _up, lo) = image();
    mkfile(&lo, "f", b"lower");
    let fs = OverlayFs::open("lowerdir=/lower,upperdir=/upper,workdir=/work,nfs_export=on",
                             &l.resolve(), true).unwrap();
    let inode = fs.root_inode().lookup("f").unwrap();
    let ops = fs.super_ops().unwrap();
    let mut bytes = vec![0u8; ops.export_fid_len(true, false) as usize];
    let (len, ty) = ops.export_encode_fh_raw(&inode, Some((1, 1)), &mut bytes);
    assert_eq!((len, ty), (0, -1));
}

#[test]
fn indexed_lower_hardlinks_share_one_overlay_inode() {
    let (l, _up, lo) = image();
    let first = mkfile(&lo, "a", b"image");
    lo.link_child(&first, "b", &CreateCtx::root()).unwrap();
    let fs = OverlayFs::open("lowerdir=/lower,upperdir=/upper,workdir=/work,index=on",
                             &l.resolve(), true).unwrap();
    let a = fs.root_inode().lookup("a").unwrap();
    let b = fs.root_inode().lookup("b").unwrap();
    assert!(Arc::ptr_eq(&a, &b), "indexed hardlinks use one real inode key");
}
