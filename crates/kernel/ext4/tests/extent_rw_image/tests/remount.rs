use super::*;

#[test]
fn append_survives_remount() {
    let disk = build_disk();
    {
        let m = ext4::Mount::open(disk.clone()).unwrap();
        let ino_n = m.lookup_path(b"/hello.txt").unwrap();
        let payload = std::vec![0x5A; m.sb.block_size as usize];
        m.append_block(ino_n, &payload).unwrap();
    }
    let m2 = ext4::Mount::open(disk).unwrap();
    let ino_n = m2.lookup_path(b"/hello.txt").unwrap();
    let inode = m2.read_inode(ino_n).unwrap();
    let blk = m2.read_file_block(&inode, 1).unwrap();
    assert_eq!(blk[0], 0x5A, "appended block survives close+reopen");
}

