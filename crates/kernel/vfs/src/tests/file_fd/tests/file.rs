use super::*;

#[test]
fn file_read_write_roundtrip() {
    let i: InodeRef = MemFile::new(1);
    let d = Dentry::new_root(Arc::clone(&i));
    let f = File::new(Arc::clone(&i), Arc::clone(&d), OpenFlags::O_RDWR);
    let n = f.write(b"hello").unwrap();
    assert_eq!(n, 5);
    assert_eq!(f.pos(), 5);
    f.set_pos(0);
    let mut buf = [0u8; 16];
    let n = f.read(&mut buf).unwrap();
    assert_eq!(n, 5);
    assert_eq!(&buf[..5], b"hello");
    assert_eq!(f.pos(), 5);
}

#[test]
fn file_read_on_writeonly_is_ebadf() {
    let i: InodeRef = MemFile::new(1);
    let d = Dentry::new_root(Arc::clone(&i));
    let f = File::new(Arc::clone(&i), Arc::clone(&d), OpenFlags::O_WRONLY);
    let mut buf = [0u8; 4];
    assert_eq!(f.read(&mut buf), Err(VfsError::Ebadf));
}

#[test]
fn file_write_on_readonly_is_ebadf() {
    let i: InodeRef = MemFile::new(1);
    let d = Dentry::new_root(Arc::clone(&i));
    let f = File::new(Arc::clone(&i), Arc::clone(&d), OpenFlags::O_RDONLY);
    assert_eq!(f.write(b"x"), Err(VfsError::Ebadf));
}

#[test]
fn file_append_uses_inode_size() {
    let i: InodeRef = MemFile::new(1);
    let d = Dentry::new_root(Arc::clone(&i));
    let writer = File::new(Arc::clone(&i), Arc::clone(&d), OpenFlags::O_RDWR);
    writer.write(b"hello").unwrap();
    let appender = File::new(Arc::clone(&i), Arc::clone(&d), OpenFlags::O_WRONLY | OpenFlags::O_APPEND);
    appender.set_pos(0);
    assert_eq!(appender.write(b"WORLD").unwrap(), 5);
    let mut buf = [0u8; 16];
    let r = File::new(Arc::clone(&i), Arc::clone(&d), OpenFlags::O_RDONLY);
    let n = r.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"helloWORLD");
}

#[test]
fn file_seek_set_cur_end() {
    let i: InodeRef = MemFile::new(1);
    let d = Dentry::new_root(Arc::clone(&i));
    let f = File::new(Arc::clone(&i), Arc::clone(&d), OpenFlags::O_RDWR);
    f.write(b"abcdefgh").unwrap();
    assert_eq!(f.seek(SeekFrom::Start, 2).unwrap(), 2);
    assert_eq!(f.seek(SeekFrom::Current, 3).unwrap(), 5);
    assert_eq!(f.seek(SeekFrom::End, -1).unwrap(),    7);
    assert_eq!(f.seek(SeekFrom::Start, 100).unwrap(), 100);
}

#[test]
fn file_seek_data_hole_generic() {
    let i: InodeRef = MemFile::new(1);
    let d = Dentry::new_root(Arc::clone(&i));
    let f = File::new(Arc::clone(&i), Arc::clone(&d), OpenFlags::O_RDWR);
    f.write(b"abcdefgh").unwrap();
    assert_eq!(f.seek(SeekFrom::Data, 0).unwrap(), 0);
    assert_eq!(f.seek(SeekFrom::Data, 3).unwrap(), 3);
    assert_eq!(f.seek(SeekFrom::Hole, 0).unwrap(), 8);
    assert_eq!(f.seek(SeekFrom::Hole, 7).unwrap(), 8);
    assert_eq!(f.seek(SeekFrom::Data, 8), Err(VfsError::Enxio));
    assert_eq!(f.seek(SeekFrom::Hole, 8), Err(VfsError::Enxio));
    assert_eq!(f.seek(SeekFrom::Data, 100), Err(VfsError::Enxio));
    assert_eq!(f.seek(SeekFrom::Data, -1), Err(VfsError::Einval));
}

