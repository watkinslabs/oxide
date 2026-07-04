use super::*;

pub fn smoke_test() {
    use hal::kassert;

    let pipe = make_pipe_inode();
    let pd = pipe_data(&pipe).expect("pipe data");
    pd.writers.store(1, core::sync::atomic::Ordering::Release);
    pd.readers.store(1, core::sync::atomic::Ordering::Release);
    let n = pipe.write(0, b"hello").expect("pipe.write");
    kassert!(n == 5, "pipe write len");
    let mut buf = [0u8; 8];
    let n = pipe.read(0, &mut buf).expect("pipe.read");
    kassert!(n == 5, "pipe read len");
    kassert!(&buf[..5] == b"hello", "pipe round-trip body");
    let r = pipe.read_nonblock(0, &mut buf);
    kassert!(matches!(r, Err(vfs::VfsError::Eagain)), "pipe drained = EAGAIN");
    pd.writers.store(0, core::sync::atomic::Ordering::Release);
    let n = pipe.read(0, &mut buf).expect("pipe.read post-writer-close");
    kassert!(n == 0, "pipe EOF after writers=0");
    pd.readers.store(0, core::sync::atomic::Ordering::Release);
    let r = pipe.write(0, b"x");
    kassert!(matches!(r, Err(vfs::VfsError::Epipe)), "pipe write w/o readers = EPIPE");

    let evt = make_eventfd_inode(0);
    let n = evt.write(0, &0x1234u64.to_ne_bytes()).expect("evt.write");
    kassert!(n == 8, "evt write len");
    let mut ev = [0u8; 8];
    let n = evt.read(0, &mut ev).expect("evt.read");
    kassert!(n == 8, "evt read len");
    kassert!(u64::from_ne_bytes(ev) == 0x1234, "evt counter round-trip");

    #[cfg(feature = "debug-boot")]
    {
        klog::write_raw(b"[INFO]  pipe-evt-smoke: ok\n");
    }
}
